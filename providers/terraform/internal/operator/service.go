package operator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
	"slices"
	"strings"
	"time"
)

const finalizer = "identity.asterius.io/remote-resource"

var kinds = map[string]string{"Application": "application", "Resource": "resource", "Policy": "policy"}
var plurals = map[string]string{"Application": "applications", "Resource": "resources", "Policy": "policies"}

type Remote interface {
	Owner() string
	Read(context.Context, string) (client.Document, error)
	Lookup(context.Context, string, string) (client.Document, error)
	Create(context.Context, string, string, json.RawMessage, bool) (client.Document, error)
	Plan(context.Context, client.Document, json.RawMessage) (client.Plan, error)
	Mutate(context.Context, string, string, string, string, any) (client.Document, error)
}
type Cluster interface {
	Get(context.Context, string, string) (Object, error)
	List(context.Context, string) ([]Object, error)
	Update(context.Context, string, Object, bool) error
	Secret(context.Context, Ref) ([]byte, error)
	Acquire(context.Context, string, time.Time) (bool, error)
}
type Config struct {
	Namespace, Tenant, Issuer, ClientID, BindingUID, ClusterID, KeyID, Holder string
	SecretNames                                                               []string
	Interval                                                                  time.Duration
}
type Service struct {
	Config      Config
	Kube        Cluster
	Remote      Remote
	Factory     func(client.Config) (Remote, error)
	fingerprint string
}

func (s *Service) secret(ctx context.Context, ref Ref) ([]byte, error) {
	if !slices.Contains(s.Config.SecretNames, ref.Name) || ref.Key == "" || strings.ContainsAny(ref.Name, "/\\") {
		return nil, errors.New("Secret reference outside configured boundary")
	}
	return s.Kube.Secret(ctx, ref)
}
func (s *Service) credentials(ctx context.Context) error {
	binding, err := s.Kube.Get(ctx, "asteriustenantbindings", "default")
	if err != nil {
		return err
	}
	var spec BindingSpec
	if decode(binding.Spec, &spec) != nil {
		return errors.New("invalid tenant binding")
	}
	if binding.Metadata.Namespace != s.Config.Namespace || binding.Metadata.UID != s.Config.BindingUID || spec.TenantID != s.Config.Tenant || spec.Issuer != s.Config.Issuer || spec.ClientID != s.Config.ClientID || spec.ClusterID != s.Config.ClusterID {
		return errors.New("tenant binding identity mismatch")
	}
	auth, err := s.secret(ctx, spec.Authentication)
	if err != nil {
		return err
	}
	proof, err := s.secret(ctx, spec.DPoP)
	if err != nil {
		return err
	}
	var ca []byte
	if spec.CA != nil {
		ca, err = s.secret(ctx, *spec.CA)
		if err != nil {
			return err
		}
	}
	digest := sha256.New()
	for _, part := range [][]byte{auth, proof, ca} {
		digest.Write([]byte(fmt.Sprintf("%d:", len(part))))
		digest.Write(part)
	}
	fingerprint := hex.EncodeToString(digest.Sum(nil))
	if s.Remote != nil && fingerprint == s.fingerprint {
		return nil
	}
	// Discard old credentials before constructing replacements: an invalid rotation
	// cannot keep issuing requests with the previous credential.
	s.Remote = nil
	s.fingerprint = ""
	remote, err := s.Factory(client.Config{Issuer: s.Config.Issuer, IssuingTenant: s.Config.Tenant, ClientID: s.Config.ClientID, KeyID: s.Config.KeyID,
		Resource:    strings.TrimRight(s.Config.Issuer, "/") + "/admin/api/v1",
		KeyMaterial: auth, DPoPMaterial: proof, CAMaterial: ca, Timeout: 5 * time.Second,
		Scopes: []string{"admin.session:read", "admin.clients:read", "admin.clients:write", "admin.resource_servers:read", "admin.resource_servers:write", "admin.policies:read", "admin.policies:write"}})
	if err != nil {
		return errors.New("service credentials invalid")
	}
	// Verify the configured issuer really routes to this tenant before any
	// remote mutation. The existing read API rejects a tenant-mismatched ID,
	// including when a custom host cannot encode a tenant in its URL path.
	probeJSON, _ := json.Marshal([]string{s.Config.Tenant, "resource", strings.TrimRight(s.Config.Issuer, "/") + "/admin/api/v1"})
	probeID := base64.RawURLEncoding.EncodeToString(probeJSON)
	probe, err := remote.Read(ctx, probeID)
	if err != nil || !identityIsBound(probe.ID, s.Config.Tenant, "resource") {
		return errors.New("issuer and tenant routing verification refused")
	}
	s.Remote = remote
	s.fingerprint = fingerprint
	return nil
}
func (s *Service) condition(o *Object, condition, status, reason string, success bool) {
	now := time.Now().UTC()
	transition := now
	for _, old := range o.Status.Conditions {
		if old.Type == condition && old.Status == status && old.Reason == reason {
			transition = old.LastTransitionTime
		}
	}
	o.Status.Conditions = []Condition{{Type: condition, Status: status, Reason: reason, Message: reason, ObservedGeneration: o.Metadata.Generation, LastTransitionTime: transition}}
	if condition != "Ready" {
		o.Status.Conditions = append(o.Status.Conditions, Condition{Type: "Ready", Status: "False", Reason: reason, Message: reason, ObservedGeneration: o.Metadata.Generation, LastTransitionTime: now})
	}
	if success {
		o.Status.ObservedGeneration = o.Metadata.Generation
	}
}
func (s *Service) report(ctx context.Context, o Object, condition, reason string) error {
	status := "True"
	if condition == "Ready" {
		status = "False"
	}
	s.condition(&o, condition, status, reason, false)
	return s.Kube.Update(ctx, plurals[o.Kind], o, true)
}
func (s *Service) bound(o Object) bool {
	return kinds[o.Kind] != "" && o.APIVersion == "identity.asterius.io/v1alpha1" && o.Metadata.Namespace == s.Config.Namespace && o.Metadata.UID != "" && o.Metadata.Generation > 0
}
func (s *Service) validRemote(o Object, d client.Document) bool {
	return identityIsBound(d.ID, s.Config.Tenant, kinds[o.Kind]) && d.ContractVersion == 1
}
func (s *Service) Reconcile(ctx context.Context, o Object) error {
	if !s.bound(o) {
		return errors.New("object outside configured namespace or version")
	}
	controls, desired, err := s.desired(ctx, o)
	if err != nil {
		return s.report(ctx, o, "Ready", "InvalidSpecification")
	}
	if !slices.Contains(o.Metadata.Finalizers, finalizer) {
		if o.Metadata.DeletionTimestamp != nil {
			return nil
		} // No remote write is allowed before finalizer installation.
		o.Metadata.Finalizers = append(o.Metadata.Finalizers, finalizer)
		return s.Kube.Update(ctx, plurals[o.Kind], o, false)
	}
	key := strings.Join([]string{s.Config.ClusterID, s.Config.Namespace, o.Kind, o.Metadata.UID}, "/")
	id := o.Status.RemoteID
	if id == "" {
		id = controls.ImportID
	}
	if id != "" {
		if !identityIsBound(id, s.Config.Tenant, kinds[o.Kind]) {
			return s.report(ctx, o, "OwnershipConflict", "ForeignRemoteIdentity")
		}
	}
	var remote client.Document
	if id != "" {
		remote, err = s.Remote.Read(ctx, id)
	} else {
		remote, err = s.Remote.Lookup(ctx, kinds[o.Kind], key)
	}
	if err != nil && client.IsNotFound(err) && id == "" {
		if o.Metadata.DeletionTimestamp != nil {
			return s.removeFinalizer(ctx, o)
		}
		remote, err = s.Remote.Create(ctx, kinds[o.Kind], key, desired, controls.protected())
	}
	if err != nil && client.IsNotFound(err) && id != "" && o.Metadata.DeletionTimestamp != nil && controls.DeletionPolicy == "Delete" && !controls.protected() && o.Status.ObservedGeneration == o.Metadata.Generation-1 && o.Status.ObservedDeletionProtection != nil && !*o.Status.ObservedDeletionProtection && o.Status.RemoteRevision != "" {
		// A committed delete followed by a lost finalizer/status response must use
		// the existing durable receipt, never treat an arbitrary 404 as success.
		_, receiptErr := s.Remote.Mutate(ctx, "DELETE", id, "", o.Status.RemoteRevision, nil)
		if receiptErr == nil {
			return s.removeFinalizer(ctx, o)
		}
		return s.failure(ctx, o, receiptErr)
	}
	if err != nil {
		return s.failure(ctx, o, err)
	}
	if !s.validRemote(o, remote) {
		return s.report(ctx, o, "OwnershipConflict", "ForeignRemoteIdentity")
	}
	o.Status.RemoteID = remote.ID
	if remote.Owner == nil {
		if o.Metadata.DeletionTimestamp != nil && controls.DeletionPolicy != "Delete" && o.Status.RemoteID == remote.ID {
			return s.removeFinalizer(ctx, o)
		}
		if controls.AdoptionPolicy != "AdoptUnowned" || o.Metadata.DeletionTimestamp != nil {
			return s.report(ctx, o, "OwnershipConflict", "ExplicitAdoptionRequired")
		}
		remote, err = s.Remote.Mutate(ctx, "POST", remote.ID, "/adopt", remote.Revision, map[string]any{})
		if err != nil {
			return s.failure(ctx, o, err)
		}
	}
	if remote.Owner == nil || *remote.Owner != s.Remote.Owner() {
		return s.report(ctx, o, "OwnershipConflict", "DifferentRemoteOwner")
	}
	if o.Metadata.DeletionTimestamp != nil {
		if controls.DeletionPolicy == "Delete" {
			if o.Status.RemoteRevision != remote.Revision {
				return s.report(ctx, o, "Deleting", "RemoteRevisionChangedBeforeDelete")
			}
			// The API server itself increments generation when first marking a
			// finalizer-bearing CRD for deletion. Its prior generation must have
			// confirmed protection=false; an unobserved desired edit still denies.
			if controls.protected() || remote.DeletionProtection || o.Status.ObservedGeneration != o.Metadata.Generation-1 || o.Status.ObservedDeletionProtection == nil || *o.Status.ObservedDeletionProtection {
				return s.report(ctx, o, "Deleting", "DeleteProtectionRequiresPriorGeneration")
			}
			_, err = s.Remote.Mutate(ctx, "DELETE", remote.ID, "", remote.Revision, nil)
		} else {
			_, err = s.Remote.Mutate(ctx, "POST", remote.ID, "/release", remote.Revision, map[string]any{})
		}
		if err != nil {
			return s.failure(ctx, o, err)
		}
		return s.removeFinalizer(ctx, o)
	}
	if o.Status.RemoteRevision != "" && remote.Revision != o.Status.RemoteRevision && o.Status.ObservedGeneration == o.Metadata.Generation {
		return s.report(ctx, o, "Drifted", "RemoteRevisionChanged")
	}
	plan, err := s.Remote.Plan(ctx, remote, desired)
	if err != nil {
		return s.failure(ctx, o, err)
	}
	if plan.OwnerConflict {
		return s.report(ctx, o, "OwnershipConflict", "RemotePlanOwnerConflict")
	}
	if plan.Changed || remote.DeletionProtection != controls.protected() {
		remote, err = s.Remote.Mutate(ctx, "PUT", remote.ID, "", remote.Revision, map[string]any{"spec": plan.Spec, "deletion_protection": controls.protected()})
		if err != nil {
			return s.failure(ctx, o, err)
		}
	}
	o.Status.RemoteID = remote.ID
	o.Status.RemoteRevision = remote.Revision
	protection := remote.DeletionProtection
	o.Status.ObservedDeletionProtection = &protection
	s.condition(&o, "Ready", "True", "CanonicalStateConfirmed", true)
	return s.Kube.Update(ctx, plurals[o.Kind], o, true)
}
func (s *Service) removeFinalizer(ctx context.Context, o Object) error {
	o.Metadata.Finalizers = slices.DeleteFunc(o.Metadata.Finalizers, func(value string) bool { return value == finalizer })
	return s.Kube.Update(ctx, plurals[o.Kind], o, false)
}
func (s *Service) failure(ctx context.Context, o Object, err error) error {
	var api *client.APIError
	if errors.As(err, &api) {
		switch api.Code {
		case "owner_conflict", "logical_key_conflict":
			return s.report(ctx, o, "OwnershipConflict", "RemoteOwnershipConflict")
		case "delete_protected", "dependency_conflict":
			return s.report(ctx, o, "Deleting", "RemoteDeletionRefused")
		case "revision_conflict":
			return s.report(ctx, o, "Reconciling", "ConcurrentRevisionConflict")
		case "invalid_request":
			return s.report(ctx, o, "Ready", "RemoteValidationRefused")
		case "not_found":
			return s.report(ctx, o, "Drifted", "RemoteIdentityMissing")
		}
	}
	if statusErr := s.report(ctx, o, "Reconciling", "RemoteUnavailable"); statusErr != nil {
		return statusErr
	}
	return errors.New("remote operation unavailable")
}
func (s *Service) Cycle(ctx context.Context) error {
	leader, err := s.Kube.Acquire(ctx, s.Config.Holder, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("lease acquisition: %w", err)
	}
	if !leader {
		return nil
	}
	if err = s.credentials(ctx); err != nil {
		for _, plural := range []string{"applications", "resources", "policies"} {
			objects, listErr := s.Kube.List(ctx, plural)
			if listErr != nil {
				break
			}
			for _, object := range objects {
				if s.bound(object) {
					_ = s.report(ctx, object, "Reconciling", "CredentialsOrBindingUnavailable")
				}
			}
		}
		return fmt.Errorf("credential boundary: %w", err)
	}
	for _, kind := range []string{"Resource", "Application", "Policy"} {
		objects, err := s.Kube.List(ctx, plurals[kind])
		if err != nil {
			return fmt.Errorf("inventory read: %w", err)
		}
		if kind == "Policy" && len(objects) > 1 {
			for _, o := range objects {
				if err := s.report(ctx, o, "OwnershipConflict", "MultipleTenantPolicies"); err != nil {
					return err
				}
			}
			continue
		}
		for _, o := range objects {
			leader, err = s.Kube.Acquire(ctx, s.Config.Holder, time.Now().UTC())
			if err != nil {
				return fmt.Errorf("object reconciliation: %w", err)
			}
			if !leader {
				return errors.New("leadership lost")
			}
			operationCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = s.Reconcile(operationCtx, o)
			cancel()
			if err != nil {
				return fmt.Errorf("object reconciliation: %w", err)
			}
		}
	}
	return nil
}
func (s *Service) Run(ctx context.Context) error {
	if s.Config.Namespace == "" || s.Config.Tenant == "" || s.Config.Issuer == "" || s.Config.ClientID == "" || s.Config.BindingUID == "" || s.Config.ClusterID == "" || s.Config.KeyID == "" || s.Config.Holder == "" || len(s.Config.SecretNames) == 0 {
		return errors.New("incomplete controller boundary configuration")
	}
	for _, name := range s.Config.SecretNames {
		if name == "" || strings.ContainsAny(name, "/\\, \t\r\n") {
			return errors.New("invalid configured Secret boundary")
		}
	}
	if s.Factory == nil {
		s.Factory = func(cfg client.Config) (Remote, error) { return client.New(cfg) }
	}
	interval := s.Config.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if interval > 10*time.Second {
		return errors.New("resync interval exceeds leader-renewal bound")
	}
	backoff := interval
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := s.Cycle(ctx); err != nil {
			fmt.Println("controller retry: bounded operation unavailable")
			backoff = min(backoff*2, 10*time.Second)
		} else {
			backoff = interval
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
	}
}
