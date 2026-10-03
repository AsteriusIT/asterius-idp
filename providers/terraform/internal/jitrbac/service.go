// Package jitrbac clears or populates one pinned, pre-existing namespaced RoleBinding.
package jitrbac

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/operator"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
)

type Binding struct {
	EntitlementID      string `json:"entitlement_id"`
	Revision           string `json:"revision"`
	ControllerClientID string `json:"controller_client_id"`
	ClusterClientID    string `json:"cluster_client_id"`
	Cluster            string `json:"cluster"`
	Namespace          string `json:"namespace"`
	ProfileRevision    int64  `json:"profile_revision"`
	Enabled            bool   `json:"enabled"`
}
type Subject struct {
	ActivationID string    `json:"activation_id"`
	Username     string    `json:"username"`
	ExpiresAt    time.Time `json:"expires_at"`
}
type Projection struct {
	Binding             Binding   `json:"binding"`
	EntitlementRevision string    `json:"entitlement_revision"`
	ObservedAt          time.Time `json:"observed_at"`
	Subjects            []Subject `json:"subjects"`
}
type Config struct {
	Tenant, ControllerClient, ClusterClient, Cluster, Namespace               string
	EntitlementID, BindingRevision, RoleBindingName, RoleBindingUID, RoleName string
	ProfileRevision                                                           int64
	Interval                                                                  time.Duration
}

var dns = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (c Config) Validate() error {
	for _, v := range []string{c.Cluster, c.Namespace, c.RoleBindingName, c.RoleName} {
		if !dns.MatchString(v) {
			return errors.New("fixed namespaced RBAC identifiers required")
		}
	}
	for _, v := range []string{c.EntitlementID, c.BindingRevision, c.RoleBindingUID} {
		if !uuid.MatchString(v) {
			return errors.New("immutable object UUID pins required")
		}
	}
	if c.Tenant == "" || strings.ContainsAny(c.Tenant, "\r\n:") || c.ControllerClient == "" || c.ClusterClient == "" || c.ProfileRevision < 1 || c.Interval < 100*time.Millisecond || c.Interval > 2*time.Second {
		return errors.New("bounded controller profile required")
	}
	return nil
}
func DecodeProjection(raw []byte) (Projection, error) {
	var p Projection
	if len(raw) > 65536 {
		return p, errors.New("projection exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return p, errors.New("invalid closed projection")
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return p, errors.New("trailing projection data")
	}
	return p, nil
}

type Remote interface {
	KubernetesProjectionRaw(context.Context, string) (json.RawMessage, error)
}
type Cluster interface {
	GetRoleBinding(context.Context, string) (operator.RoleBinding, error)
	PatchRoleBindingSubjects(context.Context, string, string, string, []operator.RBACSubject) error
}
type Service struct {
	Config Config
	Remote Remote
	Kube   Cluster
	Report func(error)
}

// Step derives only signed-server public usernames. Local request duration is
// subtracted from DB-relative deadlines; a slow read can never extend authority.
func (s Service) Step(ctx context.Context) error {
	started := time.Now()
	readContext, cancelRead := context.WithTimeout(ctx, s.Config.Interval)
	raw, readErr := s.Remote.KubernetesProjectionRaw(readContext, s.Config.EntitlementID)
	cancelRead()
	applyContext, cancelApply := context.WithTimeout(ctx, s.Config.Interval)
	defer cancelApply()
	subjects := []operator.RBACSubject{}
	if readErr == nil {
		projection, err := DecodeProjection(raw)
		if err == nil {
			subjects, err = s.subjects(projection, time.Since(started))
		}
		readErr = err
	}
	current, err := s.Kube.GetRoleBinding(applyContext, s.Config.RoleBindingName)
	if err != nil {
		return errors.New("fixed Kubernetes binding unavailable")
	}
	if current.Metadata.UID != s.Config.RoleBindingUID || current.Metadata.Namespace != s.Config.Namespace || current.Metadata.Name != s.Config.RoleBindingName || current.Kind != "RoleBinding" || current.APIVersion != "rbac.authorization.k8s.io/v1" || current.RoleRef != (operator.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: s.Config.RoleName}) {
		return errors.New("fixed role binding identity changed")
	}
	// A failed or stale read clears this dedicated binding immediately; baseline
	// bindings have different names and are never addressed by this controller.
	if !slices.Equal(current.Subjects, subjects) {
		if err = s.Kube.PatchRoleBindingSubjects(applyContext, s.Config.RoleBindingName, current.Metadata.UID, current.Metadata.ResourceVersion, subjects); err != nil {
			return errors.New("fixed Kubernetes subjects update refused")
		}
	}
	if readErr != nil {
		return errors.New("authority projection refused; temporary subjects cleared")
	}
	return nil
}
func (s Service) subjects(p Projection, elapsed time.Duration) ([]operator.RBACSubject, error) {
	c := s.Config
	b := p.Binding
	if b.EntitlementID != c.EntitlementID || b.Revision != c.BindingRevision || b.ControllerClientID != c.ControllerClient || b.ClusterClientID != c.ClusterClient || b.Cluster != c.Cluster || b.Namespace != c.Namespace || b.ProfileRevision != c.ProfileRevision || !uuid.MatchString(p.EntitlementRevision) || p.ObservedAt.IsZero() || len(p.Subjects) > 100 {
		return nil, errors.New("projection binding differs from operator pins")
	}
	if !b.Enabled {
		return []operator.RBACSubject{}, nil
	}
	prefix := "asterius-jit:" + c.BindingRevision + ":"
	seen := map[string]bool{}
	out := []operator.RBACSubject{}
	for _, subject := range p.Subjects {
		if !uuid.MatchString(subject.ActivationID) || !strings.HasPrefix(subject.Username, prefix) || len(subject.Username) <= len(prefix) || len(subject.Username) > 512 || strings.ContainsAny(subject.Username, "\r\n\t\x00") || seen[subject.Username] {
			return nil, errors.New("invalid distinct exact public username")
		}
		seen[subject.Username] = true
		if subject.ExpiresAt.Sub(p.ObservedAt) <= elapsed+c.Interval {
			continue
		}
		out = append(out, operator.RBACSubject{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: subject.Username})
	}
	slices.SortFunc(out, func(a, b operator.RBACSubject) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
func (s Service) Run(ctx context.Context) error {
	if err := s.Config.Validate(); err != nil {
		return err
	}
	ticker := time.NewTicker(s.Config.Interval)
	defer ticker.Stop()
	for {
		// Refusals are bounded status only: no tokens, subjects, reasons or upstream bodies.
		if err := s.Step(ctx); err != nil && s.Report != nil {
			s.Report(err)
		}
		select {
		case <-ctx.Done():
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			current, err := s.Kube.GetRoleBinding(cleanup, s.Config.RoleBindingName)
			if err == nil && current.Metadata.UID == s.Config.RoleBindingUID && current.RoleRef == (operator.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: s.Config.RoleName}) {
				return s.Kube.PatchRoleBindingSubjects(cleanup, s.Config.RoleBindingName, current.Metadata.UID, current.Metadata.ResourceVersion, []operator.RBACSubject{})
			}
			return errors.New("shutdown could not clear pinned subjects")
		case <-ticker.C:
		}
	}
}
