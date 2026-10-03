package operator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
	"slices"
	"testing"
	"time"
)

type memoryKube struct {
	object     Object
	writes     int
	failStatus bool
}

func (k *memoryKube) Get(context.Context, string, string) (Object, error) { return k.object, nil }
func (k *memoryKube) List(context.Context, string) ([]Object, error)      { return []Object{k.object}, nil }
func (k *memoryKube) Secret(context.Context, Ref) ([]byte, error) {
	return nil, errors.New("Secret denied")
}
func (k *memoryKube) Acquire(context.Context, string, time.Time) (bool, error) { return true, nil }
func (k *memoryKube) Update(_ context.Context, _ string, o Object, status bool) error {
	if status && k.failStatus {
		k.failStatus = false
		return errors.New("response lost")
	}
	if o.Metadata.ResourceVersion != k.object.Metadata.ResourceVersion {
		return &KubeError{409}
	}
	if status {
		k.object.Status = o.Status
	} else {
		k.object.Metadata.Finalizers = o.Metadata.Finalizers
	}
	k.writes++
	k.object.Metadata.ResourceVersion = fmt.Sprint(k.writes + 1)
	return nil
}

type memoryRemote struct {
	doc                                          *client.Document
	created, updated, adopted, deleted, released int
	lostCreate                                   bool
	owner                                        string
	receipt                                      bool
}

func (r *memoryRemote) Owner() string { return r.owner }
func (r *memoryRemote) Read(context.Context, string) (client.Document, error) {
	if r.doc == nil {
		return client.Document{}, &client.APIError{Status: 404, Code: "not_found"}
	}
	return *r.doc, nil
}
func (r *memoryRemote) Lookup(ctx context.Context, _ string, _ string) (client.Document, error) {
	return r.Read(ctx, "")
}
func (r *memoryRemote) Create(_ context.Context, kind, _ string, spec json.RawMessage, protection bool) (client.Document, error) {
	r.created++
	id := base64.RawURLEncoding.EncodeToString([]byte(`["acme","resource","https://api.example/"]`))
	r.doc = &client.Document{ContractVersion: 1, ID: id, Kind: kind, Spec: spec, Revision: fmt.Sprintf("%064d", 1), Owner: &r.owner, DeletionProtection: protection}
	if r.lostCreate {
		r.lostCreate = false
		return client.Document{}, errors.New("connection lost after commit")
	}
	return *r.doc, nil
}
func (r *memoryRemote) Plan(_ context.Context, d client.Document, spec json.RawMessage) (client.Plan, error) {
	a, _ := client.Canonical(d.Spec)
	b, _ := client.Canonical(spec)
	return client.Plan{Changed: a != b, Spec: spec}, nil
}
func (r *memoryRemote) Mutate(_ context.Context, method, id, action, revision string, body any) (client.Document, error) {
	if method == "DELETE" && r.doc == nil && r.receipt {
		return client.Document{}, nil
	}
	if r.doc == nil {
		return client.Document{}, &client.APIError{Status: 404, Code: "not_found"}
	}
	if r.doc.Revision != revision {
		return client.Document{}, &client.APIError{Status: 412, Code: "revision_conflict"}
	}
	switch {
	case method == "DELETE":
		r.deleted++
		r.doc = nil
		r.receipt = true
		return client.Document{}, nil
	case action == "/release":
		r.released++
		r.doc.Owner = nil
	case action == "/adopt":
		r.adopted++
		r.doc.Owner = &r.owner
	default:
		r.updated++
		wire := body.(map[string]any)
		r.doc.Spec = wire["spec"].(json.RawMessage)
		r.doc.DeletionProtection = wire["deletion_protection"].(bool)
	}
	r.doc.Revision = fmt.Sprintf("%064d", 2+r.updated+r.adopted+r.released)
	return *r.doc, nil
}
func fixture() (*Service, *memoryKube, *memoryRemote) {
	k := &memoryKube{object: Object{APIVersion: "identity.asterius.io/v1alpha1", Kind: "Resource", Metadata: Metadata{Name: "api", Namespace: "identity-acme", UID: "uid-1", ResourceVersion: "1", Generation: 1}, Spec: json.RawMessage(`{"tenantRef":"default","identifier":"https://api.example/","scopes":["read"],"defaultTokenLifetimeSeconds":300,"introspectionClients":[]}`)}}
	r := &memoryRemote{owner: `["acme","controller"]`}
	s := &Service{Config: Config{Namespace: "identity-acme", Tenant: "acme", ClusterID: "test", SecretNames: []string{"allowed"}}, Kube: k, Remote: r}
	return s, k, r
}
func reconcile(t *testing.T, s *Service, k *memoryKube) {
	t.Helper()
	if err := s.Reconcile(context.Background(), k.object); err != nil {
		t.Fatal(err)
	}
}
func condition(k *memoryKube, kind string) string {
	for _, condition := range k.object.Status.Conditions {
		if condition.Type == kind {
			return condition.Status
		}
	}
	return ""
}

func TestFinalizerLostCreateRetryAndStatusConverge(t *testing.T) {
	s, k, r := fixture()
	r.lostCreate = true
	reconcile(t, s, k)
	if r.created != 0 || !slices.Contains(k.object.Metadata.Finalizers, finalizer) {
		t.Fatal("write occurred before durable finalizer")
	}
	if err := s.Reconcile(context.Background(), k.object); err == nil {
		t.Fatal("lost committed response did not trigger bounded retry")
	}
	if condition(k, "Ready") != "False" || k.object.Status.ObservedGeneration != 0 {
		t.Fatal("ambiguous creation reported success")
	}
	reconcile(t, s, k)
	if r.created != 1 || condition(k, "Ready") != "True" || k.object.Status.RemoteID == "" {
		t.Fatal("lost create did not recover exact logical identity")
	}
	reconcile(t, s, k)
	if r.updated != 0 {
		t.Fatal("unchanged state mutated")
	}
}
func TestConsoleDriftRequiresNewDesiredGeneration(t *testing.T) {
	s, k, r := fixture()
	reconcile(t, s, k)
	reconcile(t, s, k)
	r.doc.Spec = json.RawMessage(`{"identifier":"https://api.example/","scopes":["console"],"default_token_lifetime_seconds":300,"introspection_clients":[]}`)
	r.doc.Revision = fmt.Sprintf("%064d", 9)
	reconcile(t, s, k)
	if condition(k, "Drifted") != "True" || r.updated != 0 {
		t.Fatal("console edit was silently overwritten")
	}
	k.object.Metadata.Generation++
	reconcile(t, s, k)
	if condition(k, "Ready") != "True" || r.updated != 1 || k.object.Status.ObservedGeneration != 2 {
		t.Fatal("explicit desired update did not replan and converge")
	}
}
func TestForeignIdentityOwnerAndSecretBoundaries(t *testing.T) {
	s, k, r := fixture()
	reconcile(t, s, k)
	reconcile(t, s, k)
	foreign := "other"
	r.doc.Owner = &foreign
	reconcile(t, s, k)
	if condition(k, "OwnershipConflict") != "True" || r.updated != 0 || r.adopted != 0 {
		t.Fatal("foreign ownership was claimed")
	}
	k.object.Metadata.Namespace = "another"
	if s.Reconcile(context.Background(), k.object) == nil {
		t.Fatal("cross-namespace object accepted")
	}
	if _, err := s.secret(context.Background(), Ref{Name: "forbidden", Key: "key"}); err == nil {
		t.Fatal("unconfigured Secret was read")
	}
}
func TestInvalidSpecificationNeverReportsReady(t *testing.T) {
	s, k, r := fixture()
	k.object.Spec = json.RawMessage(`{"tenantRef":"foreign","identifier":"https://api.example/"}`)
	reconcile(t, s, k)
	if condition(k, "Ready") != "False" || r.created != 0 {
		t.Fatal("invalid object reported success or mutated authority")
	}
}
func TestProtectedDeleteRequiresPreviouslyConfirmedGeneration(t *testing.T) {
	s, k, r := fixture()
	reconcile(t, s, k)
	reconcile(t, s, k)
	now := time.Now()
	k.object.Metadata.DeletionTimestamp = &now
	k.object.Spec = json.RawMessage(`{"tenantRef":"default","identifier":"https://api.example/","scopes":["read"],"defaultTokenLifetimeSeconds":300,"introspectionClients":[],"deletionPolicy":"Delete","deletionProtection":false}`)
	k.object.Metadata.Generation++
	reconcile(t, s, k)
	if r.deleted != 0 || !slices.Contains(k.object.Metadata.Finalizers, finalizer) {
		t.Fatal("unobserved protection disable authorized delete")
	}
	// The separate generation must have reconciled before DELETE was requested.
	k.object.Metadata.DeletionTimestamp = nil
	reconcile(t, s, k)
	k.object.Metadata.DeletionTimestamp = &now
	k.object.Metadata.Generation++ // Real API-server markAsDeleting behavior.
	k.failStatus = false
	reconcile(t, s, k)
	if r.deleted != 1 || slices.Contains(k.object.Metadata.Finalizers, finalizer) {
		t.Fatal("confirmed unprotected deletion failed")
	}
}
func TestRetainReleaseAndDeleteReceiptsSurviveLostFinalizerWrite(t *testing.T) {
	s, k, r := fixture()
	reconcile(t, s, k)
	reconcile(t, s, k)
	now := time.Now()
	k.object.Metadata.DeletionTimestamp = &now
	reconcile(t, s, k)
	if r.released != 1 || r.doc == nil || r.doc.Owner != nil || slices.Contains(k.object.Metadata.Finalizers, finalizer) {
		t.Fatal("retain did not release and preserve identity")
	}
	// A second owner-free read after a lost finalizer response cannot re-adopt.
	k.object.Metadata.Finalizers = []string{finalizer}
	reconcile(t, s, k)
	if r.adopted != 0 || r.released != 1 || slices.Contains(k.object.Metadata.Finalizers, finalizer) {
		t.Fatal("retain retry reclaimed unowned state")
	}
}
func FuzzOperatorDesired(f *testing.F) {
	f.Add([]byte(`{"tenantRef":"default","identifier":"https://api.example/","scopes":[],"defaultTokenLifetimeSeconds":300,"introspectionClients":[]}`))
	f.Add([]byte(`{"tenantRef":"foreign","tenantRef":"default","password":"secret"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, k, _ := fixture()
		k.object.Spec = raw
		controls, desired, err := s.desired(context.Background(), k.object)
		if err == nil && (controls.TenantRef != "default" || client.PublicSpec(desired) != nil) {
			t.Fatal("desired parser escaped public tenant-bound contract")
		}
	})
}
