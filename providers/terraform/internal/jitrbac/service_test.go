package jitrbac

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/operator"
	"testing"
	"time"
)

func config() Config {
	return Config{Tenant: "fixture", ControllerClient: "controller", ClusterClient: "cluster-client", Cluster: "cluster-a", Namespace: "jit", EntitlementID: "10000000-0000-4000-8000-000000000001", BindingRevision: "10000000-0000-4000-8000-000000000002", RoleBindingName: "temporary-read", RoleBindingUID: "10000000-0000-4000-8000-000000000003", RoleName: "temporary-read", ProfileRevision: 1, Interval: time.Second}
}
func projection(c Config) Projection {
	return Projection{Binding: Binding{EntitlementID: c.EntitlementID, Revision: c.BindingRevision, ControllerClientID: c.ControllerClient, ClusterClientID: c.ClusterClient, Cluster: c.Cluster, Namespace: c.Namespace, ProfileRevision: c.ProfileRevision, Enabled: true}, EntitlementRevision: "10000000-0000-4000-8000-000000000004", ObservedAt: time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC), Subjects: []Subject{{ActivationID: "10000000-0000-4000-8000-000000000005", Username: "asterius-jit:10000000-0000-4000-8000-000000000002:stable-public-sub", ExpiresAt: time.Date(2026, 10, 3, 1, 1, 0, 0, time.UTC)}}}
}
func TestBoundedProjectionRefusesForeignExpiredAndSlowAuthority(t *testing.T) {
	c := config()
	s := Service{Config: c}
	p := projection(c)
	if got, err := s.subjects(p, 0); err != nil || len(got) != 1 {
		t.Fatal("valid exact subject refused")
	}
	for _, mutate := range []func(*Projection){func(p *Projection) { p.Binding.Namespace = "other" }, func(p *Projection) { p.Binding.ControllerClientID = "other" }, func(p *Projection) { p.Subjects[0].Username = "system:masters" }, func(p *Projection) { p.Subjects[0].Username = "asterius:fixture:cluster-a:stable-public-sub" }, func(p *Projection) {
		p.Subjects[0].Username = "asterius-jit:10000000-0000-4000-8000-000000000099:stable-public-sub"
	}, func(p *Projection) { p.Subjects = append(p.Subjects, p.Subjects[0]) }} {
		p = projection(c)
		mutate(&p)
		if _, err := s.subjects(p, 0); err == nil {
			t.Fatal("foreign or duplicate authority accepted")
		}
	}
	p = projection(c)
	if got, err := s.subjects(p, time.Minute); err != nil || len(got) != 0 {
		t.Fatal("slow response extended exclusive expiry")
	}
	p = projection(c)
	p.Subjects[0].ExpiresAt = p.ObservedAt
	if got, err := s.subjects(p, 0); err != nil || len(got) != 0 {
		t.Fatal("expired subject accepted")
	}
	p = projection(c)
	p.Binding.Enabled = false
	if got, err := s.subjects(p, 0); err != nil || len(got) != 0 {
		t.Fatal("disabled mapping accepted")
	}
}

type remote struct {
	raw json.RawMessage
	err error
}

func (r remote) KubernetesProjectionRaw(context.Context, string) (json.RawMessage, error) {
	return r.raw, r.err
}

type cluster struct {
	object   operator.RoleBinding
	calls    int
	subjects []operator.RBACSubject
}

func (k *cluster) GetRoleBinding(context.Context, string) (operator.RoleBinding, error) {
	return k.object, nil
}
func (k *cluster) PatchRoleBindingSubjects(_ context.Context, _ string, _ string, _ string, s []operator.RBACSubject) error {
	k.calls++
	k.subjects = s
	return nil
}
func TestReadFailureClearsDedicatedBindingAndRefusesForeignObject(t *testing.T) {
	c := config()
	k := &cluster{object: operator.RoleBinding{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Metadata: operator.Metadata{Name: c.RoleBindingName, Namespace: c.Namespace, UID: c.RoleBindingUID, ResourceVersion: "5"}, RoleRef: operator.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: c.RoleName}, Subjects: []operator.RBACSubject{{Kind: "User", Name: "old"}}}}
	s := Service{Config: c, Kube: k, Remote: remote{err: errors.New("storage unavailable")}}
	if s.Step(context.Background()) == nil || k.calls != 1 || len(k.subjects) != 0 {
		t.Fatal("failed projection preserved temporary authority")
	}
	k.calls = 0
	k.object.Metadata.UID = "foreign"
	if s.Step(context.Background()) == nil || k.calls != 0 {
		t.Fatal("foreign binding mutated")
	}
}
func TestProjectionParserRefusesUnknownAndOversizedInput(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"posted_role":"cluster-admin"}`), make([]byte, 65537), []byte(`{} {}`)} {
		if _, err := DecodeProjection(raw); err == nil {
			t.Fatal("unbounded or injected protocol document accepted")
		}
	}
}
func FuzzProjectionParser(f *testing.F) {
	raw, _ := json.Marshal(projection(config()))
	f.Add(raw)
	f.Fuzz(func(t *testing.T, input []byte) {
		p, err := DecodeProjection(input)
		if err == nil {
			_, _ = Service{Config: config()}.subjects(p, 0)
		}
	})
}
