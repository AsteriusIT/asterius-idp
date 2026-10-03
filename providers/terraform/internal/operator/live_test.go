package operator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Models a lost response after a real authenticated management create committed.
// Every server call and subsequent exact logical-key lookup remains real.
type committedResponseLoss struct {
	Remote
	lost    bool
	created int
}

func (r *committedResponseLoss) Create(ctx context.Context, kind, key string, spec json.RawMessage, protect bool) (client.Document, error) {
	d, err := r.Remote.Create(ctx, kind, key, spec, protect)
	if err == nil {
		r.created++
		if !r.lost {
			r.lost = true
			return client.Document{}, errors.New("controlled response lost after real commit")
		}
	}
	return d, err
}

func TestLiveOperatorLifecycle(t *testing.T) {
	dir := os.Getenv("ASTERIUS_OPERATOR_FIXTURE_DIR")
	if dir == "" {
		t.Skip("owned real Asterius/Kubernetes fixture required")
	}
	root, err := filepath.Abs("../../../../")
	if err != nil {
		t.Fatal(err)
	}
	kubeconfig := filepath.Join(dir, "kubeconfig")
	kubectl := func(input []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
		cmd.Stdin = strings.NewReader(string(input))
		raw, err := cmd.Output()
		if err != nil {
			t.Fatalf("owned fixture Kubernetes operation failed: %s", strings.Join(args, " "))
		}
		return raw
	}
	apply := func(value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		kubectl(raw, "apply", "-f", "-")
	}
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal("owned fixture file unavailable")
		}
		return raw
	}
	schema := exec.Command("node", "--input-type=module", "-e", `import{crds,examples,namespaceDocuments}from'./tools/identity-operator/schema.mjs';console.log(JSON.stringify({crds,examples,namespace:namespaceDocuments('identity-e2e')}));`)
	schema.Dir = root
	raw, err := schema.Output()
	if err != nil {
		t.Fatal("schema fixture unavailable")
	}
	var fixtures struct {
		CRDs      []map[string]any `json:"crds"`
		Examples  []map[string]any `json:"examples"`
		Namespace []map[string]any `json:"namespace"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("invalid schema fixture")
	}
	list := func(items any) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "List", "items": items}
	}
	apply(list(fixtures.CRDs))
	kubectl(nil, "wait", "--for=condition=Established", "crd/applications.identity.asterius.io", "--timeout=30s")
	namespace := "identity-e2e"
	apply(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": namespace}})
	issuer := os.Getenv("ASTERIUS_OPERATOR_ISSUER")
	binding := fixtures.Examples[1]
	binding["metadata"].(map[string]any)["namespace"] = namespace
	spec := binding["spec"].(map[string]any)
	spec["tenantId"] = "e2e"
	spec["issuer"] = issuer
	spec["clientId"] = "operator-controller"
	spec["clusterId"] = "controlled"
	apply(binding)
	for _, secret := range []struct{ name, key, file string }{{"asterius-auth-key", "key.pem", "controller.pem"}, {"asterius-dpop-key", "key.pem", "dpop.pem"}, {"asterius-ca", "ca.pem", "ca.pem"}, {"application-public-jwks", "jwks.json", "public-jwks.json"}} {
		apply(map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": secret.name, "namespace": namespace}, "data": map[string]any{secret.key: base64.StdEncoding.EncodeToString(read(secret.file))}})
	}
	apply(list(fixtures.Namespace))
	// Real projected-token semantics using TokenRequest, never a mock service token.
	token := kubectl(nil, "create", "token", "asterius-controller", "-n", namespace, "--duration=600s")
	tokenFile := filepath.Join(dir, "operator-kubernetes-token")
	if os.WriteFile(tokenFile, token, 0600) != nil {
		t.Fatal("fixture token write failed")
	}
	server := strings.TrimSpace(string(kubectl(nil, "config", "view", "-o", "jsonpath={.clusters[0].cluster.server}")))
	caData := kubectl(nil, "config", "view", "--raw", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	ca, err := base64.StdEncoding.DecodeString(string(caData))
	if err != nil {
		t.Fatal("fixture Kubernetes CA unavailable")
	}
	caFile := filepath.Join(dir, "kube-ca.pem")
	if os.WriteFile(caFile, ca, 0600) != nil {
		t.Fatal("fixture CA write failed")
	}
	kube, err := NewKube(server, tokenFile, caFile, namespace)
	if err != nil {
		t.Fatal(err)
	}
	object, err := kube.Get(context.Background(), "asteriustenantbindings", "default")
	if err != nil {
		t.Fatal("controller cannot read its pinned binding")
	}
	var responseLoss *committedResponseLoss
	service := &Service{Config: Config{Namespace: namespace, Tenant: "e2e", Issuer: issuer, ClientID: "operator-controller", BindingUID: object.Metadata.UID, ClusterID: "controlled", KeyID: "operator-1", Holder: "real-fixture-1", SecretNames: []string{"asterius-auth-key", "asterius-dpop-key", "asterius-ca", "application-public-jwks"}}, Kube: kube, Factory: func(cfg client.Config) (Remote, error) {
		remote, err := client.New(cfg)
		if err != nil {
			return nil, err
		}
		responseLoss = &committedResponseLoss{Remote: remote}
		return responseLoss, nil
	}}
	cycle := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := service.Cycle(ctx); err != nil {
			// Controlled loss after a successful real commit exercises the same
			// bounded retry that Run performs; never treat a different error as success.
			if strings.Contains(err.Error(), "remote operation unavailable") {
				return
			}
			t.Fatalf("real controller cycle refused: %v", err)
		}
	}
	for _, desired := range fixtures.Examples[2:] {
		desired["metadata"].(map[string]any)["namespace"] = namespace
		if desired["kind"] == "Application" {
			spec := desired["spec"].(map[string]any)
			delete(spec, "jwksUri")
			spec["publicJwksSecretRef"] = map[string]any{"name": "application-public-jwks", "key": "jwks.json"}
		}
		apply(desired)
	}
	for i := 0; i < 6; i++ {
		cycle()
		time.Sleep(100 * time.Millisecond)
	}
	checkReady := func(plural, name string) Object {
		t.Helper()
		o, err := kube.Get(context.Background(), plural, name)
		if err != nil {
			t.Fatal("managed object unavailable")
		}
		ready := false
		for _, condition := range o.Status.Conditions {
			ready = ready || (condition.Type == "Ready" && condition.Status == "True")
		}
		if !ready || o.Status.ObservedGeneration != o.Metadata.Generation || o.Status.RemoteID == "" {
			t.Fatalf("%s did not converge: %+v", plural, o.Status.Conditions)
		}
		return o
	}
	resource := checkReady("resources", "billing")
	app := checkReady("applications", "billing")
	checkReady("policies", "tenant")
	originalResourceID, originalApplicationID := resource.Status.RemoteID, app.Status.RemoteID
	if responseLoss.created != 3 {
		t.Fatal("lost creation response produced duplicate actual resource creation")
	}
	// An ordinary live table writer participates in the same durable revision
	// trigger as console/API edits; it must be reported before any overwrite.
	drift := exec.Command("docker", "exec", os.Getenv("ASTERIUS_ACCEPTANCE_DB_CONTAINER"), "psql", "-U", "asterius", "-d", os.Getenv("ASTERIUS_OPERATOR_DB"), "-v", "ON_ERROR_STOP=1", "-c", `UPDATE resource_servers SET token_lifetime_seconds=301 WHERE tenant_id='e2e' AND identifier='https://billing-api.example/';`)
	if _, err := drift.Output(); err != nil {
		t.Fatal("controlled ordinary writer drift failed")
	}
	cycle()
	drifted, err := kube.Get(context.Background(), "resources", "billing")
	if err != nil {
		t.Fatal(err)
	}
	driftReported := false
	for _, condition := range drifted.Status.Conditions {
		driftReported = driftReported || (condition.Type == "Drifted" && condition.Status == "True")
	}
	if !driftReported {
		t.Fatal("console-equivalent edit was not reported")
	}
	liveDrift, err := service.Remote.Read(context.Background(), originalResourceID)
	if err != nil {
		t.Fatal("drift live read failed")
	}
	var driftSpec map[string]any
	if json.Unmarshal(liveDrift.Spec, &driftSpec) != nil || driftSpec["default_token_lifetime_seconds"] != float64(301) {
		t.Fatal("console drift was overwritten without new desired generation")
	}
	kubectl(nil, "patch", "resource", "billing", "-n", namespace, "--type=merge", "-p", `{"spec":{"defaultTokenLifetimeSeconds":302}}`)
	cycle()
	checkReady("resources", "billing")
	// Reconstruct the controller as after a process restart; authoritative references survive.
	service.Remote = nil
	service.fingerprint = ""
	cycle()
	if checkReady("resources", "billing").Status.RemoteID != originalResourceID || checkReady("applications", "billing").Status.RemoteID != originalApplicationID {
		t.Fatal("restart changed identity")
	}
	// A real different controller principal cannot take ownership of this resource.
	other, err := client.New(client.Config{Issuer: issuer, IssuingTenant: "e2e", ClientID: "terraform-other-controller", KeyID: "operator-1", KeyMaterial: read("controller.pem"), CAMaterial: read("ca.pem"), Resource: issuer + "/admin/api/v1", Scopes: []string{"admin.session:read", "admin.resource_servers:read", "admin.resource_servers:write", "admin.clients:read", "admin.clients:write"}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	remote, err := other.Read(context.Background(), originalResourceID)
	if err != nil {
		t.Fatal("other controller scoped read failed")
	}
	_, err = other.Mutate(context.Background(), "POST", remote.ID, "/adopt", remote.Revision, map[string]any{})
	if err == nil {
		t.Fatal("dual controller ownership accepted")
	}
	// Rotate the actual DPoP Secret and prove new sender-constrained service auth works.
	oldFingerprint := service.fingerprint
	apply(map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "asterius-dpop-key", "namespace": namespace}, "data": map[string]any{"key.pem": base64.StdEncoding.EncodeToString(read("dpop-rotated.pem"))}})
	cycle()
	if service.fingerprint == oldFingerprint {
		t.Fatal("Secret rotation did not reconstruct service credential")
	}
	checkReady("resources", "billing")
	// Invalid rotated secret fails closed instead of continuing with old keys;
	// conditions must never contain the offending private value or a PEM key.
	apply(map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "asterius-dpop-key", "namespace": namespace}, "data": map[string]any{"key.pem": base64.StdEncoding.EncodeToString([]byte("private-rotation-canary"))}})
	if service.Cycle(context.Background()) == nil || service.Remote != nil {
		t.Fatal("invalid Secret rotation retained usable old credential")
	}
	for _, plural := range []string{"applications", "resources", "policies"} {
		objects, err := kube.List(context.Background(), plural)
		if err != nil {
			t.Fatal(err)
		}
		for _, object := range objects {
			raw, _ := json.Marshal(object.Status)
			if strings.Contains(string(raw), "private-rotation-canary") || strings.Contains(string(raw), "PRIVATE KEY") {
				t.Fatal("private rotation value leaked to status")
			}
		}
	}
	apply(map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "asterius-dpop-key", "namespace": namespace}, "data": map[string]any{"key.pem": base64.StdEncoding.EncodeToString(read("dpop-rotated.pem"))}})
	cycle()
	checkReady("resources", "billing")
	// A real second replica must remain standby while the first Lease is live.
	standby := *service
	standby.Config.Holder = "real-fixture-2"
	if err := standby.Cycle(context.Background()); err != nil {
		t.Fatal("standby cycle failed")
	}
	checkReady("resources", "billing")
	// Freeze only the owned fixture server: real HTTP requests time out, no fake
	// remote status is injected. Resume before the next convergence cycle.
	pid, err := strconv.Atoi(os.Getenv("ASTERIUS_OPERATOR_SERVER_PID"))
	if err != nil || pid <= 1 {
		t.Fatal("owned server PID unavailable")
	}
	if syscall.Kill(pid, syscall.SIGSTOP) != nil {
		t.Fatal("owned server could not pause")
	}
	defer syscall.Kill(pid, syscall.SIGCONT)
	cycle()
	outage, err := kube.Get(context.Background(), "resources", "billing")
	if err != nil {
		t.Fatal(err)
	}
	readyDuringOutage := false
	for _, condition := range outage.Status.Conditions {
		readyDuringOutage = readyDuringOutage || (condition.Type == "Ready" && condition.Status == "True")
	}
	if readyDuringOutage {
		t.Fatal("outage retained successful readiness")
	}
	if syscall.Kill(pid, syscall.SIGCONT) != nil {
		t.Fatal("owned server could not resume")
	}
	cycle()
	checkReady("resources", "billing")
	// Changing the trusted binding UID must fail before any Asterius operation.
	service.Config.BindingUID = "foreign"
	if service.Cycle(context.Background()) == nil {
		t.Fatal("binding UID replacement accepted")
	}
	service.Config.BindingUID = object.Metadata.UID
	cycle()
	checkReady("resources", "billing")
	// Retain releases actual owner while preserving the remote resource.
	kubectl(nil, "delete", "application", "billing", "-n", namespace, "--wait=false")
	cycle()
	retained, err := service.Remote.Read(context.Background(), originalApplicationID)
	if err != nil || retained.Owner != nil {
		t.Fatal("retain did not preserve and release actual application")
	}
	// The retained client still references this resource. A distinct owner must
	// explicitly adopt and deprovision it before dependent resource removal.
	retained, err = other.Mutate(context.Background(), "POST", retained.ID, "/adopt", retained.Revision, map[string]any{})
	if err != nil {
		t.Fatal("explicit released application adoption failed")
	}
	retained, err = other.Mutate(context.Background(), "PUT", retained.ID, "", retained.Revision, map[string]any{"spec": retained.Spec, "deletion_protection": false})
	if err != nil {
		t.Fatal("explicit application deprovision protection update failed")
	}
	if _, err = other.Mutate(context.Background(), "DELETE", retained.ID, "", retained.Revision, nil); err != nil {
		t.Fatal("explicit application deprovision failed")
	}
	// Protection disable is a distinct successful generation before real deletion.
	kubectl(nil, "patch", "resource", "billing", "-n", namespace, "--type=merge", "-p", `{"spec":{"deletionPolicy":"Delete","deletionProtection":false}}`)
	cycle()
	protectedState := checkReady("resources", "billing")
	if protectedState.Status.ObservedDeletionProtection == nil || *protectedState.Status.ObservedDeletionProtection {
		t.Fatal("protection change was not confirmed")
	}
	kubectl(nil, "delete", "resource", "billing", "-n", namespace, "--wait=false")
	cycle()
	if _, err := service.Remote.Read(context.Background(), originalResourceID); !client.IsNotFound(err) {
		pending, _ := kube.Get(context.Background(), "resources", "billing")
		t.Fatalf("real resource remained after confirmed deletion: generation=%d observed=%d conditions=%+v", pending.Metadata.Generation, pending.Status.ObservedGeneration, pending.Status.Conditions)
	}
	if path := os.Getenv("ASTERIUS_OPERATOR_EVIDENCE_PATH"); path != "" {
		evidence := map[string]any{"recorded_at": time.Now().UTC().Format(time.RFC3339), "target": "Kubernetes v1.35.0", "server_binary_sha256": os.Getenv("ASTERIUS_OPERATOR_BINARY_SHA256"),
			"checks": []string{"three-kind canonical create", "committed response loss and exact lookup recovery", "ordinary writer drift reported without overwrite", "new desired generation conditional convergence", "restart preserves remote identities", "different FAPI controller owner refused", "real DPoP Secret rotation", "invalid rotation failclosed without stale credential", "status private-canary redaction", "binding UID isolation", "standby Lease", "real HTTP timeout after owned server pause", "real HTTP recovery", "Retain preserves identity and releases owner", "explicit adoption of released application", "explicit dependent application deprovision", "protection false confirmed before DELETE generation bump", "conditional protected deletion"}}
		raw, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil || os.WriteFile(path, append(raw, '\n'), 0600) != nil {
			t.Fatal("public evidence write failed")
		}
	}
	fmt.Println("real controller: create/lost-response retry/restart/dual-owner denial/Secret rotation/UID isolation/standby Lease/actual timeout recovery/retain/protected delete PASS")
}
