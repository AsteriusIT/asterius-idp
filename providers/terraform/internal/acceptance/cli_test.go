// Real CLI subprocesses exercise the provider protocol, state, plans and external keys.
// TestLiveCLI requires an isolated operator-provisioned Asterius fixture; it never starts or targets production.
package acceptance

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
)

type cliFixture struct {
	issuer, keyFile, keyID, caFile, clientID, userID, resource string
	publicJWK                                                  map[string]any
	drift                                                      func(string)
	live                                                       bool
}

func tools(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, name := range []string{"terraform", "tofu"} {
		path := os.Getenv("ASTERIUS_ACCEPTANCE_" + strings.ToUpper(name))
		if path == "" {
			path, _ = exec.LookPath(name)
		}
		if path == "" {
			t.Fatalf("%s CLI is required; set ASTERIUS_ACCEPTANCE_%s", name, strings.ToUpper(name))
		}
		out = append(out, path)
	}
	return out
}
func binary(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("ASTERIUS_PROVIDER_BINARY"); path != "" {
		return path
	}
	path := filepath.Join(t.TempDir(), "terraform-provider-asterius")
	cmd := exec.Command("go", "build", "-o", path, "../..")
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("provider build failed: %v\n%s", err, raw)
	}
	return path
}
func TestControlledCLI(t *testing.T) {
	if os.Getenv("ASTERIUS_ACCEPTANCE_CLI") != "1" {
		t.Skip("set ASTERIUS_ACCEPTANCE_CLI=1 to run Terraform and OpenTofu subprocesses")
	}
	f := newFixture(t)
	runStack(t, cliFixture{issuer: f.server.URL + "/t/admin", keyFile: f.keyFile, keyID: "registered", caFile: f.caFile, clientID: "controller", userID: "00000000-0000-0000-0000-000000000001", publicJWK: client.PublicJWK(f.key), drift: f.drift})
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.proofs < 20 || f.assertions < 2 {
		t.Fatal("CLI did not exercise fresh service authentication")
	}
}
func TestLiveCLI(t *testing.T) {
	if os.Getenv("ASTERIUS_ACCEPTANCE_LIVE") != "1" {
		t.Skip("isolated real Asterius fixture required; see README acceptance recipe")
	}
	jwkPath := os.Getenv("ASTERIUS_ACCEPTANCE_PUBLIC_JWK")
	raw, err := os.ReadFile(jwkPath)
	if err != nil {
		t.Fatal("external public JWK file required")
	}
	var jwk map[string]any
	if json.Unmarshal(raw, &jwk) != nil {
		t.Fatal("public JWK is invalid")
	}
	if err = client.PublicSpec(raw); err != nil {
		t.Fatal(err)
	}
	f := cliFixture{issuer: os.Getenv("ASTERIUS_ISSUER"), keyFile: os.Getenv("ASTERIUS_SIGNING_KEY_FILE"), keyID: os.Getenv("ASTERIUS_SIGNING_KEY_ID"), caFile: os.Getenv("ASTERIUS_CA_FILE"), clientID: os.Getenv("ASTERIUS_CLIENT_ID"), userID: os.Getenv("ASTERIUS_ACCEPTANCE_USER_ID"), resource: os.Getenv("ASTERIUS_TOKEN_RESOURCE"), publicJWK: jwk, live: true}
	if f.issuer == "" || f.userID == "" {
		t.Fatal("isolated fixture issuer and existing user ID are required")
	}
	f.drift = func(id string) {
		command := os.Getenv("ASTERIUS_ACCEPTANCE_DRIFT_COMMAND")
		if command == "" {
			t.Fatal("live fixture drift command is required (ordinary console/API or isolated DB writer)")
		}
		cmd := exec.Command(command, id)
		if raw, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture drift failed: %v %s", err, raw)
		}
	}
	runStack(t, f)
}
func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
func runStack(t *testing.T, f cliFixture) {
	t.Helper()
	bin := binary(t)
	for _, tool := range tools(t) {
		t.Run(filepath.Base(tool), func(t *testing.T) {
			dir := t.TempDir()
			prefix := fmt.Sprintf("acceptance-%d", time.Now().UnixNano())
			tenant := fmt.Sprintf("iac%d", time.Now().UnixNano())
			rc := filepath.Join(dir, "cli.rc")
			write(t, rc, fmt.Sprintf(`provider_installation {
 dev_overrides {
  "registry.terraform.io/asterius/asterius" = %q
  "registry.opentofu.org/asterius/asterius" = %q
 }
 direct {}
}`, filepath.Dir(bin), filepath.Dir(bin)))
			env := append(os.Environ(), "TF_CLI_CONFIG_FILE="+rc, "TOFU_CLI_CONFIG_FILE="+rc, "CHECKPOINT_DISABLE=1", "TF_IN_AUTOMATION=1", "ASTERIUS_ISSUER="+f.issuer, "ASTERIUS_CLIENT_ID="+f.clientID, "ASTERIUS_SIGNING_KEY_FILE="+f.keyFile, "ASTERIUS_SIGNING_KEY_ID="+f.keyID, "ASTERIUS_CA_FILE="+f.caFile, "ASTERIUS_TOKEN_RESOURCE="+f.resource, "ASTERIUS_SCOPES="+strings.Join(client.Scopes(), " "))
			// Debug logging is disabled: provider never logs bodies; scans below inspect every captured CLI diagnostic.
			filtered := env[:0]
			for _, item := range env {
				if !strings.HasPrefix(item, "TF_LOG=") && !strings.HasPrefix(item, "TF_LOG_PATH=") && !strings.HasPrefix(item, "ASTERIUS_TARGET_TENANT=") {
					filtered = append(filtered, item)
				}
			}
			env = filtered
			var logs []byte
			run := func(expected int, args ...string) []byte {
				t.Helper()
				cmd := exec.Command(tool, args...)
				cmd.Dir = dir
				cmd.Env = env
				raw, err := cmd.CombinedOutput()
				logs = append(logs, raw...)
				code := 0
				if err != nil {
					if exit, ok := err.(*exec.ExitError); ok {
						code = exit.ExitCode()
					} else {
						t.Fatal(err)
					}
				}
				if code != expected {
					t.Fatalf("%s %v exit %d expected %d\n%s", tool, args, code, expected, raw)
				}
				return raw
			}
			jwks, _ := json.Marshal(map[string]any{"keys": []any{f.publicJWK}})
			tenantSpec, _ := json.Marshal(map[string]any{"tenant_id": tenant, "issuer": f.issuer[:strings.LastIndex(f.issuer, "/")] + "/" + tenant, "display_name": "Terraform tenant", "default_resource": "https://default.example/", "options": map[string]any{}})
			config := fmt.Sprintf(`terraform {
 required_providers {
  asterius = { source = "asterius/asterius" }
 }
}
provider "asterius" {}
resource "asterius_tenant" "managed" {
 external_key = %q
 spec_json = %q
 }
resource "asterius_resource" "managed" {
 external_key = %q
 spec_json = jsonencode({identifier=%q,scopes=["read"],default_token_lifetime_seconds=300,introspection_clients=[]})
 }
resource "asterius_group" "managed" {
 external_key = %q
 spec_json = jsonencode({name=%q,display_name="IaC group"})
 }
resource "asterius_application" "managed" {
 external_key = %q
 spec_json = jsonencode({client_name="IaC application",redirect_uris=["https://rp.example/cb"],jwks=jsondecode(%q),resources=[]})
 }
resource "asterius_membership" "managed" {
 external_key = %q
 spec_json = jsonencode({group_id=asterius_group.managed.identity_key,user_id=%q})
 }
resource "asterius_policy" "managed" {
 external_key = %q
 spec_json = jsonencode({version=1,rules=[]})
 }
`, prefix+"/tenant", string(tenantSpec), prefix+"/resource", "https://"+prefix+".example/", prefix+"/group", prefix, prefix+"/application", string(jwks), prefix+"/membership", f.userID, prefix+"/policy")
			configPath := filepath.Join(dir, "main.tf")
			write(t, configPath, config)
			run(0, "apply", "-auto-approve", "-input=false", "-parallelism=1")
			run(0, "plan", "-input=false", "-detailed-exitcode", "-parallelism=1")
			raw := run(0, "show", "-json")
			var state struct {
				Values struct {
					RootModule struct {
						Resources []struct {
							Address string
							Values  map[string]any
						}
					} `json:"root_module"`
				} `json:"values"`
			}
			if json.Unmarshal(raw, &state) != nil || len(state.Values.RootModule.Resources) != 6 {
				t.Fatal("six resource state missing")
			}
			ids := map[string]string{}
			observed := map[string]string{}
			for _, r := range state.Values.RootModule.Resources {
				ids[r.Address] = r.Values["id"].(string)
				observed[r.Address] = r.Values["observed_spec_json"].(string)
			}
			// All six read-only data sources use the same import identities.
			for address, id := range ids {
				kind := strings.TrimPrefix(strings.Split(address, ".")[0], "asterius_")
				config += fmt.Sprintf("\ndata \"asterius_%s\" \"read\" { id = %q }\n", kind, id)
			}
			write(t, configPath, config)
			run(0, "apply", "-auto-approve", "-input=false", "-parallelism=1")
			run(0, "plan", "-input=false", "-detailed-exitcode", "-parallelism=1")
			// Import every existing live resource into a separate state. Configuration keeps the desired specs but omits creation keys.
			importDir := filepath.Join(dir, "import")
			if err := os.Mkdir(importDir, 0700); err != nil {
				t.Fatal(err)
			}

			// Imported JSON specs are complete canonical reads. Generate matching reviewed HCL from those public specs.
			importedConfig := `terraform {
 required_providers {
  asterius = { source = "asterius/asterius" }
 }
}
provider "asterius" {}
`
			for _, kind := range []string{"tenant", "resource", "group", "application", "membership", "policy"} {
				address := "asterius_" + kind + ".managed"
				importedConfig += fmt.Sprintf("resource \"asterius_%s\" \"managed\" {\n spec_json = %q\n}\n", kind, observed[address])
				importedConfig += fmt.Sprintf("data \"asterius_%s\" \"read\" { id = %q }\n", kind, ids[address])
			}
			write(t, filepath.Join(importDir, "main.tf"), importedConfig)

			originalDir := dir
			dir = importDir
			for _, kind := range []string{"tenant", "resource", "group", "application", "membership", "policy"} {
				address := "asterius_" + kind + ".managed"
				run(0, "import", "-input=false", address, ids[address])
			}
			run(0, "plan", "-input=false", "-detailed-exitcode", "-parallelism=1")
			dir = originalDir
			// Import grants no ownership. Another registered controller can read but cannot apply changes.
			otherDir := filepath.Join(originalDir, "other-controller")
			if err := os.Mkdir(otherDir, 0700); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(otherDir, "main.tf"), fmt.Sprintf(`terraform {
 required_providers {
  asterius = { source = "asterius/asterius" }
 }
}
provider "asterius" {}
resource "asterius_group" "managed" {
 spec_json = jsonencode({name=%q,display_name="Takeover attempt"})
}`, prefix))
			otherID := "other-controller"
			if f.live {
				otherID = os.Getenv("ASTERIUS_ACCEPTANCE_OTHER_CLIENT_ID")
				if otherID == "" {
					t.Fatal("registered alternate controller required for live ownership refusal")
				}
			}
			savedEnv := env
			env = append(append([]string{}, env...), "ASTERIUS_CLIENT_ID="+otherID)
			dir = otherDir
			run(0, "import", "-input=false", "asterius_group.managed", ids["asterius_group.managed"])
			refused := run(1, "apply", "-auto-approve", "-input=false")
			if !strings.Contains(string(refused), "Controller ownership conflict") {
				t.Fatalf("expected ownership refusal: %s", refused)
			}
			env = savedEnv
			dir = originalDir
			// v1 never deletes tenants, including when a caller disables ordinary deletion protection.
			badTenant := strings.Replace(config, "resource \"asterius_tenant\" \"managed\" {", "resource \"asterius_tenant\" \"managed\" {\n retain_on_delete=false\n", 1)
			write(t, configPath, badTenant)
			run(1, "plan", "-input=false")
			write(t, configPath, config)

			run(0, "apply", "-refresh-only", "-auto-approve", "-input=false", "-parallelism=1")
			// A reviewed plan cannot silently write through a subsequent console edit.
			write(t, configPath, strings.Replace(config, "display_name=\"IaC group\"", "display_name=\"Reviewed group\"", 1))
			run(0, "plan", "-input=false", "-parallelism=1", "-out=reviewed.tfplan")
			f.drift(ids["asterius_group.managed"])
			stale := run(1, "apply", "-auto-approve", "-input=false", "reviewed.tfplan")
			if !strings.Contains(string(stale), "revision_conflict") {
				t.Fatalf("expected exact revision conflict: %s", stale)
			}
			write(t, configPath, config)

			f.drift(ids["asterius_group.managed"])
			run(2, "plan", "-input=false", "-detailed-exitcode", "-parallelism=1")
			run(0, "apply", "-auto-approve", "-input=false", "-parallelism=1")
			run(0, "plan", "-input=false", "-detailed-exitcode", "-parallelism=1")
			run(1, "destroy", "-auto-approve", "-input=false", "-target=asterius_resource.managed")
			// Explicitly disable protection on an independent object, apply first, then remove it. Tenant remains retained.
			config = strings.Replace(config, "resource \"asterius_resource\" \"managed\" {", "resource \"asterius_resource\" \"managed\" {\n deletion_protection = false\n", 1)
			write(t, configPath, config)
			run(0, "apply", "-auto-approve", "-input=false", "-parallelism=1")
			run(0, "destroy", "-auto-approve", "-input=false", "-target=asterius_resource.managed")
			// The tenant-wide policy has one natural identity. Remove only this fixture-owned policy before the other CLI starts.
			config = strings.Replace(config, "resource \"asterius_policy\" \"managed\" {", "resource \"asterius_policy\" \"managed\" {\n deletion_protection = false\n", 1)
			write(t, configPath, config)
			run(0, "apply", "-auto-approve", "-input=false", "-target=asterius_policy.managed")
			run(0, "destroy", "-auto-approve", "-input=false", "-target=asterius_policy.managed")

			privateRaw, _ := os.ReadFile(f.keyFile)
			for _, sensitive := range []string{string(privateRaw), "-----BEGIN PRIVATE KEY-----", "\"client_secret\"", "\"access_token\"", "\"refresh_token\"", "registration_access_token"} {
				if strings.Contains(string(logs), sensitive) {
					t.Fatalf("credential field leaked to CLI logs: %q", sensitive)
				}
			}
			for _, stateDir := range []string{originalDir, importDir} {
				for _, name := range []string{"terraform.tfstate", "terraform.tfstate.backup"} {
					raw, err := os.ReadFile(filepath.Join(stateDir, name))
					if err != nil {
						continue
					}
					for _, marker := range []string{"-----BEGIN PRIVATE KEY-----", "\"client_secret\"", "\"access_token\"", "\"refresh_token\"", "registration_access_token"} {
						if strings.Contains(string(raw), marker) {
							t.Fatalf("credential field leaked to state: %s", marker)
						}
					}
				}
			}
			t.Log("six apply/import/data sources/refresh/empty second plans, stale-plan refusal, ownership refusal, drift repair and protected deletion verified")
		})
	}
}
