package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPublicSpecRejectsCredentialsAndPreservesOrderedRules(t *testing.T) {
	for _, raw := range []string{`{"client_secret":"no"}`, `{"jwks":{"keys":[{"kty":"EC","d":"private"}]}}`, `{"kty":"oct","k":"secret"}`, `{"nested":{"private_key":"no"}}`, `{"a":1} {"b":2}`, `{"a":1,"a":2}`, `{"jwks":{"keys":[{"kty":"EC","d":"private","d":null}]}}`} {
		if PublicSpec([]byte(raw)) == nil {
			t.Fatalf("accepted credential/invalid JSON: %s", raw)
		}
	}
	one, err := Canonical([]byte(`{"rules":[{"name":"first"},{"name":"second"}],"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	two, _ := Canonical([]byte(`{"a":1,"rules":[{"name":"second"},{"name":"first"}]}`))
	if one == two {
		t.Fatal("ordered rules lost")
	}
}
func TestOperatorKeyMaterialPinsDPoPAndRejectsInvalidRotation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(key *ecdsa.PrivateKey) []byte {
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	}
	cfg := Config{Issuer: "https://idp.example/t/acme", ClientID: "controller", KeyID: "key", KeyMaterial: encode(key), DPoPMaterial: encode(proofKey), Timeout: time.Second}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := c.proof("GET", "https://idp.example/t/acme/admin/api/v1", "token", "")
	if err != nil {
		t.Fatal(err)
	}
	header, claims := VerifyJWT(t, compact, &proofKey.PublicKey)
	if header["typ"] != "dpop+jwt" || claims["ath"] == nil {
		t.Fatal("proof key or token binding lost")
	}
	if c.cfg.KeyMaterial != nil || c.cfg.DPoPMaterial != nil {
		t.Fatal("raw Secret material retained after parsing")
	}
	cfg.DPoPMaterial = []byte("not a private key")
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid rotated DPoP key accepted")
	}
}
func TestImportIdentityBoundaries(t *testing.T) {
	for _, p := range [][]string{{"acme", "resource", "https://api.example/a?x=y"}, {"acme", "membership", "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"}} {
		raw, _ := json.Marshal(p)
		if _, err := ParseID(b64(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{`["acme","group","ABCDEF00-0000-0000-0000-000000000001"]`, `["acme","policy","other"]`, `["acme","membership","00000000-0000-0000-0000-000000000001"]`, `["acme","tenant","other"]`} {
		if _, err := ParseID(b64([]byte(raw))); err == nil {
			t.Fatal("accepted malformed import")
		}
	}
}
func FuzzParseID(f *testing.F) {
	f.Add(b64([]byte(`["acme","policy","policy"]`)))
	f.Add("%")
	f.Fuzz(func(t *testing.T, id string) {
		parts, err := ParseID(id)
		if err == nil {
			if len(parts) < 3 || !ValidKind(parts[1]) {
				t.Fatal("invalid parse invariant")
			}
		}
	})
}
func FuzzPublicSpec(f *testing.F) {
	f.Add([]byte(`{"jwks":{"keys":[{"kty":"EC","d":"private"}]}}`))
	f.Add([]byte(`{"rules":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if PublicSpec(raw) == nil {
			canonical, err := Canonical(raw)
			if err != nil || !json.Valid([]byte(canonical)) {
				t.Fatal("canonical invariant")
			}
		}
	})
}
func VerifyJWT(t *testing.T, compact string, key *ecdsa.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT")
	}
	var h, c map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if json.Unmarshal(raw, &h) != nil {
		t.Fatal("invalid header")
	}
	raw, _ = base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(raw, &c) != nil {
		t.Fatal("invalid claims")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || len(sig) != 64 || !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("invalid signature")
	}
	return h, c
}
func TestClientUsesBoundKeysFreshProofsNonceAndRedactedErrors(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dir := t.TempDir()
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	var mu sync.Mutex
	seen := map[string]bool{}
	tokenChallenges, managementChallenges := 0, 0
	id := b64([]byte(`["acme","policy","policy"]`))
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		proof := r.Header.Get("DPoP")
		parts := strings.Split(proof, ".")
		if len(parts) != 3 {
			t.Error("missing proof")
			w.WriteHeader(401)
			return
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var h map[string]any
		_ = json.Unmarshal(raw, &h)
		jwk := h["jwk"].(map[string]any)
		x, _ := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
		y, _ := base64.RawURLEncoding.DecodeString(jwk["y"].(string))
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		header, claims := VerifyJWT(t, proof, pub)
		if header["typ"] != "dpop+jwt" || claims["htm"] != r.Method || claims["htu"] != server.URL+r.URL.Path {
			t.Error("wrong proof binding")
		}
		jti := claims["jti"].(string)
		if seen[jti] {
			t.Error("proof replay")
		}
		seen[jti] = true
		if r.URL.Path == "/t/acme/token" {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			_, assertion := VerifyJWT(t, r.Form.Get("client_assertion"), &key.PublicKey)
			if assertion["aud"] != server.URL+"/t/acme" || assertion["iss"] != "controller" || assertion["sub"] != "controller" {
				t.Error("assertion audience/client")
			}
			if seen[assertion["jti"].(string)] {
				t.Error("assertion replay")
			}
			seen[assertion["jti"].(string)] = true
			if tokenChallenges == 0 {
				tokenChallenges++
				w.Header().Set("DPoP-Nonce", "token-nonce")
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
				return
			}
			if claims["nonce"] != "token-nonce" {
				t.Error("missing token nonce")
			}
			_, _ = w.Write([]byte(`{"access_token":"SENTINEL-ACCESS-TOKEN","token_type":"DPoP","expires_in":60,"scope":"admin.session:read admin.policies:read"}`))
			return
		}
		if r.Header.Get("Authorization") != "DPoP SENTINEL-ACCESS-TOKEN" {
			t.Error("wrong authorization")
		}
		digest := sha256.Sum256([]byte("SENTINEL-ACCESS-TOKEN"))
		if claims["ath"] != b64(digest[:]) {
			t.Error("missing token binding")
		}
		if managementChallenges == 0 {
			managementChallenges++
			w.Header().Set("DPoP-Nonce", "management-nonce")
			w.WriteHeader(401)
			return
		}
		if claims["nonce"] != "management-nonce" {
			t.Error("missing resource nonce")
		}
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"code":"owner_conflict","message":"SENTINEL-SECRET","private_key":"PRIVATE"}`))
	}))
	defer server.Close()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Issuer: server.URL + "/t/acme", ClientID: "controller", KeyID: "registered", KeyFile: keyPath, CAFile: caPath, Scopes: []string{"admin.session:read", "admin.policies:read"}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Read(context.Background(), id)
	if err == nil || !strings.Contains(err.Error(), "owner_conflict") || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("unsafe error %v", err)
	}
}

func TestNestedManagementErrorsKeepOnlyBoundedCode(t *testing.T) {
	for _, raw := range []string{`{"error":{"code":"revision_conflict","message":"PRIVATE SENTINEL"}}`, `{"code":"revision_conflict","message":"PRIVATE SENTINEL"}`} {
		err := apiError(412, []byte(raw))
		if !strings.Contains(err.Error(), "revision_conflict") || strings.Contains(err.Error(), "SENTINEL") {
			t.Fatal("unbounded management error")
		}
	}
	err := apiError(500, []byte(`{"error":{"code":"PRIVATE SENTINEL"}}`))
	if strings.Contains(err.Error(), "SENTINEL") {
		t.Fatal("unknown code echoed")
	}
}
func TestResponsePrivateMaterialCannotReachState(t *testing.T) {
	id := b64([]byte(`["acme","application","client"]`))
	d := Document{ContractVersion: 1, ID: id, Kind: "application", Revision: strings.Repeat("a", 64), Spec: json.RawMessage(`{"jwks":{"keys":[{"kty":"EC","d":"PRIVATE"}]}}`)}
	if ValidateDocument(d, id, "application") == nil {
		t.Fatal("private response accepted")
	}
}
