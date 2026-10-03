package acceptance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
)

type fixture struct {
	mu                 sync.Mutex
	server             *httptest.Server
	key                *ecdsa.PrivateKey
	keyFile, caFile    string
	docs               map[string]client.Document
	logical            map[string]string
	tokens             map[string]token
	seen               map[string]bool
	generation         uint64
	proofs, assertions int
}
type token struct {
	owner  string
	scopes map[string]bool
	thumb  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{key: key, docs: map[string]client.Document{}, logical: map[string]string{}, tokens: map[string]token{}, seen: map[string]bool{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	dir := t.TempDir()
	f.keyFile = filepath.Join(dir, "external-key.pem")
	f.caFile = filepath.Join(dir, "ca.pem")
	raw, _ := x509.MarshalPKCS8PrivateKey(key)
	if err = os.WriteFile(f.keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}
func decode(compact string, pub *ecdsa.PublicKey) (map[string]any, map[string]any, bool) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, false
	}
	hraw, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	craw, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	var h, c map[string]any
	if e1 != nil || e2 != nil || e3 != nil || len(sig) != 64 || json.Unmarshal(hraw, &h) != nil || json.Unmarshal(craw, &c) != nil {
		return nil, nil, false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return h, c, ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}
func proof(compact string) (map[string]any, string, bool) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	var h struct {
		Alg string                          `json:"alg"`
		Typ string                          `json:"typ"`
		JWK struct{ Kty, Crv, X, Y string } `json:"jwk"`
	}
	if err != nil || json.Unmarshal(raw, &h) != nil || h.Alg != "ES256" || h.Typ != "dpop+jwt" || h.JWK.Kty != "EC" || h.JWK.Crv != "P-256" {
		return nil, "", false
	}
	x, e1 := base64.RawURLEncoding.DecodeString(h.JWK.X)
	y, e2 := base64.RawURLEncoding.DecodeString(h.JWK.Y)
	if e1 != nil || e2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, "", false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, "", false
	}
	_, c, ok := decode(compact, pub)
	return c, h.JWK.X + "." + h.JWK.Y, ok
}
func refuse(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code})
}
func emit(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
func canonical(kind string, raw json.RawMessage) json.RawMessage {
	var v map[string]any
	_ = json.Unmarshal(raw, &v)
	if kind == "group" {
		if _, ok := v["display_name"]; !ok {
			v["display_name"] = nil
		}
	}
	if kind == "resource" {
		for key, value := range map[string]any{"scopes": nil, "default_token_lifetime_seconds": 300, "introspection_clients": []string{}} {
			if _, ok := v[key]; !ok {
				v[key] = value
			}
		}
	}
	out, _ := json.Marshal(v)
	return out
}
func (f *fixture) rev(d *client.Document) {
	f.generation++
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", d.ID, f.generation)))
	d.Revision = fmt.Sprintf("%x", hash)
}
func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	claims, thumb, ok := proof(r.Header.Get("DPoP"))
	if !ok || claims["htm"] != r.Method || claims["htu"] != f.server.URL+r.URL.Path {
		refuse(w, 401, "invalid_client")
		return
	}
	jti, _ := claims["jti"].(string)
	iat, _ := claims["iat"].(float64)
	if jti == "" || f.seen[jti] || time.Now().Unix()-int64(iat) > 60 {
		refuse(w, 401, "invalid_client")
		return
	}
	f.seen[jti] = true
	f.proofs++
	if strings.HasSuffix(r.URL.Path, "/token") {
		if err := r.ParseForm(); err != nil {
			refuse(w, 400, "invalid_request")
			return
		}
		_, assertion, ok := decode(r.Form.Get("client_assertion"), &f.key.PublicKey)
		clientID := r.Form.Get("client_id")
		if !ok || assertion["aud"] != f.server.URL+"/t/admin" || assertion["iss"] != clientID || assertion["sub"] != clientID || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			refuse(w, 401, "invalid_client")
			return
		}
		jti, _ := assertion["jti"].(string)
		if jti == "" || f.seen[jti] {
			refuse(w, 401, "invalid_client")
			return
		}
		f.seen[jti] = true
		f.assertions++
		allowed := map[string]bool{}
		for _, s := range client.Scopes() {
			allowed[s] = true
		}
		scopes := map[string]bool{}
		for _, s := range strings.Fields(r.Form.Get("scope")) {
			if !allowed[s] {
				refuse(w, 400, "invalid_scope")
				return
			}
			scopes[s] = true
		}
		access, _ := client.RandomID()
		owner, _ := json.Marshal([]string{"admin", clientID})
		f.tokens[access] = token{string(owner), scopes, thumb}
		emit(w, map[string]any{"access_token": access, "token_type": "DPoP", "expires_in": 60, "scope": r.Form.Get("scope")})
		return
	}
	access := strings.TrimPrefix(r.Header.Get("Authorization"), "DPoP ")
	tok, ok := f.tokens[access]
	hash := sha256.Sum256([]byte(access))
	if !ok || tok.thumb != thumb || claims["ath"] != base64.RawURLEncoding.EncodeToString(hash[:]) {
		refuse(w, 401, "invalid_client")
		return
	}
	var body struct {
		Kind        string          `json:"kind"`
		ExternalKey string          `json:"external_key"`
		Spec        json.RawMessage `json:"spec"`
		Protection  bool            `json:"deletion_protection"`
	}
	if r.Method != "GET" && r.Method != "DELETE" && r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	base := "/admin/api/v1/declarative/v1/resources"
	idx := strings.Index(r.URL.Path, base)
	if idx < 0 {
		refuse(w, 404, "not_found")
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path[idx+len(base):], "/")
	segments := strings.Split(suffix, "/")
	id := segments[0]
	kind := body.Kind
	var d client.Document
	if id != "" {
		d, ok = f.docs[id]
		if !ok {
			refuse(w, 404, "not_found")
			return
		}
		kind = d.Kind
	}
	prefix := map[string]string{"tenant": "tenants", "application": "clients", "resource": "resource_servers", "group": "groups", "membership": "memberships", "policy": "policies"}[kind]
	writing := r.Method != "GET" && !(len(segments) > 1 && segments[1] == "plan")
	if !tok.scopes["admin.session:read"] || !tok.scopes["admin."+prefix+":read"] || (writing && !tok.scopes["admin."+prefix+":write"]) {
		refuse(w, 403, "forbidden")
		return
	}
	if id == "" && r.Method == "POST" {
		logical := tok.owner + "/" + kind + "/" + body.ExternalKey
		if prior, ok := f.logical[logical]; ok {
			old, live := f.docs[prior]
			if !live {
				refuse(w, 409, "logical_key_conflict")
				return
			}
			emit(w, old)
			return
		}
		var spec map[string]any
		if json.Unmarshal(body.Spec, &spec) != nil || client.PublicSpec(body.Spec) != nil {
			refuse(w, 400, "invalid_request")
			return
		}
		tenant := "admin"
		key := "policy"
		switch kind {
		case "tenant":
			tenant, _ = spec["tenant_id"].(string)
			key = tenant
		case "resource":
			key, _ = spec["identifier"].(string)
		case "application":
			key, _ = client.RandomID()
		case "group":
			var b [16]byte
			_, _ = rand.Read(b[:])
			key = fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
		case "membership":
			key, _ = spec["group_id"].(string)
		}
		parts := []string{tenant, kind, key}
		if kind == "membership" {
			user, _ := spec["user_id"].(string)
			parts = append(parts, user)
		}
		encoded, _ := json.Marshal(parts)
		id = base64.RawURLEncoding.EncodeToString(encoded)
		if _, exists := f.docs[id]; exists {
			refuse(w, 409, "logical_key_conflict")
			return
		}
		d = client.Document{ContractVersion: 1, ID: id, Kind: kind, Spec: canonical(kind, body.Spec), Owner: &tok.owner, Origin: []json.RawMessage{}, DeletionProtection: body.Protection}
		f.rev(&d)
		f.docs[id] = d
		f.logical[logical] = id
		emit(w, d)
		return
	}
	if r.Method == "GET" {
		w.Header().Set("ETag", "\""+d.Revision+"\"")
		emit(w, d)
		return
	}
	if r.Header.Get("If-Match") != "\""+d.Revision+"\"" {
		refuse(w, 412, "revision_conflict")
		return
	}
	action := ""
	if len(segments) > 1 {
		action = segments[1]
	}
	if action == "plan" {
		spec := canonical(kind, body.Spec)
		emit(w, map[string]any{"contract_version": 1, "id": id, "revision": d.Revision, "spec": spec, "changed": !reflect.DeepEqual(d.Spec, spec), "owner_conflict": d.Owner != nil && *d.Owner != tok.owner})
		return
	}
	if d.Owner != nil && *d.Owner != tok.owner {
		refuse(w, 409, "owner_conflict")
		return
	}
	switch {
	case action == "adopt":
		d.Owner = &tok.owner
	case action == "release":
		d.Owner = nil
	case r.Method == "PUT":
		if d.Owner == nil {
			refuse(w, 409, "owner_conflict")
			return
		}
		d.Spec = canonical(kind, body.Spec)
		d.DeletionProtection = body.Protection
	case r.Method == "DELETE":
		if d.DeletionProtection || kind == "tenant" {
			refuse(w, 409, "delete_protected")
			return
		}
		delete(f.docs, id)
		emit(w, map[string]any{"deleted": true})
		return
	default:
		refuse(w, 400, "invalid_request")
		return
	}
	f.rev(&d)
	f.docs[id] = d
	emit(w, d)
}
func (f *fixture) drift(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.docs[id]
	var spec map[string]any
	_ = json.Unmarshal(d.Spec, &spec)
	spec["display_name"] = "Console drift"
	d.Spec, _ = json.Marshal(spec)
	f.rev(&d)
	f.docs[id] = d
}
