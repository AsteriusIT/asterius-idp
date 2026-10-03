// Package client implements the bounded public declarative API and FAPI service authentication.
package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var kinds = map[string]string{"tenant": "tenants", "application": "clients", "resource": "resource_servers", "group": "groups", "membership": "memberships", "policy": "policies"}

func ValidKind(k string) bool { _, ok := kinds[k]; return ok }
func Scopes() []string {
	out := []string{"admin.session:read"}
	for _, k := range []string{"tenants", "clients", "resource_servers", "groups", "memberships", "policies"} {
		out = append(out, "admin."+k+":read", "admin."+k+":write")
	}
	return out
}

type Config struct {
	Issuer, ClientID, KeyFile, KeyID, CAFile, Resource, TargetTenant, IssuingTenant, TargetIssuer string
	Scopes                                                                                        []string
	Timeout                                                                                       time.Duration
	// Operator Secret material stays in memory; provider file configuration remains unchanged.
	KeyMaterial, DPoPMaterial, CAMaterial []byte
}
type Client struct {
	cfg       Config
	http      *http.Client
	key, dpop *ecdsa.PrivateKey
	mu        sync.Mutex
	token     string
	expiry    time.Time
	nonces    map[string]string
}
type Document struct {
	ContractVersion    int               `json:"contract_version"`
	ID                 string            `json:"id"`
	Kind               string            `json:"kind"`
	Spec               json.RawMessage   `json:"spec"`
	Revision           string            `json:"revision"`
	Owner              *string           `json:"owner"`
	Origin             []json.RawMessage `json:"origin"`
	DeletionProtection bool              `json:"deletion_protection"`
}
type Plan struct {
	Changed, OwnerConflict bool
	Spec                   json.RawMessage
}
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("management request refused (HTTP %d, %s); refresh and replan before resolving conflicts", e.Status, e.Code)
}
func IsNotFound(err error) bool { var e *APIError; return errors.As(err, &e) && e.Status == 404 }

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("issuer must be an absolute HTTPS URL without credentials, query or fragment")
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.IssuingTenant == "" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) >= 2 && parts[len(parts)-2] == "t" {
			cfg.IssuingTenant = parts[len(parts)-1]
		}
	}
	if !tenantPattern.MatchString(cfg.IssuingTenant) {
		return nil, errors.New("issuing_tenant is required when issuer does not end in /t/tenant")
	}
	if cfg.TargetIssuer != "" {
		target, err := url.Parse(cfg.TargetIssuer)
		if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || cfg.TargetTenant == "" {
			return nil, errors.New("target_issuer requires target_tenant and an absolute HTTPS URL")
		}
		cfg.TargetIssuer = strings.TrimRight(cfg.TargetIssuer, "/")
	}

	if cfg.TargetTenant != "" && !tenantPattern.MatchString(cfg.TargetTenant) {
		return nil, errors.New("invalid target tenant")
	}
	if cfg.ClientID == "" || cfg.KeyID == "" {
		return nil, errors.New("client_id and key_id are required")
	}
	raw := cfg.KeyMaterial
	if len(raw) == 0 {
		raw, err = os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, errors.New("cannot read external signing key")
		}
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("external signing key must be a single PKCS8 PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid external signing key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("external signing key must be ES256 (P-256)")
	}
	dpop, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("cannot initialize proof key")
	}
	if len(cfg.DPoPMaterial) > 0 {
		proofBlock, remaining := pem.Decode(cfg.DPoPMaterial)
		if proofBlock == nil || proofBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(remaining)) != 0 {
			return nil, errors.New("proof key must be a single PKCS8 PEM private key")
		}
		parsedProof, parseErr := x509.ParsePKCS8PrivateKey(proofBlock.Bytes)
		if parseErr != nil {
			return nil, errors.New("invalid proof key")
		}
		var valid bool
		dpop, valid = parsedProof.(*ecdsa.PrivateKey)
		if !valid || dpop.Curve != elliptic.P256() {
			return nil, errors.New("proof key must be ES256 (P-256)")
		}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		raw, err = os.ReadFile(cfg.CAFile)
		if err != nil || !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("cannot load CA bundle")
		}
	}
	if len(cfg.CAMaterial) > 0 && !roots.AppendCertsFromPEM(cfg.CAMaterial) {
		return nil, errors.New("cannot load CA bundle")
	}
	// Parsed keys and certificate pools are the only retained credential material.
	cfg.KeyMaterial, cfg.DPoPMaterial, cfg.CAMaterial = nil, nil, nil
	if cfg.Timeout <= 0 || cfg.Timeout > 10*time.Minute {
		return nil, errors.New("request timeout must be greater than zero and at most ten minutes")
	}
	for _, scope := range cfg.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return nil, errors.New("invalid scope")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &Client{cfg: cfg, key: key, dpop: dpop, nonces: map[string]string{}, http: &http.Client{Transport: transport, Timeout: cfg.Timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("credential redirects are refused") }}}, nil
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func RandomID() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("cannot generate logical identity")
	}
	return b64(b[:]), nil
}
func SignJWT(key *ecdsa.PrivateKey, header, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", errors.New("signature failed")
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + b64(signature), nil
}
func PublicJWK(key *ecdsa.PrivateKey) map[string]any {
	return map[string]any{"kty": "EC", "crv": "P-256", "x": b64(key.X.FillBytes(make([]byte, 32))), "y": b64(key.Y.FillBytes(make([]byte, 32)))}
}
func (c *Client) proof(method, target, token, nonce string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", errors.New("invalid target")
	}
	u.RawQuery = ""
	u.Fragment = ""
	id, err := RandomID()
	if err != nil {
		return "", err
	}
	claims := map[string]any{"htm": method, "htu": u.String(), "iat": time.Now().Unix(), "jti": id}
	if token != "" {
		hash := sha256.Sum256([]byte(token))
		claims["ath"] = b64(hash[:])
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return SignJWT(c.dpop, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": PublicJWK(c.dpop)}, claims)
}
func (c *Client) fetchToken(ctx context.Context) error {
	target := c.cfg.Issuer + "/token"
	for attempt := 0; attempt < 2; attempt++ {
		id, err := RandomID()
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		assertion, err := SignJWT(c.key, map[string]any{"alg": "ES256", "typ": "JWT", "kid": c.cfg.KeyID}, map[string]any{"iss": c.cfg.ClientID, "sub": c.cfg.ClientID, "aud": c.cfg.Issuer, "iat": now, "exp": now + 60, "jti": id})
		if err != nil {
			return err
		}
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.ClientID}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}, "scope": {strings.Join(c.cfg.Scopes, " ")}}
		if c.cfg.Resource != "" {
			form.Set("resource", c.cfg.Resource)
		}
		req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(form.Encode()))
		if err != nil {
			return errors.New("cannot construct token request")
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		proof, err := c.proof("POST", target, "", c.nonces["token"])
		if err != nil {
			return err
		}
		req.Header.Set("DPoP", proof)
		res, err := c.http.Do(req)
		if err != nil {
			return errors.New("token request failed")
		}
		raw, err := boundedBody(res)
		if err != nil {
			return err
		}
		if nonce := res.Header.Get("DPoP-Nonce"); nonce != "" {
			c.nonces["token"] = nonce
			if res.StatusCode == 400 || res.StatusCode == 401 {
				continue
			}
		}
		if res.StatusCode != 200 {
			return apiError(res.StatusCode, raw)
		}
		var tok struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Scope       string `json:"scope"`
		}
		if json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" || !strings.EqualFold(tok.TokenType, "DPoP") || tok.ExpiresIn <= 0 || tok.ExpiresIn > 86400 {
			return errors.New("token response is not a bounded DPoP credential")
		}
		if tok.Scope != "" {
			granted := map[string]bool{}
			for _, s := range strings.Fields(tok.Scope) {
				granted[s] = true
			}
			for _, s := range c.cfg.Scopes {
				if !granted[s] {
					return errors.New("token response omitted a requested scope")
				}
			}
		}
		c.token = tok.AccessToken
		c.expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
		return nil
	}
	return errors.New("token nonce challenge did not converge")
}
func boundedBody(res *http.Response) ([]byte, error) {
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errors.New("invalid or oversized response")
	}
	return raw, nil
}
func apiError(status int, raw []byte) error {
	var wire struct {
		Code  string          `json:"code"`
		Error json.RawMessage `json:"error"`
	}
	_ = json.Unmarshal(raw, &wire)
	code := wire.Code
	if code == "" && len(wire.Error) > 0 {
		if json.Unmarshal(wire.Error, &code) != nil {
			var nested struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(wire.Error, &nested)
			code = nested.Code
		}
	}
	switch code {
	case "invalid_request", "not_found", "forbidden", "revision_conflict", "owner_conflict", "delete_protected", "dependency_conflict", "logical_key_conflict", "precondition_required", "unavailable", "use_dpop_nonce", "invalid_client", "invalid_scope", "invalid_token":
	default:
		code = "request_refused"
	}
	return &APIError{status, code}
}

func (c *Client) request(ctx context.Context, method, target, revision string, body any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, err := json.Marshal(body)
	if err != nil {
		return errors.New("invalid request")
	}
	if len(raw) > 65536 {
		return errors.New("specification exceeds 64 KiB")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if c.token == "" || time.Until(c.expiry) < 5*time.Second {
			if err = c.fetchToken(ctx); err != nil {
				return err
			}
		}
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, reader)
		if err != nil {
			return errors.New("cannot construct management request")
		}
		req.Header.Set("Authorization", "DPoP "+c.token)
		req.Header.Set("Content-Type", "application/json")
		if revision != "" {
			req.Header.Set("If-Match", "\""+revision+"\"")
		}
		proof, err := c.proof(method, target, c.token, c.nonces["management"])
		if err != nil {
			return err
		}
		req.Header.Set("DPoP", proof)
		res, err := c.http.Do(req)
		if err != nil {
			return errors.New("management request failed; preserve the logical key and refresh before retry")
		}
		response, err := boundedBody(res)
		if err != nil {
			return err
		}
		nonce := res.Header.Get("DPoP-Nonce")
		if nonce != "" {
			c.nonces["management"] = nonce
		}
		if res.StatusCode == 401 {
			if nonce == "" {
				c.token = ""
			}
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return apiError(res.StatusCode, response)
		}
		if out != nil && json.Unmarshal(response, out) != nil {
			return errors.New("invalid management response")
		}
		return nil
	}
	return errors.New("management authentication challenge did not converge")
}

func (c *Client) base(tenant string) (string, error) {
	if c.cfg.TargetIssuer != "" && tenant == c.cfg.TargetTenant {
		return c.cfg.TargetIssuer + "/admin/api/v1/declarative/v1/resources", nil
	}
	if tenant == c.cfg.IssuingTenant {
		return c.cfg.Issuer + "/admin/api/v1/declarative/v1/resources", nil
	}
	u, _ := url.Parse(c.cfg.Issuer)
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[len(parts)-2] != "t" {
		return "", errors.New("target_issuer and target_tenant are required to address this imported tenant")
	}
	parts[len(parts)-1] = tenant
	u.Path = "/" + strings.Join(parts, "/")
	return strings.TrimRight(u.String(), "/") + "/admin/api/v1/declarative/v1/resources", nil
}

func (c *Client) Read(ctx context.Context, id string) (Document, error) {
	parts, err := ParseID(id)
	if err != nil {
		return Document{}, err
	}
	base, err := c.base(parts[0])
	if err != nil {
		return Document{}, err
	}
	var d Document
	err = c.request(ctx, "GET", base+"/"+id, "", nil, &d)
	if err == nil {
		err = ValidateDocument(d, id, parts[1])
	}
	return d, err
}
func (c *Client) Create(ctx context.Context, kind, key string, spec json.RawMessage, protection bool) (Document, error) {
	routed := c.cfg.IssuingTenant
	if c.cfg.TargetTenant != "" {
		routed = c.cfg.TargetTenant
	}
	base, err := c.base(routed)
	if err != nil {
		return Document{}, err
	}
	var d Document
	err = c.request(ctx, "POST", base, "", map[string]any{"kind": kind, "external_key": key, "spec": spec, "deletion_protection": protection}, &d)
	if err == nil {
		err = ValidateDocument(d, d.ID, kind)
	}
	return d, err
}

// Lookup recovers a committed creation whose response/status write was lost.
// The authenticated owner's exact external key is the only lookup authority.
func (c *Client) Lookup(ctx context.Context, kind, key string) (Document, error) {
	base, err := c.base(c.cfg.IssuingTenant)
	if err != nil {
		return Document{}, err
	}
	query := url.Values{"kind": {kind}, "external_key": {key}}
	var d Document
	err = c.request(ctx, "GET", base+"?"+query.Encode(), "", nil, &d)
	if err == nil {
		err = ValidateDocument(d, d.ID, kind)
	}
	return d, err
}
func (c *Client) Mutate(ctx context.Context, method, id, action, revision string, body any) (Document, error) {
	parts, err := ParseID(id)
	if err != nil {
		return Document{}, err
	}
	base, err := c.base(parts[0])
	if err != nil {
		return Document{}, err
	}
	var d Document
	var out any = &d
	if method == "DELETE" {
		out = nil
	}
	err = c.request(ctx, method, base+"/"+id+action, revision, body, out)
	if err == nil && method != "DELETE" {
		err = ValidateDocument(d, id, parts[1])
	}
	return d, err
}
func (c *Client) Plan(ctx context.Context, d Document, spec json.RawMessage) (Plan, error) {
	parts, err := ParseID(d.ID)
	if err != nil {
		return Plan{}, err
	}
	base, err := c.base(parts[0])
	if err != nil {
		return Plan{}, err
	}
	var wire struct {
		Changed         bool            `json:"changed"`
		OwnerConflict   bool            `json:"owner_conflict"`
		Spec            json.RawMessage `json:"spec"`
		Revision        string          `json:"revision"`
		ContractVersion int             `json:"contract_version"`
		ID              string          `json:"id"`
	}
	err = c.request(ctx, "POST", base+"/"+d.ID+"/plan", d.Revision, map[string]any{"spec": spec}, &wire)
	if err == nil && (wire.ContractVersion != 1 || wire.ID != d.ID || wire.Revision != d.Revision || !json.Valid(wire.Spec)) {
		err = errors.New("invalid planning response")
	}
	if err == nil {
		err = PublicSpec(wire.Spec)
	}
	return Plan{wire.Changed, wire.OwnerConflict, wire.Spec}, err
}
func (c *Client) Owner() string {
	raw, _ := json.Marshal([]string{c.cfg.IssuingTenant, c.cfg.ClientID})
	return string(raw)
}
