// Package tokenreview implements the candidate stateless API-server adapter.
// Its HTTPS listener must require and verify the dedicated API-server client CA.
package tokenreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

const version = "authentication.k8s.io/v1"
const kind = "TokenReview"
const denied = `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":false}}`

type Remote interface {
	TokenReview(context.Context, string, json.RawMessage) (json.RawMessage, error)
}

type Handler struct {
	Remote                      Remote
	HumanClient, IdentityPrefix string
	ClientSPKI                  [32]byte
	// This semaphore is required: the underlying FAPI client serializes nonce
	// handling. Admission must expire with the request, not wait on its mutex.
	Admission chan struct{}
}

type User struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}
type Status struct {
	Authenticated bool     `json:"authenticated"`
	User          *User    `json:"user,omitempty"`
	Audiences     []string `json:"audiences,omitempty"`
}
type Response struct {
	Version string `json:"apiVersion"`
	Kind    string `json:"kind"`
	Status  Status `json:"status"`
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	deadline := time.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, denied)
		return
	}
	spki := sha256.Sum256(r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(spki[:], h.ClientSPKI[:]) != 1 {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, denied)
		return
	}
	reject := func() { _, _ = io.WriteString(w, denied) }
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != http.MethodPost || r.URL.Path != "/review" || r.URL.RawQuery != "" || media != "application/json" || err != nil || h.Remote == nil || h.Admission == nil {
		reject()
		return
	}
	// The listener also sets ReadTimeout. This bounds a slow authenticated peer
	// even when the context itself cannot interrupt the request body reader.
	if http.NewResponseController(w).SetReadDeadline(deadline) != nil {
		reject()
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if err != nil || !json.Valid(raw) {
		reject()
		return
	}
	select {
	case h.Admission <- struct{}{}:
		defer func() { <-h.Admission }()
	case <-ctx.Done():
		reject()
		return
	}
	response, err := h.Remote.TokenReview(ctx, h.HumanClient, json.RawMessage(raw))
	if err != nil || ctx.Err() != nil || len(response) > 65536 {
		reject()
		return
	}
	var output Response
	d := json.NewDecoder(bytes.NewReader(response))
	d.DisallowUnknownFields()
	if d.Decode(&output) != nil || d.Decode(new(any)) != io.EOF || output.Version != version || output.Kind != kind {
		reject()
		return
	}
	status := output.Status
	if !status.Authenticated {
		reject()
		return
	}
	if len(status.Audiences) != 1 || status.Audiences[0] != h.HumanClient || status.User == nil || !safe(status.User.Username, h.IdentityPrefix) || len(status.User.Groups) > 100 {
		reject()
		return
	}
	seen := map[string]bool{}
	for _, group := range status.User.Groups {
		if !safe(group, h.IdentityPrefix+"group:") || seen[group] {
			reject()
			return
		}
		seen[group] = true
	}
	// Re-serialize only the closed validated output, never the incoming request.
	if ctx.Err() != nil {
		reject()
		return
	}
	_ = json.NewEncoder(w).Encode(output)
}

func safe(value, prefix string) bool {
	if prefix == "" || !strings.HasPrefix(prefix, "asterius:") || !strings.HasPrefix(value, prefix) || len(value) <= len(prefix) || len(value) > 2048 {
		return false
	}
	for _, r := range value {
		if r < 32 || (r >= 127 && r <= 159) {
			return false
		}
	}
	return true
}
