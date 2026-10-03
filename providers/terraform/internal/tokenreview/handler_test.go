package tokenreview

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type remoteFunc func(context.Context, string, json.RawMessage) (json.RawMessage, error)

func (f remoteFunc) TokenReview(c context.Context, a string, b json.RawMessage) (json.RawMessage, error) {
	return f(c, a, b)
}

func fixture(t *testing.T, remote Remote, wrongPin bool) (*httptest.Server, *http.Client) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned-review-test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(serial int64, use x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{use}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key, Leaf: parsed}
	}
	serverCert := leaf(2, x509.ExtKeyUsageServerAuth)
	clientCert := leaf(3, x509.ExtKeyUsageClientAuth)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	pin := sha256.Sum256(clientCert.Leaf.RawSubjectPublicKeyInfo)
	if wrongPin {
		pin[0] ^= 1
	}
	h := Handler{Remote: remote, HumanClient: "cluster-client", IdentityPrefix: "asterius:team:cluster:", ClientSPKI: pin, Admission: make(chan struct{}, 1)}
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	s.StartTLS()
	t.Cleanup(s.Close)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{clientCert}}}
	t.Cleanup(transport.CloseIdleConnections)
	return s, &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

const accepted = `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"user":{"username":"asterius:team:cluster:human","groups":["asterius:team:cluster:group:group:00000000-0000-0000-0000-000000000001"]},"audiences":["cluster-client"]}}`

func request(t *testing.T, s *httptest.Server, c *http.Client) (int, string) {
	t.Helper()
	return requestAt(t, s, c, "/review")
}

func requestAt(t *testing.T, s *httptest.Server, c *http.Client, path string) (int, string) {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, s.URL+path, strings.NewReader(`{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"must-never-echo","audiences":["cluster-client"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-Client-Cert", "spoofed")
	response, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "must-never-echo") || strings.Contains(string(body), "spoofed") {
		t.Fatal("credential or forwarded identity escaped")
	}
	return response.StatusCode, string(body)
}

func TestTokenReviewRealVerifiedTLSAndClosedResponse(t *testing.T) {
	r := remoteFunc(func(ctx context.Context, aud string, raw json.RawMessage) (json.RawMessage, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Second || aud != "cluster-client" {
			t.Error("missing total route deadline or audience pin")
		}
		return json.RawMessage(accepted), nil
	})
	s, c := fixture(t, r, false)
	status, body := request(t, s, c)
	if status != 200 || !strings.Contains(body, `"authenticated":true`) {
		t.Fatal(status, body)
	}
}
func TestTokenReviewWrongSPKIAndForeignBackendIdentityFailClosed(t *testing.T) {
	r := remoteFunc(func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(accepted), nil
	})
	s, c := fixture(t, r, true)
	status, body := request(t, s, c)
	if status != 403 || !strings.Contains(body, `"authenticated":false`) {
		t.Fatal(status, body)
	}
	for _, bad := range []string{
		strings.Replace(accepted, "cluster-client", "foreign-client", 1),
		strings.Replace(accepted, "asterius:team:cluster:human", "system:admin", 1),
		strings.Replace(accepted, `"status":`, `"spec":{"token":"must-never-echo"},"status":`, 1),
		strings.Replace(accepted, `"authenticated":true`, `"authenticated":false,"authenticated":true`, 1),
		strings.Replace(accepted, `"username":`, `"username":"system:admin","username":`, 1),
		strings.Replace(accepted, `"groups":["asterius:team:cluster:group:group:00000000-0000-0000-0000-000000000001"]`, `"groups":null`, 1),
		strings.Replace(accepted, "00000000-0000-0000-0000-000000000001", "not-a-canonical-uuid", 1),
	} {
		raw := bad
		s, c := fixture(t, remoteFunc(func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(raw), nil
		}), false)
		_, body := request(t, s, c)
		if !strings.Contains(body, `"authenticated":false`) {
			t.Fatal("accepted foreign or open response")
		}
	}
}
func TestTokenReviewTimeoutCannotReleasePositiveIdentity(t *testing.T) {
	s, c := fixture(t, remoteFunc(func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		<-ctx.Done()
		return json.RawMessage(accepted), nil
	}), false)
	started := time.Now()
	_, body := request(t, s, c)
	if time.Since(started) > 4*time.Second || !strings.Contains(body, `"authenticated":false`) {
		t.Fatal("late positive escaped total deadline")
	}
}

func TestTokenReviewKubernetesTransportQueryCannotExtendDeadline(t *testing.T) {
	for _, query := range []string{"", "?timeout=30s", "?timeout=300s", "?timeout=30s&timeout=30s", "?timeout=30s&audience=foreign", "?timeout=%33%30s"} {
		t.Run(query, func(t *testing.T) {
			called := false
			remote := remoteFunc(func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
				called = true
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 3*time.Second {
					t.Error("transport query changed local review deadline")
				}
				return json.RawMessage(accepted), nil
			})
			server, client := fixture(t, remote, false)
			status, body := requestAt(t, server, client, "/review"+query)
			allowed := query == "" || query == "?timeout=30s"
			if status != 200 || called != allowed || strings.Contains(body, `"authenticated":true`) != allowed {
				t.Fatalf("query=%q status=%d called=%t allowed=%t", query, status, called, allowed)
			}
		})
	}
}
