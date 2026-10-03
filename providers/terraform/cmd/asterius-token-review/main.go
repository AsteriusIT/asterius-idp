// asterius-token-review is a candidate stateless, mutually authenticated adapter.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/tokenreview"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:9448", "HTTPS listen address")
	issuer := flag.String("issuer", "", "Exact Asterius tenant HTTPS issuer")
	human := flag.String("human-client", "", "Selected cluster human client")
	reviewer := flag.String("reviewer-client", "", "Distinct confidential reviewer client")
	key := flag.String("reviewer-key", "", "Operator-owned ES256 PKCS8 signing key")
	kid := flag.String("reviewer-kid", "", "Registered reviewer signing key ID")
	issuerCA := flag.String("issuer-ca", "", "Optional issuer CA bundle")
	cert := flag.String("server-cert", "", "Adapter HTTPS server certificate")
	serverKey := flag.String("server-key", "", "Adapter HTTPS private key")
	apiCA := flag.String("apiserver-ca", "", "Dedicated API-server client CA bundle")
	apiPin := flag.String("apiserver-spki-sha256", "", "Exact lowercase client SPKI SHA256")
	prefix := flag.String("identity-prefix", "", "Reviewed asterius:tenant:cluster: prefix")
	flag.Parse()
	if *human == "" || *human == *reviewer || *cert == "" || *serverKey == "" || !strings.HasPrefix(*prefix, "asterius:") || !strings.HasSuffix(*prefix, ":") {
		return errors.New("exact distinct cluster/reviewer and verified TLS configuration required")
	}
	pin, err := hex.DecodeString(*apiPin)
	if err != nil || len(pin) != 32 || hex.EncodeToString(pin) != *apiPin {
		return errors.New("canonical API-server SPKI pin required")
	}
	rootBytes, err := os.ReadFile(*apiCA)
	if err != nil || len(rootBytes) == 0 || len(rootBytes) > 1048576 {
		return errors.New("bounded dedicated API-server CA bundle required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootBytes) {
		return errors.New("invalid dedicated API-server CA bundle")
	}
	remote, err := client.New(client.Config{Issuer: *issuer, ClientID: *reviewer, KeyFile: *key, KeyID: *kid,
		CAFile: *issuerCA, Resource: strings.TrimRight(*issuer, "/") + "/admin/api/v1",
		Scopes: []string{"admin.kubernetes_reviews:read"}, Timeout: 3 * time.Second})
	if err != nil {
		return err
	}
	var digest [32]byte
	copy(digest[:], pin)
	handler := tokenreview.Handler{Remote: remote, HumanClient: *human, IdentityPrefix: *prefix,
		ClientSPKI: digest, Admission: make(chan struct{}, 1)}
	server := &http.Server{Addr: *listen, Handler: handler,
		ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 4 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots},
		ErrorLog:  log.New(io.Discard, "", 0)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServeTLS(*cert, *serverKey) }()
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("adapter HTTPS listener unavailable")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
