// Disposable composition; pinned SSFgo owns SSF parsing, storage and signing.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

func run() error {
	issuer := flag.String("issuer", "", "exact approved public HTTPS issuer")
	audience := flag.String("audience", "", "operator-pinned Asterius receiver audience")
	bind := flag.String("bind", "127.0.0.1:9485", "loopback listener behind approved HTTPS proxy")
	control := flag.String("control", "127.0.0.1:9486", "loopback-only test event control listener")
	bearer := flag.String("bearer-file", "", "private management bearer file")
	delivery := flag.String("delivery", "poll", "poll or push; native SSFgo delivery worker")
	endpoint := flag.String("push-endpoint", "", "exact allowed public HTTPS push receiver")
	flag.Parse()
	if *delivery != "poll" && *delivery != "push" {
		return fmt.Errorf("invalid delivery mode")
	}
	if *delivery == "push" {
		u, err := url.Parse(*endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("exact HTTPS push endpoint required")
		}
	}
	if *issuer == "" || *audience == "" {
		return fmt.Errorf("issuer and audience required")
	}
	for _, addr := range []string{*bind, *control} {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			return fmt.Errorf("listeners require literal loopback addresses")
		}
	}
	info, err := os.Stat(*bearer)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("credential requires private regular file")
	}
	if info.Size() > 8192 {
		return fmt.Errorf("credential exceeds bound")
	}
	credential, err := os.ReadFile(*bearer)
	if err != nil {
		return fmt.Errorf("credential unavailable")
	}
	token := strings.TrimSuffix(string(credential), "\n")
	if len(token) < 32 || strings.ContainsAny(token, " \r\n\t") {
		return fmt.Errorf("invalid test credential")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("signing key unavailable")
	}
	var receiptMu sync.Mutex
	receipts := []map[string]any{}
	methods := []ssf.DeliveryMethod{ssf.DeliveryPoll}
	if *delivery == "push" {
		methods = []ssf.DeliveryMethod{ssf.DeliveryPush}
	}
	tx, err := transmitter.New(transmitter.Config{
		Issuer: *issuer, Assurance: ssf.AssuranceDevelopment,
		SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.ES256, KeyID: "owned-disposable-ssfgo-key"}},
		EventsSupported: []ssf.EventType{caep.SessionRevokedEventType, caep.CredentialChangeEventType},
		DeliveryMethods: methods, DefaultSubjects: ssf.DefaultSubjectsAll,
		Store: memstore.NewStreamStore(), Limits: transmitter.RecommendedLimits(), PermitEvent: transmitter.PermitAll,
		MultipleStreamsPerReceiver: true,
		PushRetry:                  transmitter.RecommendedPushRetry(),
		AllowPushEndpoint: func(_ transmitter.Receiver, u *url.URL) error {
			if u.String() != *endpoint {
				return fmt.Errorf("unapproved fixture endpoint")
			}
			return nil
		},
		Hooks: transmitter.Hooks{Push: func(_ context.Context, info transmitter.PushInfo) {
			receiptMu.Lock()
			defer receiptMu.Unlock()
			if len(receipts) < 100 {
				receipts = append(receipts, map[string]any{"outcome": info.Outcome.String(), "attempt": info.Attempt})
			}
		}},
		Authorize: func(_ context.Context, presented string) (transmitter.Receiver, error) {
			if subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
				return transmitter.Receiver{}, transmitter.ErrInvalidToken
			}
			return transmitter.Receiver{ID: "owned-asterius-receiver", Audience: []string{*audience}, Access: transmitter.AccessManage}, nil
		},
	})
	if err != nil {
		return fmt.Errorf("transmitter configuration refused: %w", err)
	}
	controls := http.NewServeMux()
	controls.HandleFunc("POST /emit-session-revoked", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			w.WriteHeader(401)
			return
		}
		var body struct {
			Subject string `json:"subject"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil || body.Subject == "" || len(body.Subject) > 256 {
			w.WriteHeader(400)
			return
		}
		event := caep.SessionRevoked{Common: caep.Common{EventTimestamp: ssf.NewNumericDate(time.Now())}}
		if err := tx.Emit(r.Context(), ssf.IssSubSubject{Issuer: *issuer, Subject: body.Subject}, event); err != nil {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(204)
	})
	controls.HandleFunc("GET /delivery-receipts", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			w.WriteHeader(401)
			return
		}
		receiptMu.Lock()
		defer receiptMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipts)
	})
	failures := make(chan error, 3)
	if *delivery == "push" {
		go func() { failures <- tx.Run(context.Background()) }()
	}
	for _, server := range []*http.Server{
		{Addr: *bind, Handler: tx.Handler(), ReadHeaderTimeout: 5 * time.Second},
		{Addr: *control, Handler: controls, ReadHeaderTimeout: 5 * time.Second},
	} {
		go func(s *http.Server) { failures <- s.ListenAndServe() }(server)
	}
	// Tokens, subjects, request bodies and SETs never enter these logs.
	log.Print("disposable independent SSFgo ES256 transmitter ready")
	return <-failures
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
