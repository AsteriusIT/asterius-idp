package main

import (
	"context"
	"fmt"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/operator"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	cfg := operator.Config{Namespace: os.Getenv("ASTERIUS_NAMESPACE"), Tenant: os.Getenv("ASTERIUS_TENANT"), Issuer: os.Getenv("ASTERIUS_ISSUER"), ClientID: os.Getenv("ASTERIUS_CLIENT_ID"), BindingUID: os.Getenv("ASTERIUS_BINDING_UID"), ClusterID: os.Getenv("ASTERIUS_CLUSTER_ID"), KeyID: os.Getenv("ASTERIUS_KEY_ID"), Holder: os.Getenv("ASTERIUS_HOLDER"), SecretNames: strings.Split(os.Getenv("ASTERIUS_SECRET_NAMES"), ","), Interval: 2 * time.Second}
	base := os.Getenv("KUBERNETES_API_URL")
	if base == "" {
		base = "https://kubernetes.default.svc"
	}
	token := os.Getenv("KUBERNETES_TOKEN_FILE")
	if token == "" {
		token = "/var/run/asterius-kubernetes/token"
	}
	ca := os.Getenv("KUBERNETES_CA_FILE")
	if ca == "" {
		ca = "/var/run/asterius-kubernetes/ca.crt"
	}
	kube, err := operator.NewKube(base, token, ca, cfg.Namespace)
	if err != nil {
		fmt.Fprintln(os.Stderr, "controller configuration refused")
		os.Exit(1)
	}
	service := operator.Service{Config: cfg, Kube: kube}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := service.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "controller configuration or operation refused")
		os.Exit(1)
	}
}
