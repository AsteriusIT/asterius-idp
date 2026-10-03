package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/jitrbac"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/operator"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "one controller configuration path required")
		os.Exit(1)
	}
	input, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "controller configuration unavailable")
		os.Exit(1)
	}
	info, err := input.Stat()
	if err != nil || info.Size() > 65536 {
		input.Close()
		fmt.Fprintln(os.Stderr, "controller configuration exceeds bound")
		os.Exit(1)
	}
	var cfg struct {
		Controller                                                                           jitrbac.Config
		Issuer, KeyFile, KeyID, CAFile, KubernetesURL, KubernetesTokenFile, KubernetesCAFile string
	}
	d := json.NewDecoder(io.LimitReader(input, 65537))
	d.DisallowUnknownFields()
	err = d.Decode(&cfg)
	var trailing any
	if err == nil && d.Decode(&trailing) != io.EOF {
		err = fmt.Errorf("trailing configuration data")
	}
	input.Close()
	if err != nil || cfg.Controller.Validate() != nil {
		fmt.Fprintln(os.Stderr, "controller configuration refused")
		os.Exit(1)
	}
	remote, err := client.New(client.Config{Issuer: cfg.Issuer, ClientID: cfg.Controller.ControllerClient, KeyFile: cfg.KeyFile, KeyID: cfg.KeyID, CAFile: cfg.CAFile, Scopes: []string{"admin.app_roles:read"}, Resource: cfg.Issuer + "/admin/api/v1", Timeout: cfg.Controller.Interval})
	if err != nil {
		fmt.Fprintln(os.Stderr, "controller authentication configuration refused")
		os.Exit(1)
	}
	kube, err := operator.NewKube(cfg.KubernetesURL, cfg.KubernetesTokenFile, cfg.KubernetesCAFile, cfg.Controller.Namespace)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Kubernetes configuration refused")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	service := jitrbac.Service{Config: cfg.Controller, Remote: remote, Kube: kube, Report: func(error) { fmt.Fprintln(os.Stderr, "temporary RBAC reconciliation refused; failclosed retry") }}
	// Clearing reduces healthy revocation latency. Signed JIT identity expiry
	// independently bounds stale-binding access during a crash or outage.
	if err = service.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "temporary RBAC shutdown/configuration refused")
		os.Exit(1)
	}
}
