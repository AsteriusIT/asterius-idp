// Disposable interoperability check against the target Kubernetes 1.35 authenticator.
// Reads synthetic public fixtures; performs no discovery or cluster mutations.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	jose "gopkg.in/go-jose/go-jose.v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/apis/apiserver/install"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	"k8s.io/apiserver/pkg/authentication/cel"
	oidc "k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

type fixtures struct {
	JWKS   jose.JSONWebKeySet `json:"jwks"`
	Tokens map[string]string  `json:"tokens"`
}

// Signature verification uses the same JOSE dependency as Kubernetes' verifier.
// Only the fixture's public keys are loaded; no bypass returns unverified claims.
type fixtureKeys struct{ keys jose.JSONWebKeySet }

func (k fixtureKeys) VerifySignature(_ context.Context, token string) ([]byte, error) {
	signed, err := jose.ParseSigned(token)
	if err != nil {
		return nil, err
	}
	for _, key := range k.keys.Keys {
		if payload, err := signed.Verify(key.Key); err == nil {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("fixture signature did not verify")
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: go run . <authentication.json> <synthetic-fixtures.json>")
	}
	configBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	fixtureBytes, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	var fixture fixtures
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	install.Install(scheme)
	obj, _, err := serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder().Decode(configBytes, nil, nil)
	if err != nil {
		return err
	}
	config, ok := obj.(*apiserver.AuthenticationConfiguration)
	if !ok || len(config.JWT) != 1 {
		return fmt.Errorf("expected one strict AuthenticationConfiguration authenticator")
	}
	if problems := validation.ValidateAuthenticationConfiguration(cel.NewDefaultCompiler(), config, nil); len(problems) != 0 {
		return problems.ToAggregate()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newAuthenticator := func(spec apiserver.JWTAuthenticator) (oidc.AuthenticatorTokenWithHealthCheck, error) {
		return oidc.New(ctx, oidc.Options{JWTAuthenticator: spec, KeySet: fixtureKeys{fixture.JWKS}, SupportedSigningAlgs: []string{"ES256"}})
	}
	a, err := newAuthenticator(config.JWT[0])
	if err != nil {
		return err
	}
	response, authenticated, err := a.AuthenticateToken(ctx, fixture.Tokens["valid"])
	if err != nil || !authenticated {
		return fmt.Errorf("valid Asterius ES256 fixture rejected: %v", err)
	}
	if response.User.GetName() != "asterius:demo:cluster-a:fictional-user" {
		return fmt.Errorf("unexpected username mapping")
	}
	groups := response.User.GetGroups()
	if len(groups) != 1 || groups[0] != "asterius:demo:cluster-a:group:group:00000000-0000-0000-0000-000000000001" {
		return fmt.Errorf("unexpected group mapping")
	}
	for _, name := range []string{"wrong_audience", "wrong_issuer", "expired", "excessive_lifetime", "multiple_audiences", "unsupported_algorithm", "tampered"} {
		if _, authenticated, _ := a.AuthenticateToken(ctx, fixture.Tokens[name]); authenticated {
			return fmt.Errorf("negative fixture %s authenticated", name)
		}
	}
	withoutGroups, authenticated, err := a.AuthenticateToken(ctx, fixture.Tokens["absent_groups"])
	if err != nil || !authenticated || len(withoutGroups.User.GetGroups()) != 0 {
		return fmt.Errorf("absent groups did not produce unprivileged identity: %v", err)
	}
	bSpec := config.JWT[0].DeepCopy()
	bSpec.Issuer.Audiences = []string{"cluster-b-client"}
	b, err := newAuthenticator(*bSpec)
	if err != nil {
		return err
	}
	if _, authenticated, _ := b.AuthenticateToken(ctx, fixture.Tokens["valid"]); authenticated {
		return fmt.Errorf("Cluster A token authenticated at Cluster B")
	}
	fmt.Println("Kubernetes v1.35.0: strict generated config and CEL validated; Asterius ES256 signature/user/group accepted; seven negative fixtures, absent groups and cross-cluster rejection passed")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
