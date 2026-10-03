package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
	"io"
	"net/url"
	"strings"
)

type Common struct {
	TenantRef          string `json:"tenantRef"`
	DeletionPolicy     string `json:"deletionPolicy"`
	DeletionProtection *bool  `json:"deletionProtection"`
	ImportID           string `json:"importId,omitempty"`
	AdoptionPolicy     string `json:"adoptionPolicy"`
}

func (c Common) protected() bool { return c.DeletionProtection == nil || *c.DeletionProtection }
func (c Common) check(tenant, kind string) error {
	if c.TenantRef != "default" || (c.DeletionPolicy != "" && c.DeletionPolicy != "Retain" && c.DeletionPolicy != "Delete") || (c.AdoptionPolicy != "" && c.AdoptionPolicy != "Never" && c.AdoptionPolicy != "AdoptUnowned") {
		return errors.New("invalid identity controls")
	}
	if c.ImportID != "" {
		if !identityIsBound(c.ImportID, tenant, kind) {
			return errors.New("foreign import identity")
		}
	}
	return nil
}
func identityIsBound(id, tenant, kind string) bool {
	parts, err := client.ParseID(id)
	if err != nil || parts[0] != tenant || parts[1] != kind {
		return false
	}
	if kind == "resource" {
		u, err := url.Parse(parts[2])
		return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
	}
	return true
}
func decode(raw []byte, out any) error {
	if len(raw) > 65536 || client.PublicSpec(raw) != nil {
		return errors.New("specification exceeds supported bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("invalid specification")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("invalid specification")
	}
	return nil
}
func (s *Service) desired(ctx context.Context, o Object) (Common, json.RawMessage, error) {
	var controls Common
	var public any
	switch o.Kind {
	case "Application":
		var spec struct {
			Common
			ClientName   string   `json:"clientName"`
			RedirectURIs []string `json:"redirectUris"`
			GrantTypes   []string `json:"grantTypes"`
			Scopes       []string `json:"scopes"`
			Resources    []string `json:"resources"`
			JWKSURI      string   `json:"jwksUri,omitempty"`
			JWKSRef      *Ref     `json:"publicJwksSecretRef,omitempty"`
		}
		if err := decode(o.Spec, &spec); err != nil {
			return controls, nil, err
		}
		controls = spec.Common
		if (spec.JWKSURI == "") == (spec.JWKSRef == nil) {
			return controls, nil, errors.New("ambiguous public JWKS source")
		}
		registration := map[string]any{"client_name": spec.ClientName, "compliance_profile": "fapi", "application_type": "web", "token_endpoint_auth_method": "private_key_jwt", "redirect_uris": spec.RedirectURIs, "grant_types": spec.GrantTypes, "scope": strings.Join(spec.Scopes, " "), "resources": spec.Resources}
		if spec.JWKSRef != nil {
			raw, err := s.secret(ctx, *spec.JWKSRef)
			if err != nil {
				return controls, nil, err
			}
			if client.PublicSpec(raw) != nil {
				return controls, nil, errors.New("invalid public JWKS")
			}
			var jwks any
			if json.Unmarshal(raw, &jwks) != nil {
				return controls, nil, errors.New("invalid public JWKS")
			}
			registration["jwks"] = jwks
		} else {
			registration["jwks_uri"] = spec.JWKSURI
		}
		public = registration
	case "Resource":
		var spec struct {
			Common
			Identifier    string    `json:"identifier"`
			Scopes        *[]string `json:"scopes"`
			Lifetime      *int64    `json:"defaultTokenLifetimeSeconds"`
			Introspection []string  `json:"introspectionClients"`
		}
		if err := decode(o.Spec, &spec); err != nil {
			return controls, nil, err
		}
		controls = spec.Common
		public = map[string]any{"identifier": spec.Identifier, "scopes": spec.Scopes, "default_token_lifetime_seconds": spec.Lifetime, "introspection_clients": spec.Introspection}
	case "Policy":
		var spec struct {
			Common
			RulesJSON string `json:"rulesJson"`
		}
		if err := decode(o.Spec, &spec); err != nil {
			return controls, nil, err
		}
		controls = spec.Common
		if err := client.PublicSpec([]byte(spec.RulesJSON)); err != nil {
			return controls, nil, errors.New("invalid policy document")
		}
		public = json.RawMessage(spec.RulesJSON)
	default:
		return controls, nil, errors.New("unsupported identity kind")
	}
	if err := controls.check(s.Config.Tenant, kinds[o.Kind]); err != nil {
		return controls, nil, err
	}
	raw, err := json.Marshal(public)
	if err != nil || client.PublicSpec(raw) != nil {
		return controls, nil, errors.New("invalid public desired state")
	}
	return controls, raw, nil
}
