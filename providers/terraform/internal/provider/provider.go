package provider

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type identityProvider struct{ version string }
type configModel struct {
	IssuingTenant types.String `tfsdk:"issuing_tenant"`
	TargetIssuer  types.String `tfsdk:"target_issuer"`
	TargetTenant  types.String `tfsdk:"target_tenant"`
	Issuer        types.String `tfsdk:"issuer"`
	ClientID      types.String `tfsdk:"client_id"`
	KeyFile       types.String `tfsdk:"signing_key_file"`
	KeyID         types.String `tfsdk:"signing_key_id"`
	CAFile        types.String `tfsdk:"ca_file"`
	Resource      types.String `tfsdk:"token_resource"`
	Scopes        types.String `tfsdk:"scopes"`
	Timeout       types.String `tfsdk:"request_timeout"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &identityProvider{version: version} }
}
func (p *identityProvider) Metadata(_ context.Context, _ provider.MetadataRequest, r *provider.MetadataResponse) {
	r.TypeName = "asterius"
	r.Version = p.version
}
func (p *identityProvider) Schema(_ context.Context, _ provider.SchemaRequest, r *provider.SchemaResponse) {
	r.Schema = schema.Schema{Description: "Public declarative identity configuration via scoped DPoP service credentials. Only external key paths are configured; credentials are never resource attributes.", Attributes: map[string]schema.Attribute{
		"issuing_tenant":   schema.StringAttribute{Optional: true, Description: "Authenticated issuer's tenant ID; inferred for /t/tenant URLs, required for vanity issuers. Environment ASTERIUS_ISSUING_TENANT."},
		"target_issuer":    schema.StringAttribute{Optional: true, Description: "Canonical issuer URL of target_tenant for vanity hosts or a different authority. Environment ASTERIUS_TARGET_ISSUER."},
		"target_tenant":    schema.StringAttribute{Optional: true, Description: "Routed tenant for creation; defaults to issuing tenant. Deployment-reach credentials may address another tenant. Environment ASTERIUS_TARGET_TENANT."},
		"issuer":           schema.StringAttribute{Optional: true, Description: "HTTPS issuing tenant URL. Environment ASTERIUS_ISSUER."},
		"client_id":        schema.StringAttribute{Optional: true, Description: "Dedicated automation client ID. Environment ASTERIUS_CLIENT_ID."},
		"signing_key_file": schema.StringAttribute{Optional: true, Description: "External PKCS8 ES256 PEM file path; never inline private material. Environment ASTERIUS_SIGNING_KEY_FILE."},
		"signing_key_id":   schema.StringAttribute{Optional: true, Description: "Registered public JWK kid. Environment ASTERIUS_SIGNING_KEY_ID."},
		"ca_file":          schema.StringAttribute{Optional: true, Description: "Additional trusted PEM CA bundle path. Environment ASTERIUS_CA_FILE."},
		"token_resource":   schema.StringAttribute{Optional: true, Description: "Admin API token audience (RFC8707). Environment ASTERIUS_TOKEN_RESOURCE."},
		"scopes":           schema.StringAttribute{Optional: true, Description: "Space-separated dedicated admin.session:read and kind read/write scopes. Environment ASTERIUS_SCOPES. Must be explicitly granted; there is no all-powerful default."},
		"request_timeout":  schema.StringAttribute{Optional: true, Description: "HTTP request timeout, default 60s, maximum 10m."},
	}}
}
func env(value types.String, key string) string {
	if value.IsNull() {
		return os.Getenv(key)
	}
	return value.ValueString()
}
func (p *identityProvider) Configure(ctx context.Context, req provider.ConfigureRequest, r *provider.ConfigureResponse) {
	var data configModel
	r.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if r.Diagnostics.HasError() {
		return
	}
	for _, v := range []types.String{data.Issuer, data.ClientID, data.KeyFile, data.KeyID, data.CAFile, data.Resource, data.Scopes, data.Timeout, data.TargetTenant, data.IssuingTenant, data.TargetIssuer} {
		if v.IsUnknown() {
			return
		}
	}
	timeout := 60 * time.Second
	if !data.Timeout.IsNull() {
		var err error
		timeout, err = time.ParseDuration(data.Timeout.ValueString())
		if err != nil {
			r.Diagnostics.AddError("Invalid timeout", "request_timeout must be a Go duration.")
			return
		}
	}
	scopes := strings.Fields(env(data.Scopes, "ASTERIUS_SCOPES"))
	if len(scopes) == 0 {
		r.Diagnostics.AddError("Missing dedicated scopes", "Set scopes or ASTERIUS_SCOPES explicitly; admin.session:read and the addressed kind read/write scopes are required.")
		return
	}
	c, err := client.New(client.Config{IssuingTenant: env(data.IssuingTenant, "ASTERIUS_ISSUING_TENANT"), TargetIssuer: env(data.TargetIssuer, "ASTERIUS_TARGET_ISSUER"), TargetTenant: env(data.TargetTenant, "ASTERIUS_TARGET_TENANT"), Issuer: env(data.Issuer, "ASTERIUS_ISSUER"), ClientID: env(data.ClientID, "ASTERIUS_CLIENT_ID"), KeyFile: env(data.KeyFile, "ASTERIUS_SIGNING_KEY_FILE"), KeyID: env(data.KeyID, "ASTERIUS_SIGNING_KEY_ID"), CAFile: env(data.CAFile, "ASTERIUS_CA_FILE"), Resource: env(data.Resource, "ASTERIUS_TOKEN_RESOURCE"), Scopes: scopes, Timeout: timeout})
	if err != nil {
		r.Diagnostics.AddError("Cannot configure service client", err.Error())
		return
	}
	r.ResourceData = c
	r.DataSourceData = c
}
func (p *identityProvider) Resources(_ context.Context) []func() resource.Resource {
	var out []func() resource.Resource
	for _, kind := range []string{"tenant", "application", "resource", "group", "membership", "policy"} {
		k := kind
		out = append(out, func() resource.Resource { return &identityResource{kind: k} })
	}
	return out
}
func (p *identityProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	var out []func() datasource.DataSource
	for _, kind := range []string{"tenant", "application", "resource", "group", "membership", "policy"} {
		k := kind
		out = append(out, func() datasource.DataSource { return &identityDataSource{kind: k} })
	}
	return out
}
