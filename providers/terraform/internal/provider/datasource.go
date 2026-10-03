package provider

import (
	"context"
	"encoding/json"
	"time"

	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type identityDataSource struct {
	kind   string
	client *client.Client
}
type dataModel struct {
	IdentityKey types.String `tfsdk:"identity_key"`
	ID          types.String `tfsdk:"id"`
	Spec        types.String `tfsdk:"spec_json"`
	Revision    types.String `tfsdk:"revision"`
	Owner       types.String `tfsdk:"owner"`
	Origin      types.String `tfsdk:"origin_json"`
	Protection  types.Bool   `tfsdk:"deletion_protection"`
}

func (d *identityDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, r *datasource.MetadataResponse) {
	r.TypeName = req.ProviderTypeName + "_" + d.kind
}
func (d *identityDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, r *datasource.SchemaResponse) {
	r.Schema = schema.Schema{Description: "Read one public " + d.kind + " by immutable identity. Never adopts or writes.", Attributes: map[string]schema.Attribute{
		"identity_key": schema.StringAttribute{Computed: true, Description: "Immutable first identity key for resource dependencies."},
		"id":           schema.StringAttribute{Required: true, Description: "Portable base64url JSON import identity."}, "spec_json": schema.StringAttribute{Computed: true, Description: "Full canonical public configuration."}, "revision": schema.StringAttribute{Computed: true, Description: "Strong server revision."}, "owner": schema.StringAttribute{Computed: true, Description: "Server-derived owner JSON, empty if unowned."}, "origin_json": schema.StringAttribute{Computed: true, Description: "Durable builder provenance."}, "deletion_protection": schema.BoolAttribute{Computed: true, Description: "Active server deletion guard."}}}
}
func (d *identityDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, r *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	var ok bool
	d.client, ok = req.ProviderData.(*client.Client)
	if !ok {
		r.Diagnostics.AddError("Invalid provider client", "Internal provider configuration type is invalid.")
	}
}
func (d *identityDataSource) Read(ctx context.Context, req datasource.ReadRequest, r *datasource.ReadResponse) {
	if d.client == nil {
		r.Diagnostics.AddError("Service configuration is unknown", "Configure known external service credentials before reading.")
		return
	}

	var data dataModel
	r.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if r.Diagnostics.HasError() {
		return
	}
	parts, err := client.ParseID(data.ID.ValueString())
	if err != nil || parts[1] != d.kind {
		r.Diagnostics.AddError("Invalid data source identity", "Import identity must match the data source kind.")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	doc, err := d.client.Read(ctx, data.ID.ValueString())
	if err != nil {
		r.Diagnostics.AddError("Cannot read public identity", err.Error())
		return
	}
	canonical, _ := client.Canonical(doc.Spec)
	data.Spec = types.StringValue(canonical)
	data.Revision = types.StringValue(doc.Revision)
	data.IdentityKey = types.StringValue(parts[2])
	data.Owner = types.StringValue("")
	if doc.Owner != nil {
		data.Owner = types.StringValue(*doc.Owner)
	}
	origin := doc.Origin
	if origin == nil {
		origin = []json.RawMessage{}
	}
	raw, _ := json.Marshal(origin)
	data.Origin = types.StringValue(string(raw))
	data.Protection = types.BoolValue(doc.DeletionProtection)
	r.Diagnostics.Append(r.State.Set(ctx, &data)...)
}
