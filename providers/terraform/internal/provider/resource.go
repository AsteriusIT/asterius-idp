package provider

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type identityResource struct {
	kind   string
	client *client.Client
}
type resourceModel struct {
	IdentityKey types.String `tfsdk:"identity_key"`
	ID          types.String `tfsdk:"id"`
	ExternalKey types.String `tfsdk:"external_key"`
	Spec        types.String `tfsdk:"spec_json"`
	Observed    types.String `tfsdk:"observed_spec_json"`
	Revision    types.String `tfsdk:"revision"`
	Owner       types.String `tfsdk:"owner"`
	Origin      types.String `tfsdk:"origin_json"`
	Protection  types.Bool   `tfsdk:"deletion_protection"`
	Adopt       types.Bool   `tfsdk:"adopt"`
	Retain      types.Bool   `tfsdk:"retain_on_delete"`
	Timeout     types.String `tfsdk:"operation_timeout"`
}

func (r *identityResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.kind
}
func (r *identityResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage one " + r.kind + " by immutable import identity and exclusive authenticated service ownership. Public specs only; no generated credentials. Writes bind to the refreshed revision and never force a conflict.", Attributes: map[string]schema.Attribute{
		"identity_key":        schema.StringAttribute{Computed: true, Description: "Immutable first identity key for resource dependencies.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"id":                  schema.StringAttribute{Computed: true, Description: "Portable base64url JSON import identity.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"external_key":        schema.StringAttribute{Optional: true, Computed: true, Description: "Durable nonsecret logical creation identity. Required for creation; omit when importing. Changing it creates a new incarnation; old keys cannot be reused after deletion.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}},
		"spec_json":           schema.StringAttribute{Required: true, Description: "Public desired specification as jsonencode(...), using the declarative API v1 schema. Server defaults are canonicalized without causing plan churn; ordered policy rules remain ordered."},
		"observed_spec_json":  schema.StringAttribute{Computed: true, Description: "Full canonical public server specification; not a secret store."},
		"revision":            schema.StringAttribute{Computed: true, Description: "Strong server revision (including management generation), used as If-Match."},
		"owner":               schema.StringAttribute{Computed: true, Description: "Server-derived issuing tenant and client ID, encoded as JSON; empty if unowned."},
		"origin_json":         schema.StringAttribute{Computed: true, Description: "Durable builder provenance; never erased by adoption or deletion."},
		"deletion_protection": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), Description: "Server deletion protection. Disable in a separate apply before destroying."},
		"adopt":               schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "Explicit permission to adopt an imported unowned object during apply. Import/refresh never adopts, managed builder origins remain protected."},
		"retain_on_delete":    schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(r.kind == "tenant"), Description: "Release controller ownership and retain live state on destroy. Required for tenants, which v1 never deletes."},
		"operation_timeout":   schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("2m"), Description: "Bounded duration for each read/create/update/delete, maximum 10m."},
	}}
}
func (r *identityResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	var ok bool
	r.client, ok = req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Invalid provider client", "Internal provider configuration type is invalid.")
	}
}
func bounded(ctx context.Context, data resourceModel) (context.Context, context.CancelFunc, error) {
	duration, err := time.ParseDuration(data.Timeout.ValueString())
	if err != nil || duration <= 0 || duration > 10*time.Minute {
		return nil, nil, errors.New("operation_timeout must be greater than zero and at most ten minutes")
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	return ctx, cancel, nil
}
func publicData(data resourceModel) (json.RawMessage, error) {
	if data.Spec.IsUnknown() || data.Spec.IsNull() {
		return nil, errors.New("desired public specification is unknown")
	}
	raw := json.RawMessage(data.Spec.ValueString())
	return raw, client.PublicSpec(raw)
}
func populate(data *resourceModel, doc client.Document) {
	data.ID = types.StringValue(doc.ID)
	parts, _ := client.ParseID(doc.ID)
	data.IdentityKey = types.StringValue(parts[2])
	data.Revision = types.StringValue(doc.Revision)
	canonical, _ := client.Canonical(doc.Spec)
	data.Observed = types.StringValue(canonical)
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
}
func (r *identityResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !data.Spec.IsUnknown() && !data.Spec.IsNull() {
		if _, err := publicData(data); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("spec_json"), "Invalid public specification", err.Error())
		}
	}
	if r.kind == "tenant" && !data.Retain.IsNull() && !data.Retain.IsUnknown() && !data.Retain.ValueBool() {
		resp.Diagnostics.AddAttributeError(path.Root("retain_on_delete"), "Tenant deletion is unavailable", "Tenant v1 supports retain/release only.")
	}
	if !data.Timeout.IsUnknown() && !data.Timeout.IsNull() {
		_, cancel, err := bounded(ctx, data)
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("operation_timeout"), "Invalid timeout", err.Error())
		} else {
			cancel()
		}
	}
}
func (r *identityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Service configuration is unknown", "Configure known external service credentials before executing an operation.")
		return
	}

	var data resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel, err := bounded(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid timeout", err.Error())
		return
	}
	defer cancel()
	spec, err := publicData(data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid public specification", err.Error())
		return
	}
	if data.ExternalKey.IsUnknown() || data.ExternalKey.IsNull() || data.ExternalKey.ValueString() == "" {
		resp.Diagnostics.AddError("Explicit creation identity required", "Set a unique, nonsecret external_key before creating an object. It must remain stable across uncertain outcomes and retries. Omit this attribute only when importing.")
		return
	}
	// Preserve logical intent even if the response is lost. Explicit keys let another run resolve the same create safely.
	doc, err := r.client.Create(ctx, r.kind, data.ExternalKey.ValueString(), spec, data.Protection.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("Cannot create managed identity", err.Error()+"; retry with the same explicit external_key if the outcome is uncertain.")
		return
	}
	populate(&data, doc)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
func (r *identityResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Service configuration is unknown", "Configure known external service credentials before executing an operation.")
		return
	}

	var data resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Import initially contains only id; populate safe provider-only defaults before the first refresh.
	if data.Timeout.IsNull() {
		data.Timeout = types.StringValue("2m")
	}
	if data.Adopt.IsNull() {
		data.Adopt = types.BoolValue(false)
	}
	if data.Retain.IsNull() {
		data.Retain = types.BoolValue(r.kind == "tenant")
	}
	if data.ExternalKey.IsNull() {
		data.ExternalKey = types.StringValue("import/" + data.ID.ValueString())
	}
	ctx, cancel, err := bounded(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid timeout", err.Error())
		return
	}
	defer cancel()
	doc, err := r.client.Read(ctx, data.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Cannot refresh managed identity", err.Error())
		return
	}
	if doc.Kind != r.kind {
		resp.Diagnostics.AddError("Wrong import kind", "The imported identity does not match this resource type.")
		return
	}
	if data.Spec.IsNull() {
		canonical, _ := client.Canonical(doc.Spec)
		data.Spec = types.StringValue(canonical)
	} else {
		spec, err := publicData(data)
		if err != nil {
			resp.Diagnostics.AddError("Invalid stored specification", err.Error())
			return
		}
		plan, err := r.client.Plan(ctx, doc, spec)
		if err != nil {
			resp.Diagnostics.AddError("Cannot compare canonical drift", err.Error())
			return
		}
		if plan.Changed {
			canonical, _ := client.Canonical(doc.Spec)
			data.Spec = types.StringValue(canonical)
		}
	}
	populate(&data, doc)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
func (r *identityResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Service configuration is unknown", "Configure known external service credentials before executing an operation.")
		return
	}

	var data, prior resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel, err := bounded(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid timeout", err.Error())
		return
	}
	defer cancel()
	spec, err := publicData(data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid public specification", err.Error())
		return
	}
	revision := prior.Revision.ValueString()
	if prior.Owner.ValueString() == "" {
		if !data.Adopt.ValueBool() {
			resp.Diagnostics.AddError("Explicit adoption required", "Import and refresh are read-only. Set adopt = true to claim an unowned object during apply.")
			return
		}
		doc, err := r.client.Mutate(ctx, "POST", prior.ID.ValueString(), "/adopt", revision, nil)
		if err != nil {
			resp.Diagnostics.AddError("Cannot adopt identity", err.Error())
			return
		}
		revision = doc.Revision
	} else if prior.Owner.ValueString() != r.client.Owner() {
		resp.Diagnostics.AddError("Controller ownership conflict", "The resource belongs to another service client; no implicit takeover is allowed.")
		return
	}
	doc, err := r.client.Mutate(ctx, "PUT", prior.ID.ValueString(), "", revision, map[string]any{"spec": spec, "deletion_protection": data.Protection.ValueBool()})
	if err != nil {
		resp.Diagnostics.AddError("Cannot update managed identity", err.Error())
		return
	}
	populate(&data, doc)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
func (r *identityResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Service configuration is unknown", "Configure known external service credentials before executing an operation.")
		return
	}

	var data resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel, err := bounded(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid timeout", err.Error())
		return
	}
	defer cancel()
	owner := data.Owner.ValueString()
	if owner != "" && owner != r.client.Owner() {
		resp.Diagnostics.AddError("Controller ownership conflict", "Cannot delete or release another controller's object.")
		return
	}
	if data.Retain.ValueBool() {
		if owner != "" {
			_, err = r.client.Mutate(ctx, "POST", data.ID.ValueString(), "/release", data.Revision.ValueString(), nil)
		}
		if err != nil {
			resp.Diagnostics.AddError("Cannot release identity", err.Error())
			return
		}
		resp.State.RemoveResource(ctx)
		return
	}
	if r.kind == "tenant" || data.Protection.ValueBool() {
		resp.Diagnostics.AddError("Deletion protection enabled", "Apply deletion_protection = false separately before destroy, or set retain_on_delete = true.")
		return
	}
	if owner == "" {
		resp.Diagnostics.AddError("Unowned identity", "An unowned imported object cannot be deleted; explicitly adopt it or retain it.")
		return
	}
	_, err = r.client.Mutate(ctx, "DELETE", data.ID.ValueString(), "", data.Revision.ValueString(), nil)
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Cannot delete managed identity", err.Error())
		return
	}
	resp.State.RemoveResource(ctx)
}
func (r *identityResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts, err := client.ParseID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import identity", err.Error())
		return
	}
	if parts[1] != r.kind {
		resp.Diagnostics.AddError("Wrong import kind", "Import identity kind must match the resource type.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

func (r *identityResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var planned, prior resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &planned)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() || planned.Spec.IsUnknown() || planned.Spec.IsNull() || prior.Spec.IsNull() {
		return
	}
	var desired, existing map[string]any
	if json.Unmarshal([]byte(planned.Spec.ValueString()), &desired) != nil || json.Unmarshal([]byte(prior.Spec.ValueString()), &existing) != nil {
		return
	}
	fields := []string{}
	switch r.kind {
	case "resource":
		fields = []string{"identifier"}
	case "membership":
		fields = []string{"group_id", "user_id"}
	case "tenant":
		fields = []string{"tenant_id"}
	}
	for _, field := range fields {
		if !reflect.DeepEqual(desired[field], existing[field]) {
			resp.RequiresReplace = append(resp.RequiresReplace, path.Root("spec_json"))
			return
		}
	}
}
