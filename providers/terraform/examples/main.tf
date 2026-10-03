terraform {
  required_providers {
    asterius = {
      source  = "asterius/asterius"
      version = "~> 0.1"
    }
  }
}

# Set ASTERIUS_* environment variables as described in ../README.md.
# Tenant creation needs reserved-tenant service credentials with deployment reach.
provider "asterius" {}

variable "issuer_origin" {
  type        = string
  description = "HTTPS origin used by path-based tenant issuers."
}

variable "client_public_jwks_file" {
  type        = string
  description = "External file containing only the application's public JWKS."
}

variable "existing_user_id" {
  type        = string
  description = "Existing user UUID in the routed tenant; the provider never creates a password."
}

resource "asterius_tenant" "business" {
  external_key = "production/business-tenant/v1"
  spec_json = jsonencode({
    tenant_id        = "business"
    issuer           = "${var.issuer_origin}/t/business"
    display_name     = "Business"
    default_resource = "https://business-api.example/"
    options          = {}
  })
  retain_on_delete = true
}

# The remaining objects belong to the provider's routed tenant. To manage
# business's contents instead, use a provider alias with target_tenant =
# asterius_tenant.business.identity_key and the matching canonical issuer.
resource "asterius_resource" "billing" {
  external_key = "production/billing-audience/v1"
  spec_json = jsonencode({
    identifier                     = "https://billing-api.example/"
    scopes                         = ["read", "write"]
    default_token_lifetime_seconds = 300
    introspection_clients          = []
  })
}

resource "asterius_application" "billing" {
  external_key = "production/billing-application/v1"
  spec_json = jsonencode({
    client_name                = "Billing"
    compliance_profile         = "fapi"
    token_endpoint_auth_method = "private_key_jwt"
    redirect_uris              = ["https://billing.example/callback"]
    jwks                       = jsondecode(file(var.client_public_jwks_file))
    resources                  = [asterius_resource.billing.identity_key]
  })
}

resource "asterius_group" "billing" {
  external_key = "production/billing-group/v1"
  spec_json = jsonencode({
    name         = "billing"
    display_name = "Billing team"
  })
}

resource "asterius_membership" "billing" {
  external_key = "production/billing-member/${var.existing_user_id}/v1"
  spec_json = jsonencode({
    group_id = asterius_group.billing.identity_key
    user_id  = var.existing_user_id
  })
}

# This empty ordered rule set is a schema example. Review a real access policy
# before applying it; import an existing policy instead of creating a duplicate.
resource "asterius_policy" "tenant" {
  external_key = "production/tenant-policy/v1"
  spec_json = jsonencode({
    version = 1
    rules   = []
  })
}

data "asterius_group" "billing" {
  id = asterius_group.billing.id
}

output "billing_group_id" {
  value = data.asterius_group.billing.identity_key
}
