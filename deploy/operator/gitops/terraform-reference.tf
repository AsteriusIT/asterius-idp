terraform {
  required_providers {
    asterius = { source = "asterius/asterius" }
  }
}

# Configure a dedicated read-only FAPI client through ASTERIUS_* environment
# variables. Keep signing_key_file/ca_file outside the repository and state.
provider "asterius" {}

variable "operator_resource_import_id" {
  type        = string
  description = "Same-tenant immutable status.remoteId from a Ready Resource."
}

data "asterius_resource" "operator_managed" {
  id = var.operator_resource_import_id
}

output "operator_resource_identifier" {
  value = data.asterius_resource.operator_managed.identity_key
}
