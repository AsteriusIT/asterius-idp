# Mount/path names must match your explicitly approved secret path.
path "kv/data/approved/application" {
  capabilities = ["read"]
}
path "auth/token/revoke-self" {
  capabilities = ["update"]
}
