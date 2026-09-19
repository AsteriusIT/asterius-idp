# Tenant authentication assurance

Tenant administrators edit **Tenant settings → Authentication**. The same policy is
read by discovery, authorization, password/passkey sign-in, step-up, account pages,
device/CIBA approval, token issuance and AuthZEN. `GET` and `PUT
/admin/api/v1/tenants/{tenant_id}/settings` expose `acr_policy`:

```json
{
  "amr_in_id_token": true,
  "levels": [
    { "value": "tenant:password", "amr": ["pwd"] },
    { "value": "tenant:verified", "amr": ["swk", "user"] }
  ]
}
```

Supply the existing required code/access-token lifetime fields when using PUT.
Omitting `acr_policy` preserves it, including saves from older consoles. The
migration adds a null override only to previously unconfigured tenants. Absence
and null retain the existing built-in deployment ladder (password, passkey,
verified passkey and the `phr` alias). No deployment-configured ACR ladder existed
before this migration. An empty levels list deliberately emits no ACR claims.

The ladder is ordered weakest first, with at most 32 unique ASCII names of 255
bytes. Every level needs a method. `pwd`, `swk` and `user` describe a password,
passkey and user verification; `user` must accompany `swk`. OTP, existing-session
and hardware-attestation claims cannot be configured because this implementation
cannot establish them as authentication ceremonies. Reserved passkey names cannot
be weakened. Deployment and tenant administrators still need the independently
enforced passkey with user verification; editing this ladder cannot bypass that
guard. Setting `amr_in_id_token` false omits AMR from ID tokens, while recorded
proof and access-token authentication facts remain available for enforcement.

Writes require the target tenant's `admin.tenants:write` authority and console
CSRF protection (or the existing DPoP automation credentials). They produce an
`admin.changed` event with the tenant and policy before/after values. Cache entries
are keyed by tenant. The writing server invalidates its settings cache immediately;
other replicas reload within the existing 30-second TTL. Already cached discovery
responses retain the existing five-minute HTTP cache lifetime. A failed settings
read refuses the request rather than substituting a default policy.

Changing a class's required methods never upgrades an existing session by name.
Authorization compares the session's recorded methods with the current definition;
a stronger essential requirement starts step-up, and a silent request returns
`interaction_required`. Removing an essential context makes it unattainable.
Consent completion checks the policy again so a change during an interaction cannot
issue a grant on insufficient proof. Newly issued tokens remove a historical ACR
whose current definition is no longer met, including offline grant snapshots;
they do not invent a stronger ACR. A policy edit does not revoke already signed
tokens, sessions or grants, and does not retroactively change proof timestamps.
