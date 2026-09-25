# SCIM provisioning surface

The SCIM base URL for a tenant is its issuer URL followed by
`/admin/api/v1/scim/v2`. Discovery currently serves
`ServiceProviderConfig`, `Schemas`, and `ResourceTypes`. The catalogues list
the implemented User resource. Group provisioning remains tracked by
`ast-s36.13.3`.

Discovery requires an OAuth 2.0 client credentials access token issued by the
target tenant for the admin API audience (`<issuer>/admin/api/v1`), carrying
`admin.scim:read` for discovery and reads, or `admin.scim:write` for writes.
Present it with the `DPoP` authorization scheme and a DPoP
proof bound to the request method and absolute URL. A token issued for another
tenant or for the reserved deployment tenant is refused; an administrator's
browser session cannot access this surface.

`GET /Users` offers bounded offset paging (`startIndex` 1–10001, `count` 0–200)
and the exact `userName eq "value"` filter. `POST /Users` creates an account
without credentials. `GET /Users/{id}` returns the current profile and weak
ETag; `PUT`, `PATCH`, and `DELETE` require that ETag in `If-Match`.
`PUT` and `PATCH` accept only `userName`, one work email, `externalId`, and
`active`; PATCH supports `add`, `replace`, and `remove` on these paths.
`active=false` disables the account and revokes its sessions, grants, refresh
tokens and previously minted access tokens. DELETE additionally tombstones the
client's SCIM resource, so later reads return 404. A SCIM client cannot unlock
a security-locked account. Passwords, passkeys, roles, and grants remain under
their existing account and administration policies.

`ServiceProviderConfig` advertises User PATCH, the supported filter shape and
ETags. Bulk, sort, and password changes are unsupported. RFC 9865 cursor
pagination and RFC 9967 asynchronous requests are not advertised.
