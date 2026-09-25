# SCIM provisioning surface

The SCIM base URL for a tenant is its issuer URL followed by
`/admin/api/v1/scim/v2`. Discovery currently serves
`ServiceProviderConfig`, `Schemas`, and `ResourceTypes`. The two catalogue
endpoints return empty SCIM `ListResponse` documents until the Users and Groups
handlers tracked by `ast-s36.13.2` and `ast-s36.13.3` are implemented.

Discovery requires an OAuth 2.0 client credentials access token issued by the
target tenant for the admin API audience (`<issuer>/admin/api/v1`), carrying
`admin.scim:read`. Present it with the `DPoP` authorization scheme and a DPoP
proof bound to the request method and absolute URL. A token issued for another
tenant or for the reserved deployment tenant is refused; an administrator's
browser session cannot access this surface.

`ServiceProviderConfig` reports `patch`, `bulk`, `filter`, `sort`, `etag`, and
`changePassword` as unsupported. Passwords, passkeys, roles, and grants remain
under their existing account and administration policies. RFC 9865 cursor
pagination and RFC 9967 asynchronous requests are not advertised.
