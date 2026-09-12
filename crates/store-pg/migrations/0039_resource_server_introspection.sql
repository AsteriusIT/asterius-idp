-- Which clients may introspect a resource server's tokens (RFC 7662, `ast-1sk.1`).
--
-- RFC 7662 §2.1 requires the introspection endpoint to "require either client
-- authentication ... or ... a separate OAuth 2.0 access token", and §4 goes
-- further: the authorization server "MUST ... only allow ... protected
-- resources that are authorized to introspect" a given token. That is a
-- relation between a *caller* and an *audience*, and until this column there
-- was nowhere to record it: `resource_servers` said which APIs exist (RFC 8707
-- §3) and `clients` said which credentials exist, and nothing joined the two.
--
-- The column lives here rather than on `clients` for the reason the table
-- exists at all. A resource server is a property of the deployment: the
-- operator who registered `https://api.example/accounts` is the one who knows
-- which credential fronts it. And client metadata is writable by a client at
-- RFC 7591 §2 registration, so a `resource_servers` list on the client row
-- would be a self-registering client naming the audiences whose tokens it may
-- read. There is no spelling of that which is not a privilege escalation.
--
-- Null and the empty array mean the same thing and are both left legal: no
-- client introspects tokens for this resource server, so the endpoint is
-- usable only by the token's own client (RFC 7662 §2.1's other authorized
-- caller). That is the default every row that exists today gets, which is the
-- narrowest posture rather than the most convenient one — a migration that
-- turned every registered client into an introspector of every audience would
-- be the escalation this column exists to prevent.
--
-- No foreign key to `clients`. A client that is deleted and registered again
-- under the same `client_id` is a different principal and must not inherit the
-- authority (`ast-m9c.12` writes a revocation cutoff for exactly that case),
-- but `on delete cascade` would silently empty an operator's configuration on
-- a deprovisioning, and `on delete restrict` would make deprovisioning fail
-- for a reason nobody expects. The list is an operator's statement about names,
-- checked against the *authenticated* caller at request time, which is where
-- the identity is established anyway.

alter table resource_servers
    add column introspection_clients text[] not null default '{}';

comment on column resource_servers.introspection_clients is
    'client_id values allowed to introspect tokens audienced at this resource server (RFC 7662 §2.1)';
