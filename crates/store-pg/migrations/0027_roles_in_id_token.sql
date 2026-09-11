-- Whether a client's ID tokens carry the application-role claims (`ast-mqt`).
--
-- `ast-095` put `roles` and `resource_access` in the access token and at
-- `/userinfo`. An ID token is a different container: it passes through a
-- browser, it is stored by the client, and it turns up in the log line
-- somebody pasted into a ticket. So the claims reach it only when the client
-- asks — per authorization with OIDC Core §5.5's `claims` parameter, or once
-- and for all with this column.
--
-- Not null with a `false` default, which is the answer every client already
-- registered gives: a client registered before this column existed did not ask
-- for authority claims in the token that passes through a browser, and a
-- default of true would put them there for every client of every tenant at
-- once.
alter table clients
    add column roles_in_id_token boolean not null default false;
