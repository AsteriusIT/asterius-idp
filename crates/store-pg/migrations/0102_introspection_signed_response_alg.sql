-- RFC 9701 signed introspection is an explicit per-client opt-in. Existing
-- resource servers keep RFC 7662 JSON responses; no implicit RS256 default is
-- enabled because the tenant signing profile has no RS256 key.
alter table clients
    add column introspection_signed_response_alg text
        check (introspection_signed_response_alg in ('EdDSA', 'ES256', 'PS256'));
