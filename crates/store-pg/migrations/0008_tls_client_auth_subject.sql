-- The certificate subject a `tls_client_auth` client is matched on
-- (RFC 8705 §2.1.2, `ast-m9c.3`).
--
-- §2.1.2 registers five metadata parameters — `tls_client_auth_subject_dn` and
-- four `tls_client_auth_san_*` — and requires a client to use "exactly one" of
-- them. Two columns rather than five, holding the field name and its value,
-- because "exactly one" is then a property of the row rather than a check
-- across five nullable columns that a later migration could weaken by adding a
-- sixth.
--
-- The value is compared byte for byte against what the presented certificate
-- says (§2.1). It is stored as written for that reason: no normalisation, no
-- case folding, no trimming. A `citext` column or a lower-cased index here
-- would make two different certificates match one registration, and the second
-- of them belongs to somebody else.
alter table clients
    add column tls_client_auth_field text
        check (tls_client_auth_field in (
            'tls_client_auth_subject_dn',
            'tls_client_auth_san_dns',
            'tls_client_auth_san_uri',
            'tls_client_auth_san_ip',
            'tls_client_auth_san_email')),
    add column tls_client_auth_value text;

alter table clients
    -- Both or neither: a field naming nothing, or a value nobody knows how to
    -- compare, are each a row the authenticator would have to guess about.
    add constraint clients_tls_client_auth_subject_is_complete
        check ((tls_client_auth_field is null) = (tls_client_auth_value is null)),
    -- The invariant `ClientMetadata::validate` establishes, restated where the
    -- data is: a PKI-mode client has a subject, and nobody else does.
    --
    -- Without the first half, a `tls_client_auth` client with no registered
    -- subject would be a client whose certificate is compared against nothing
    -- — which is a client that any certificate from a trusted CA
    -- authenticates. Without the second, a value would sit on a row nothing
    -- reads, which an operator can believe is in force.
    add constraint clients_tls_client_auth_subject_matches_method
        check (
            (token_endpoint_auth_method = 'tls_client_auth')
            = (tls_client_auth_field is not null)
        );
