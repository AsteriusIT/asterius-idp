-- CIBA Core 1.0 §4 client metadata (`ast-lh3.7`).
--
-- Three columns for the three members a CIBA client registers beside
-- `backchannel_authentication_request_signing_alg`, which the baseline already
-- has. They are nullable and default to the absence of CIBA, so every client
-- already registered keeps exactly the shape it had.
--
-- The checks restate `ClientMetadata::validate`, and deliberately: a row is
-- reloaded and re-validated by the same code that accepted the document
-- (`ClientMetadata` round-trips through the store), but nothing stops a
-- migration, a fixture or a hand-edited row from writing a combination the
-- validator would have refused — and a stored CIBA client with no delivery
-- mode is one the backchannel endpoint (`ast-lh3.4`) could not answer.
alter table clients
    -- §4: "backchannel_token_delivery_mode ... REQUIRED". Poll and ping only:
    -- push (§10.3) posts the tokens themselves to a client-supplied URL, which
    -- is not a place this server sends a credential, so it is not a value the
    -- column can hold.
    add column backchannel_token_delivery_mode text
        check (backchannel_token_delivery_mode in ('poll', 'ping')),
    -- §4: REQUIRED in ping mode, and https, since §10.2 posts to it.
    add column backchannel_client_notification_endpoint text,
    -- §4. Whether the client sends a `user_code`. Not null: false is the
    -- specification's default and the answer for every client that is not a
    -- CIBA client.
    add column backchannel_user_code_parameter boolean not null default false;

-- The grant and the mode arrive together or not at all. Without this, a client
-- could hold a delivery mode it will never use, or use the CIBA grant with no
-- mode to be answered in.
alter table clients
    add constraint clients_ciba_grant_has_a_delivery_mode
        check ((backchannel_token_delivery_mode is not null)
               = ('urn:openid:params:grant-type:ciba' = any (grant_types)));

-- §10.1: a poll client is never called back, so a notification endpoint on one
-- is a URL nothing reads — and one a later switch to ping would start posting
-- to without anybody reviewing it.
alter table clients
    add constraint clients_notification_endpoint_needs_ping
        check ((backchannel_client_notification_endpoint is null)
               = (backchannel_token_delivery_mode is distinct from 'ping'));

-- The same rule as the three columns beside it: the members CIBA defines are
-- meaningless on a client that cannot make a backchannel authentication
-- request, and a value nothing reads is one an operator can believe is in
-- force.
alter table clients
    add constraint clients_backchannel_members_need_the_ciba_grant
        check ('urn:openid:params:grant-type:ciba' = any (grant_types)
               or (backchannel_authentication_request_signing_alg is null
                   and not backchannel_user_code_parameter));
