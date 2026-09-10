-- Backchannel authentication requests (CIBA Core 1.0), `ast-lh3.4`.
--
-- One table, for the reason `device_codes` is one table: a CIBA request is a
-- single row that four actors move through three states, and splitting it
-- would put the state machine in application code where two of those actors
-- race.
--
--   * the client, which creates the row (§7.1) and then polls the token
--     endpoint with it (§10.1) or waits to be notified (§10.2);
--   * the person, who is asked on a device of their own and approves or
--     refuses (§7.3, `ast-lh3.6`);
--   * the token endpoint, which spends the approval exactly once (§10.1);
--   * retention, which deletes the row once it can no longer be spent.
--
-- The shape is deliberately the device flow's, because the flows are the same
-- shape: a credential held by a machine, an approval given elsewhere by a
-- person, and a clock. Where they differ the difference is stated below.
create table ciba_requests (
    tenant_id                      text        not null,
    -- §7.3's `auth_req_id`, digested. The client presents it at the token
    -- endpoint (§10.1) exactly as a device presents a device code, so it gets
    -- the treatment every bearer value here gets: a dump of this table is a
    -- list of digests rather than a list of identifiers somebody could poll
    -- with (RFC 6749 §10.4, RFC 9700 §4.14).
    auth_req_id_hash               bytea       not null,
    client_id                      text        not null,
    -- Who the hint resolved to (§7.2 step 2). Not null, and that is the
    -- difference from `device_codes`: a device authorization is created
    -- *before* anybody is identified and a CIBA request is created after. A
    -- row with no user would be a notification with nowhere to go.
    user_id                        uuid        not null,
    -- What the client asked for, already narrowed to its registration. The
    -- approval is for *these*, so they are recorded when the request arrives
    -- rather than re-read from anywhere later.
    scopes                         text[]      not null default '{}',
    authorization_details          jsonb       not null default '[]'::jsonb,
    -- §7.1's `acr_values`, in the order of preference the client wrote. An
    -- array rather than a space-delimited string: the order is meaning, and a
    -- text column would make it a parsing question at every read.
    acr_values                     text[]      not null default '{}',
    -- §7.1's `binding_message`, in the clear. It is displayed on the
    -- consumption device and on the authentication device so a person can see
    -- that the two are the same transaction, so it is not a secret and cannot
    -- be digested — it has to be rendered.
    binding_message                text,
    -- §4's `backchannel_token_delivery_mode`, copied onto the row rather than
    -- read back off the client. The mode decides who is answered and how, and
    -- a client whose registration changes between the request and the answer
    -- must not change how a request already in flight is delivered. Push is
    -- absent for the reason `0020_ciba_client_metadata.sql` gives.
    delivery_mode                  text        not null
                                   check (delivery_mode in ('poll', 'ping')),
    -- §7.1's `client_notification_token`, digested. It is the credential the
    -- §10.2 notification carries in an `Authorization` header, which makes it
    -- exactly the kind of value a database copy must not yield. The
    -- notification is signed with the value the *client* holds; this column is
    -- only ever compared against, never sent.
    client_notification_token_hash bytea,
    -- §7.1.2's `user_code`, digested if it is ever stored at all. Null today:
    -- this deployment advertises `backchannel_user_code_parameter_supported`
    -- as false and has no per-user code to verify one against (`ast-lh3.4`
    -- SUITE). The column exists so that the row shape does not change when it
    -- does, and it is a digest for the same reason `device_codes.user_code_hash`
    -- is.
    user_code_hash                 bytea,
    issued_at                      timestamptz not null default now(),
    -- §7.3's `expires_in`. At most five minutes, and shorter where the client
    -- asked for less: a pending CIBA request is a notification on somebody's
    -- lock screen, and every second it stays live is a second in which it can
    -- be approved by somebody who has forgotten what it was for.
    expires_at                     timestamptz not null,
    -- §7.3's `interval`, in seconds, as it currently stands for this request.
    -- Per-row rather than constant for the reason `device_codes` gives: the
    -- token endpoint raises it on a `slow_down` (`ast-lh3.5`), and a client
    -- that has already obeyed one must not be told to slow down again at the
    -- rate it was just asked to use.
    poll_interval_seconds          integer     not null,
    -- When the client last polled, which is the only thing "too fast" can be
    -- measured against. Null until the first poll, so the first one is never
    -- `slow_down`.
    last_polled_at                 timestamptz,
    -- The state machine. `pending` is what §11's `authorization_pending`
    -- answers for; `approved` is redeemable exactly once; `denied` is §11's
    -- `access_denied` and is terminal. Expiry is *not* a state — it is the
    -- clock against `expires_at` — so `expired_token` is the honest answer
    -- from the moment it is true rather than from the moment a sweep runs.
    status                         text        not null default 'pending'
                                   check (status in ('pending', 'approved', 'denied')),
    -- The authorization the approval created, and when. Both null while
    -- pending.
    grant_id                       uuid,
    approved_at                    timestamptz,
    -- Set by the one statement that spends the row (§10.1: the `auth_req_id`
    -- is redeemable once, as an authorization code is).
    redeemed_at                    timestamptz,
    -- Whether the §10.2 notification has been posted, so that a retry does not
    -- send a second one. Null in poll mode, where nothing is ever posted.
    notified_at                    timestamptz,

    primary key (tenant_id, auth_req_id_hash),
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, grant_id)
        references grants (tenant_id, grant_id) on delete set null,
    -- §7.3 leaves `expires_in` to the OP; `ast-lh3.4` caps it at five minutes
    -- and the schema says so too, so a row that violated the cap could not be
    -- written even if the issuing code were wrong.
    constraint ciba_requests_max_lifetime
        check (expires_at <= issued_at + interval '300 seconds'),
    -- The interval this server advertises is five seconds and `slow_down` only
    -- ever raises it. A row below it would be this server advertising a rate
    -- it then punishes a client for using.
    constraint ciba_requests_interval_floor
        check (poll_interval_seconds >= 5),
    -- §7.1: the notification token is REQUIRED in ping mode and MUST NOT be
    -- provided otherwise. A poll row holding one would be a credential nothing
    -- ever presents — and one a later switch to ping would start presenting
    -- without anybody reviewing it.
    constraint ciba_requests_notification_token_needs_ping
        check ((client_notification_token_hash is null) = (delivery_mode <> 'ping')),
    -- Nothing is notified in poll mode.
    constraint ciba_requests_only_ping_is_notified
        check (notified_at is null or delivery_mode = 'ping'),
    -- An approval is a stamp and a grant, or it is neither.
    constraint ciba_requests_approval_is_whole
        check ((status = 'approved') = (approved_at is not null)),
    -- Nothing that was never approved can have been spent.
    constraint ciba_requests_only_approved_are_redeemed
        check (redeemed_at is null or status = 'approved')
);

-- The two reads that are not by primary key: the approvals inbox lists a
-- person's pending requests (`ast-lh3.6`), and retention deletes by
-- `expires_at`.
create index ciba_requests_pending_for_user
    on ciba_requests (tenant_id, user_id, status);
create index ciba_requests_expiring on ciba_requests (tenant_id, expires_at);
