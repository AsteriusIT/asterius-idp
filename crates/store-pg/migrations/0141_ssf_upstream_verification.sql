-- An operator request has one unpredictable state and a bounded response
-- window. Retain processed JTIs long enough to acknowledge retransmissions
-- after an interrupted RFC 8936 ACK.
alter table ssf_receiver_upstream_streams
    add column verification_state_hash bytea,
    add column verification_expires_at timestamptz,
    add column last_verified_at timestamptz,
    add column last_challenge_verified_at timestamptz,
    add constraint ssf_upstream_verification_pending_pair check
        ((verification_state_hash is null) = (verification_expires_at is null)),
    add constraint ssf_upstream_verification_state_size check
        (verification_state_hash is null or octet_length(verification_state_hash) = 32);

alter table ssf_receiver_upstream_streams
    add constraint ssf_upstream_stream_identity_unique
        unique (tenant_id, peer_client_id, stream_id);

create table ssf_receiver_upstream_verification_events (
    tenant_id text not null,
    peer_client_id text not null,
    jti text not null,
    stream_id text not null,
    replay_until timestamptz not null,
    processed_at timestamptz not null,
    primary key (tenant_id, peer_client_id, jti),
    foreign key (tenant_id, peer_client_id, stream_id)
        references ssf_receiver_upstream_streams
            (tenant_id, peer_client_id, stream_id) on delete cascade,
    check (length(jti) between 1 and 255),
    check (length(stream_id) between 1 and 255)
);
create index ssf_receiver_upstream_verification_expiry
    on ssf_receiver_upstream_verification_events (replay_until);
