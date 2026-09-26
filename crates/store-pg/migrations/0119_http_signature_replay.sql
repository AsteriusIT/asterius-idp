alter table jti_replay drop constraint jti_replay_purpose_check;
alter table jti_replay add constraint jti_replay_purpose_check
    check (purpose in ('client_assertion', 'dpop_proof',
                      'admin_idempotency', 'http_signature'));
