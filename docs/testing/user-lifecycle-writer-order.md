# Current-human lifecycle serialization

`ast-0xgz` aligns lifecycle writers with the final current-human authority
reader from `ast-dd1y.9`. Writers acquire the same tenant row `FOR NO KEY UPDATE`
before locking an existing user or a source ownership row, and retain that lock
on the same transaction until commit. Final issuance holds the tenant row
`FOR SHARE`, then canonical clients, current users, and grant lineage. This
prevents both an unfenced account disable and the user/tenant inversion caused
by a lifecycle AFTER trigger acquiring the tenant lock too late.

Covered writers are user replacement/upsert/deletion, Console disable, SCIM
profile replacement/deactivation/deletion, LDAP snapshot application, and
inbound SSF AccountDisabled. LDAP takes the lock before its advisory run lock
because group changes and absence pruning share the snapshot transaction.
Other SSF actions do not change account status. Standalone verified-email and
OIDC display-name updates do not withdraw human lifecycle authority.

The tenant existence predicate permits cleanup of an inactive tenant. It does
not make an inactive tenant usable for issuance. Existing SCIM reserved-email
retirement, locked-account refusal, revision predicates, and notification
transactionality are preserved. Direct database lifecycle writers must obey the
same tenant-before-user order; an AFTER trigger alone cannot establish it.
This does not alter expiry of previously issued offline bearer tokens.

## Verification

The ignored PostgreSQL CI test
`lifecycle_writer_waits_before_user_lock_and_disable_is_visible_after_commit`
uses the actual user repository and signing fence. It observes actual PostgreSQL
lock waits, proves a pending writer has not acquired the user row, then reverses
the order and checks the reader sees disabled status after the writer commits.
It is selected explicitly in the ignored CI filter and is not run locally.

`scripts/testing/user-lifecycle-locks.py` provides a smaller structural SQL smoke
on an explicitly selected PostgreSQL instance. It creates a nonce schema,
exercises both lock orders, and drops its own schema in `finally`. The owned
PostgreSQL smoke passed all four checks on 2026-10-04: signer-first user remains
unlocked; disable commits; writer-first reader waits; post-wait status is current.
This SQL evidence does not claim to execute the Rust adapter. Worker compilation
and the final focused gate are delegated to the orchestrator's exclusive slot.
