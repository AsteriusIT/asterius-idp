# Exact grant linkage across session lookup rotation

Cookie rotation now moves grant lookup references in the same transaction after
winning the live session update. It selects only the exact tenant, user and old
private digest. Original grant authentication and assurance evidence stay frozen.
A private `grant_session_lineage` association attests the original stable public
SID. Proof preservation requires that same SID under the new lookup digest;
an unrelated same-user session cannot supply it. An unproven pure lookup
reassignment discards proof and lineage. Session or grant deletion cascades the
private association; the original grant assurance evidence still survives
ordinary session cleanup.

Controlled source SQL smoke passed against a fresh nonce database on local
PostgreSQL5433, applying all source migrations. It checked byte-identical frozen
proof after a new session proof, exact linkage movement, an untouched independent
same-user grant, unrelated session reassignment denial, and deletion cascades.
Run `python3 scripts/session-rotation-lineage-smoke.py` with the explicitly local
acceptance database base to reproduce. The harness always drops its own database.
The initial harness attempt failed a client key-source check; the fixture was
corrected to register an explicit empty JWKS, without changing production checks.

The new ignored PostgreSQL regression additionally checks a different user's
grant and a losing repeat rotation. CI selects it explicitly. It has not run
locally; Rust check/final targeted verification and actual online code/refresh
rotation acceptance remain pending the root's composition gate. No fresh human
ceremony is established by this SQL-only evidence.
