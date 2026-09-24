# Changing an account email address

The signed-in account page at `/account/email` requires an authentication from
the previous two minutes before it accepts a replacement address. The old
address remains in `users.email`, remains the recovery destination, and is the
address reported to OIDC clients until the new mailbox confirms a fifteen
minute link. The token is tenant scoped, stored only as a digest, supersedes
earlier pending links, and can be used once.

Confirmation atomically moves the address and sets `email_verified=true`.
Uniqueness is case-insensitive within a tenant. A concurrent claim of the same
new address, a disabled account, or a changed old address leaves the pending
link unusable. The confirmation route creates no session. A verified old
address receives a link-free security notice in the same database transaction
as the change. Request, success, and refusal are audited without recording
the token or either mailbox address in audit details.

If the old mailbox is unavailable, a tenant administrator can update the
account through the existing user administration API. The administrator should
set `email_verified=false` until the new mailbox is independently verified;
an administrative change does not turn an unproven address into a verified
OIDC claim. Self-service confirmation invalidates older verification links;
the verification handler also checks the current address before asserting a
claim.
