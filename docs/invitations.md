# Account invitations

Administrators with `admin.users:write` can send up to 50 invitations in one
`POST /admin/api/v1/invitations` request. Each entry names an email address,
an optional username, an `expires_at` Unix timestamp, and optional tenant role
and managed group IDs. The expiry must be between one minute and 24 hours from
issuance. Assigning roles also requires `admin.roles:write`; assigning groups
requires `admin.groups:write`. The API returns an invitation ID and a `queued`
status, never the token or a password. An unavailable address or username gets
the same `unavailable` result whether it belongs to an account or another
pending invitation.

`POST /admin/api/v1/invitations/{invitation_id}/resend` takes a fresh
`expires_at` and rotates the bearer token. `DELETE` on the same invitation URL
revokes it. A replaced, expired, revoked or used link shows the same generic
page. Each link is tenant bound, stores only a SHA-256 digest, and can be used
once. The invitation row and outgoing mail are queued in one transaction;
account creation, password storage, and approved assignments are committed in
another. The queued mail carries the exact expiry so the mail worker can drop
it after the link stops working.

Following the link opens a server-rendered page. Posting its CSRF-protected
form proves access to the mailbox and sets an initial password under the
server's password policy. Activation sets `email_verified=true`, records the
activation and assignments in the audit trail, **and does not create a
session**. The user signs in through the ordinary authentication flow, where
the tenant's assurance policy still applies. An invitation is refused if a
password-only sign-in reaches no level in that policy. If the policy changes
while a link is outstanding, the page directs the recipient to contact an
administrator for another onboarding path.
