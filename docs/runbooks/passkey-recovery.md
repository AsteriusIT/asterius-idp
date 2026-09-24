# Passkey-only account recovery

An email address is a contact, not a substitute for a user-verified passkey.
An account with at least one recorded passkey and no active password cannot
receive or use a password-reset link. This includes accounts whose passkeys
have been disabled. The request page always gives the same response and asks
the person to contact their organization's account administrator.

## Support procedure

1. Ask whether the person has another registered passkey. If so, sign in with
   it, register a replacement at `/passkeys`, then remove the lost credential
   from `/account/passkeys`. A session authenticated with a passkey retains its
   normal ACR; a recovery request does not create a session.
2. If no registered passkey works, use the organization's identity-verification
   procedure outside this product. Do not treat the recovery email, an admin
   session, or possession of the old mailbox as passkey-level evidence. The
   forced password-reset action will refuse this account.
3. Where policy allows replacement, provision a new account through the normal
   invitation or registration route and have the person enrol a new passkey.
   Revoke the old account's sessions and grants and disable the old account
   using the administration console. Review relying-party account links before
   transferring access; this product does not silently relink subjects.
4. If identity cannot be established or replacement is not permitted, leave
   the old account disabled or inaccessible and explain that support cannot
   restore access. Record the decision in the organization's case system.

## Failure and notification states

Recovery requests for unknown, disabled and passkey-only accounts render the
same page. A passkey-only refusal is recorded as `recovery.refused` with reason
`passkey_only`; a prior verified email receives a link-free
`recovery_refused` notice. Unverified or absent contact details receive no
security email. Mail delivery status is visible in the tenant's notification
status API; a queued notice is not evidence of delivery. An expired or already
spent link cannot be used. A store failure fails closed and must be resolved
before trying again.

Ordinary password recovery revokes all live sessions and notifies participating
relying parties; existing grants follow their separate revocation policy.
Passkey-only refusal changes neither credentials nor sessions nor grants. When
support replaces an account, the operator must revoke its sessions and grants
as part of the replacement procedure.
