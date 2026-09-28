# Console access and recovery review

Reviewed 2026-09-28 for `ast-ynzi`. This review covers every registered console
section and the shared navigation, help, and confirmation components.

## Findings and changes

| Area | Review result |
| --- | --- |
| Shell and navigation | Denied routes explain unavailable access; unknown routes show a missing-page screen. Startup failures can retry. Failed sign-out remains visible. |
| Users and external providers | External provider names appear in the directory. Provider settings expose the signed username claim and explain synchronization. Linked identities clear stale account state, confirm changes, and send only accepted identity fields on unlink. |
| Groups and roles | Membership removal, role withdrawal, and role deletion require confirmation. Existing read and write scopes remain authoritative. |
| Applications and resources | Client-secret revocation requires confirmation. Application, resource, SCIM, and authorization-detail controls retain their existing scope checks. |
| Architecture editor | Unsaved navigation and diagram object removal use the shared confirmation dialog; editor shortcuts pause while it has focus. |
| Signing keys | Rotation and retirement controls require key-write permission; immediate signing and retirement require confirmation. Read-only access retains public-key visibility. |
| Federation, SAML, and access policy | Existing write-scope checks and loading/error states reviewed. |
| Shared signals and mail | Dead-letter deletion, inbound-subject removal, and invitation revocation require confirmation; invitation errors provide retry. |
| Overview and audit | Metrics retain independent read scopes and loading/error/empty states. Audit remains read-only. |
| Tenants, settings, branding, and preferences | Deployment administration stays deployment-scoped. Settings and branding retain write checks; preferences remain local to the browser. |
| Help | Change instructions require the corresponding write scopes. Review instructions remain available to readers. |

External sign-in failures now render a tenant-themed page, with a safe return
link for a live browser-bound interaction or instructions to restart from the
application. The page provides a support reference and excludes upstream error
descriptions, callback state, and tokens.

## Responsibility boundaries

The UI reflects existing server-enforced permissions: directory administration,
application access, key management, and deployment administration retain their
separate scopes. Hiding an action is presentation, not authorization. This work
does not introduce a second-person approval system or a new backend role model.

The review follows [OWASP authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
on least privilege and server-side enforcement, and W3C guidance on
[identifying errors](https://www.w3.org/WAI/WCAG22/Understanding/error-identification)
and [explaining recovery](https://www.w3.org/WAI/WCAG21/Understanding/error-suggestion).

## Verification scope

Console production build and Node tests cover component models and routing.
Focused browser checks cover inaccessible/unknown routes, key-reader controls,
identity-link confirmations, membership removal, key rotation, account creation,
and external error recovery with and without JavaScript. The error page also
receives an automated accessibility check. This is not a claim of a complete
WCAG conformance audit or a full browser regression run.
