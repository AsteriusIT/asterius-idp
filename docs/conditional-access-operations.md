# Conditional access operations

Conditional scopes add restrictions to the existing policy. Active scopes must
permit the selected application and enforcement boundary in addition to the base
policy. Report-only evaluates restrictions for inspection and preserves the base
decision; it never grants access denied by the base policy.

The policy editor shows scope modes, applications, boundaries and explicit required
facts. Rule conditions can require further facts. Stage report-only, simulate
representative cases and inspect missing evidence before staging active enforcement.
Staging changes only the editor draft. Publishing and history restoration require
`admin.policies:write`, confirmation and the reviewed whole-policy revision. The
console sends quoted `If-Match: "sha256:…"` or `If-None-Match: *` for first
publication. Conflicts preserve the draft and require reload and review, without
automatic retries. The storage layer atomically rejects unguarded conditional
additions, replacements and removals. Existing unscoped legacy publications retain
their compatibility contract.

Application sensitivity is administrator-owned and separate from registration.
The application editor reads its current classification UUID. Changes require
`admin.clients:write`, confirmation and that exact revision (or null for first
classification); conflicts require reload and review. An unclassified application
has absent sensitivity evidence. Removing classification can therefore deny scopes
that require it. Changes are audited.

## Inspecting trusted evidence

Simulation requires policy, user, application and resource read scopes. Select
records in the routed tenant, the resource operation (such as `read`) and a separate
server enforcement boundary (such as `refresh_token`). The boundary defaults to
`access_evaluation` and accepts only the nine supported production boundaries.
The stored policy revision binds the preview; a changed policy refuses the request.
The editor draft can be evaluated explicitly without being published.

Groups, roles and grants always come from current tenant records. No authentication
transaction is selected, so trusted assurance, authentication age and network zone
are absent. Device compliance is unavailable without a verified adapter. Sensitivity
comes from administrative client settings. Legacy base-policy context semantics
remain for report-only previews; active previews use the separately bound trusted
context. Aggregate grants do not become trusted assurance.

Operators can explicitly supply hypothetical assurance, relative authentication
age, sensitivity, named network zones and device compliance. Each fact can be known,
absent, stale, unavailable or invalid. Known values are bounded and typed; other
states carry no value. Unsupported assurance levels become invalid evidence.
Directory facts and source identities cannot be overridden. Every example is labelled
`hypothetical_operator_example`; it never enters production adapters, creates grants
or issues credentials. Generic context cannot populate the reserved trusted namespace.

Results report base and active decisions, matching scope modes and would-results,
required facts, missing evidence, attainable assurance remedies and fact sources.
They distinguish the stored snapshot revision from the evaluated document revision
(which can be an unpublished draft), and include ACR and client revisions without directory fact values
or condition literals. Missing required facts deny active scopes even inside `ANY`
or `NOT`. Remedies use the current attainable ACR ladder. Every response is
`enforced: false`: inspection provides no access authority.

Simulation audits and checks tenant/RBAC before lookups; validation refusals do not
echo submitted values. Publication and classification changes are separate audited
writes. Production enforcement obtains its own evidence and never consumes examples.
A hypothetical success proves policy behavior, not availability of a production source.

## Controlled acceptance

`ASTERIUS_BIN=/path/to/verified/asterius bash scripts/conditional-simulation-acceptance.sh`
creates a fresh database in the dedicated local fixture PostgreSQL, a TLS listener
on port 9461 and two isolated tenants. Real confidential FAPI/DPoP clients exercise
publication and inspection; the runner drops its database, stops its server and
removes private fixture files on exit. It rejects a non-loopback database base.
Do not point this acceptance at an existing deployment. The committed
[acceptance evidence](testing/conditional-access-simulation-evidence.json) distinguishes
these actual API checks from deterministic browser fixtures and targeted parser
compilation. It makes no claim of runtime instrumented fuzzing or a full local suite.
