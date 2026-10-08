# Disposable native Entra approval proposal

Prepared only: no application, service principal, job, source identity or assignment
has been created. Read-only `az account show` confirmed ASTERIUS_DEV in tenant
`f3b3c6c2-ac86-462e-b68e-cfbed01ead3d`, AzureCloud; the Custom template GET confirmed
its ID and sync capability. [native-graph-proposal.json](native-graph-proposal.json)
contains the concrete app/job/secret request bodies and bounded mapping objects.
Replace placeholders through private 0600 body files, never shell arguments/logs.

The proposed first authorization creates one nonce-named application and its service
principal via the Custom template, and one modern `scim` synchronization job. Inspect
available templates; abort if `scim` is absent rather than silently using legacy
`customappsso`. The created job must remain Disabled. Validate credentials through
this adapter's exact public HTTPS base, then configure only its isolated opaque
credential. No Asterius Bearer route or relaxation of backend DPoP/If-Match occurs.
The fixture credential expires after 24 hours and is revoked at cleanup; the proposed
cloud fixture lives at most four hours and requires a cleanup supervisor/recovery
manifest, since Graph app/job objects do not automatically expire.

The current operator's delegated Graph authorization needs Application.ReadWrite.All
for template instantiation and Synchronization.ReadWrite.All for job/schema/secret
operations, plus an applicable Application Administrator/Cloud Application
Administrator or supported ownership/custom role. These are operator permissions,
not permissions to grant to the disposable SCIM app. Do not add API permissions,
app secrets, admin consent or tenant roles to that app. Do not elevate the current
account automatically if an operation is denied. An already separately provisioned
application automation identity can instead use Application.ReadWrite.OwnedBy for
its own app; this proposal does not create such an identity.

After creating the disabled job, GET its complete schema and save the original.
Graph PUT fully replaces that schema: retain connector directories, IDs and required
metadata, replace only the User/Group attribute mappings with the manifest mappings,
disable every other object mapping, then inspect the exact complete replacement
before sending. Attribute target names/types must exist in the returned schema;
`active` must be Boolean, and members must retain the User reference type. Native
accountEnabled is mapped directly, without expressions that emit string booleans.
The full instantiated schema cannot be prepared before the approved job exists.

Set SyncAll=false and appRoleAssignmentRequired=true. Credential validation alone
is not full acceptance. A separate full-lifecycle scope needs two disposable cloud
users, one disposable security group, their memberships and assignments only to
this app, plus one dedicated disposable Asterius tenant/client/adapter state. New
users use a tenant-verified domain selected read-only at execution, random private
passwords and no assigned licenses. Never assign or mutate existing directory
users/groups. This extra scope needs delegated User.ReadWrite.All, Group.ReadWrite.All
and AppRoleAssignment.ReadWrite.All (with their supported operator roles); creating
fixture users/groups does not grant those permissions to the app. The actual source
identity/assignment bodies must be reviewed after selecting the domain and returned
app role ID. If these writes are not approved, keep the job disabled and report
validation-only evidence.

For lifecycle approval, run only the owned assigned scope: create, update, group
membership, disable, delete and retries; verify native missing If-Match uses one
owned read/CAS, racing412, locked409, foreign404 and expired/revoked adapter credential.
No scheduled start before this scope is approved. Delete only exact IDs from the
nonce-owned recovery manifest in the listed order, verify deletion, and retain the
manifest when cleanup fails. Sanitize evidence to IDs, methods, statuses and counts;
never retain authorization headers, tokens, passwords or private keys. Existing
harness `scripts/scim/entra_acceptance.py` is the old direct-DPoP incompatibility
probe and must not be reused as current adapter certification.

Sources: [template instantiation](https://learn.microsoft.com/en-us/graph/api/applicationtemplate-instantiate?view=graph-rest-1.0),
[job creation](https://learn.microsoft.com/en-us/graph/api/synchronization-synchronization-post-jobs?view=graph-rest-1.0),
[full schema replacement](https://learn.microsoft.com/en-us/graph/api/synchronization-synchronizationschema-update?view=graph-rest-1.0),
[attribute mapping types](https://learn.microsoft.com/en-us/graph/api/resources/synchronization-attributemapping?view=graph-rest-1.0).
