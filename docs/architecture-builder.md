# Visual identity architecture builder

Status: the first tenant-scoped builder is implemented. Saving a draft changes
only the diagram. **Preview changes** checks live resources and returns a
revision-bound digest; **Apply changes** explicitly provisions supported
nodes and connections.

The implemented catalog provisions FAPI web applications, APIs with scopes,
groups, application roles, application-to-API access, and group-to-role grants.
An application needs its JWKS URI and redirect URIs before it can be applied.
The server rejects secrets in node settings. Stream and external identity
provider nodes document architecture only; they do not configure integrations.

## Operator journey

1. Open **Architecture flows** for the active tenant. Start from a blank canvas
   or a template such as **Web app + API**.
2. Add typed nodes for a web application, API/resource server, group, role and
   supported signal integration. Inspect each node in a labelled form. A node
   either describes a resource to create or references an existing resource.
3. Connect nodes with named relationships, such as **app calls API**, **role
   belongs to app**, **group grants role** or **stream sends events to receiver**.
   The canvas rejects obviously invalid connections and explains why. The
   server performs the same validation on save and apply.
4. Save a draft without changing live identity resources. **Preview changes**
   shows create, update, retry, reference, unchanged, attach, conflict, document, and
   detached operations. The operator explicitly applies that exact digest.
5. The flow shows its applied revision and the last apply error. A failed apply
   can leave earlier steps complete; preview again before retrying. Its linked
   resource list shows node and resource IDs, including objects removed from
   the draft that remain live. Resource screens link back to their flow.

The Web app + API template supplies the graph shape; the operator fills in
tenant-specific identifiers and credentials before applying. The canvas does
not treat a drawn external identity provider as connected.

## Graph model

React Flow (`@xyflow/react`) supplies custom node rendering, interaction and
layout persistence. The product schema is an Asterius-owned, versioned graph;
the raw React Flow JSON is not an authorization or provisioning instruction.
Store semantic node IDs, node types and validated configuration separately
from coordinates, viewport and cosmetic edge paths. This keeps a dragged node
from changing infrastructure and lets future UI versions read old diagrams.

Every edge has a typed relation. The backend validates allowed source and
target types, tenant scope, unique names, multiplicity and cycles where they
would be nonsensical. Examples:

| Relation | Source → target | Provisioning meaning |
| --- | --- | --- |
| `calls` | Web app → API | Assign the API resource and selected scopes to the client. |
| `defines_role` | Application → role | Create or reference an application role under that owner. |
| `grants` | Group → role | Assign the role to the group. |
| `delivers` | Stream → receiver | Configure a supported Shared Signals relationship once its API exposes the full contract. |

A flow is tenant-scoped and has a stable ID, name, description, revision,
schema version, editor, timestamps and a saved graph. Layout edits may change
the draft revision but produce an empty provisioning diff. Optimistic revision
checks prevent one operator from overwriting another's draft.

## Resource origin and ownership

Keep origin metadata in a separate tenant-scoped relation rather than adding
`flow_id` columns to every resource table:

```
flow_resource_links(
  tenant_id, flow_id, node_id, resource_kind, resource_id,
  relation, created_at, created_in_revision, last_applied_revision
)
```

`relation` is **managed** for a resource created by the flow and **reference**
for an existing resource selected by an operator. A live resource has at most
one managed origin; several flows may reference it. The managed origin is
durable even if someone later edits the resource outside the builder. The
flow then reports drift against the last applied specification. A rename does
not change the resource ID or erase its origin.

Removing a node from a draft does not delete its live resource. Preview marks
it **detached**. Deletion and flow archival are future operations; use the
ordinary resource screens for explicit deletion. Provenance survives diagram
edits.

## Planning and applying

The browser sends a graph revision, not a sequence of arbitrary admin API
calls. A server-side compiler resolves references, checks the current resource
revisions and the caller's permission for *every* planned operation, and
returns a bounded plan with explanations. Applying requires that exact plan
digest and graph revision, so edits or drift between preview and apply force a
fresh preview.

The apply runner records each operation with a stable flow/node link. It
creates resources through the tenant's existing domain model and records
their IDs in `flow_resource_links`. It retains the last fully applied graph.
Later node edits preview as updates only while flow-managed fields on the live
resource still match that graph; manual changes to those fields appear as
conflicts. Updates use conditional writes
and preserve resource origin. The runner resumes safely after interruption.
Some operations span multiple tables or external effects, so an interrupted
apply can be partial. The UI shows completed, pending and refused operations
and offers a safe retry; it never reports the whole flow as applied while one
operation remains. Concurrent applies of one flow are serialized.

The server enforces tenant isolation for both the graph and every referenced
resource. The graph grants no privileges by itself: the operator needs the
existing write scope for each operation. Apply, detach, conflict and failure
are audited with the flow and revision. Secret values stay in dedicated
write-only credential controls, never in node JSON, export files, URL
parameters or React Flow state.

## Console behavior

Each node has a readable title, resource state and direct link. A side panel
shows fields and errors instead of squeezing forms into a small card. Preview
uses a table as well as colored graph markers, so the result is usable without
relying on color or precise dragging. Provide keyboard access, a structured
list view of the same graph, zoom controls, undo/redo for draft edits, and a
clear distinction between **Save draft** and **Apply changes**.

The first release needs a small typed catalog and a reliable apply loop. Later
templates can use the same graph and provenance model for identity providers,
provisioning, policies and event streams, after those services expose the
required setup operations.

React Flow's current package is [`@xyflow/react`](https://reactflow.dev/learn).
Its [custom nodes](https://reactflow.dev/learn/customization/custom-nodes),
[connection validation](https://reactflow.dev/examples/interaction/validation)
and [JSON flow format](https://reactflow.dev/api-reference/types/react-flow-json-object)
cover the canvas mechanics; the server owns the product semantics above.
