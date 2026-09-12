/**
 * The navigation, and the authority each destination needs.
 *
 * Scope-aware navigation is a *usability* property and is written down here as
 * one: hiding a link the caller may not use spares them a 403 they cannot act
 * on. It is not a security control, and nothing here is trusted by the server
 * — every route re-checks the authority it declares
 * (`crates/admin-api/src/rbac.rs`), so a console that showed every link to
 * everybody would leak nothing but noise.
 */

/** How far a destination reaches, mirroring `admin_api::rbac::Reach`. */
export type Reach = 'tenant' | 'deployment';

/**
 * The headings the sidebar files the destinations under (`ast-gore` (3)).
 *
 * Nine flat links in one column is a list an administrator reads from the top
 * every time. The groups are what a screen is *about* rather than which API
 * serves it: Signing keys and Policy are both "what this tenant will accept"
 * though one is JOSE and the other Cedar, and Tenants sits beside Tenant
 * settings because both are the deployment looking at a tenant.
 *
 * `Overview` is a group of one, drawn without a heading: it is where the
 * console opens, and a heading above a single item says the item's name twice.
 */
export type Group = 'Overview' | 'Identities' | 'Security' | 'Signals' | 'Deployment';

/** The order the groups appear in, top to bottom. */
export const GROUPS: readonly Group[] = [
  'Overview',
  'Identities',
  'Security',
  'Signals',
  'Deployment',
];

/** One destination in the console. */
export interface Destination {
  /** The fragment route, without the `#`. */
  readonly route: string;
  /** What the link says. */
  readonly label: string;
  /** The authority needed to get anything out of it. */
  readonly reach: Reach;
  /**
   * The scope the screen's own first request declares.
   *
   * A screen is worth showing when the caller may make the call it opens with,
   * so this is that call's scope and not a category: Users opens by listing
   * accounts (`admin.users:read`), Tenant settings opens on a form that only
   * means something to somebody who may save it (`admin.tenants:write`).
   */
  readonly scope: string;
  /** The bead that fills the screen in. */
  readonly bead: string;
  /** Which heading the sidebar files it under (`ast-gore`). */
  readonly group: Group;
}

/**
 * What the caller may do, as `GET /session` reports it.
 *
 * Roles are deliberately absent. The server maps role to scopes
 * (`asterius_domain::Role::grants`) and reports the result; repeating the
 * mapping here would be a second answer to "what may a support agent see",
 * and the console's copy is the one that would be wrong.
 */
export interface HeldScopes {
  readonly scopes: readonly string[];
  readonly deployment_scopes: readonly string[];
}

/**
 * Every screen the console will have, in the order they appear.
 *
 * `bead` is what the placeholder in `App.tsx` names for a screen that is not
 * built yet, so it has to be a ticket somebody could go and read: a closed one
 * says "this shipped, where is it?" and a wrong one sends the reader to
 * somebody else's work. `ast-f7m.3` tagged Users with `ast-f7m.4` and Tenants
 * with `ast-f7m.6`, and both were wrong — `.4` had shipped as tenant settings
 * and `.6` is Users itself. The tags below are the ones that are true at
 * `ast-f7m.6`: Users, Clients, Signing keys and Tenant settings are built and
 * their tags are historical; Shared signals and Policy name open tickets. The
 * Tenants line named the *epic* for as long as no ticket carried that screen,
 * and names `ast-l5bl` now that one has built it.
 */
export const DESTINATIONS: readonly Destination[] = [
  { route: 'overview', label: 'Overview', reach: 'tenant', scope: 'admin.tenants:read', bead: 'ast-f7m.3', group: 'Overview' },
  { route: 'users', label: 'Users', reach: 'tenant', scope: 'admin.users:read', bead: 'ast-f7m.6', group: 'Identities' },
  { route: 'clients', label: 'Clients', reach: 'tenant', scope: 'admin.clients:read', bead: 'ast-f7m.5', group: 'Identities' },
  // Built by `ast-l5bl`, so the tag is historical like the four around it.
  // The line kept the *epic* while it was a placeholder, because no child
  // ticket carried a tenants screen and a placeholder naming a closed or
  // nonexistent ticket tells an administrator that a screen is arriving when
  // nobody is building it. One now does.
  //
  // The scope is the list's, `admin.tenants:read`, and the reach is the
  // deployment's: a tenant admin holds that scope over their own tenant and
  // must not be offered the deployment-wide list (see `reaches`). Creating a
  // tenant and suspending one ask for `admin.tenants:write` at the same reach,
  // and the screen hides those controls itself — the server refuses them
  // either way.
  { route: 'tenants', label: 'Tenants', reach: 'deployment', scope: 'admin.tenants:read', bead: 'ast-l5bl', group: 'Deployment' },
  { route: 'keys', label: 'Signing keys', reach: 'tenant', scope: 'admin.keys:read', bead: 'ast-f7m.7', group: 'Security' },
  // The screen opens by listing the streams (`admin.ssf:read`); the
  // dead-letter table beneath them is shown when the caller also holds
  // `admin.outbox:read`, and the buttons when it holds the write scopes.
  { route: 'ssf', label: 'Shared signals', reach: 'tenant', scope: 'admin.ssf:read', bead: 'ast-f7m.8', group: 'Signals' },
  // The trail and its export share one scope, `admin.audit:read`, held by the
  // auditor and the administrators and by nobody else (`ast-lh3.9`).
  { route: 'audit', label: 'Audit trail', reach: 'tenant', scope: 'admin.audit:read', bead: 'ast-f7m.8', group: 'Signals' },
  // The policy has its own scope: reading a tenant's lifetimes is not reading
  // its authorization model (`ast-pj0.4`). The screen opens by reading the
  // document, so `admin.policies:read` is what it asks for — an auditor holds
  // it, and the editor's buttons ask for `admin.policies:write` separately.
  { route: 'policy', label: 'Policy', reach: 'tenant', scope: 'admin.policies:read', bead: 'ast-f7m.9', group: 'Security' },
  // A form nobody may save is worse than an absent link, so the settings
  // screen asks for the write scope its only button needs.
  { route: 'settings', label: 'Tenant settings', reach: 'tenant', scope: 'admin.tenants:write', bead: 'ast-bfn', group: 'Deployment' },
];

/**
 * Whether `held` reaches `destination`.
 *
 * The two lists are kept apart on purpose: a scope string does not say how far
 * it reaches, and a tenant admin holding `admin.tenants:read` over its own
 * tenant must not be offered the deployment-wide tenant list.
 */
export function reaches(held: HeldScopes, destination: Destination): boolean {
  const granted =
    destination.reach === 'deployment' ? held.deployment_scopes : held.scopes;
  return granted.includes(destination.scope);
}

/** The destinations this caller's scopes may use. */
export function visibleTo(held: HeldScopes): readonly Destination[] {
  return DESTINATIONS.filter((destination) => reaches(held, destination));
}

/** One heading of the sidebar and what is under it. */
export interface Section {
  readonly group: Group;
  readonly destinations: readonly Destination[];
}

/**
 * The visible destinations, filed under their headings (`ast-gore` (3)).
 *
 * A group with nothing in it is dropped rather than drawn empty: a support
 * agent who reaches neither Tenants nor Tenant settings should see no
 * "Deployment" heading, for the same reason they see no link — a heading over
 * an empty column is a promise of screens that are not there.
 */
export function sectionsFor(held: HeldScopes): readonly Section[] {
  const visible = visibleTo(held);
  return GROUPS.map((group) => ({
    group,
    destinations: visible.filter((destination) => destination.group === group),
  })).filter((section) => section.destinations.length > 0);
}
