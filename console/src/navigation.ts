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
 * their tags are historical; Shared signals and Policy name open tickets; and
 * Tenants names the epic, because no ticket carries it.
 */
export const DESTINATIONS: readonly Destination[] = [
  { route: 'overview', label: 'Overview', reach: 'tenant', scope: 'admin.tenants:read', bead: 'ast-f7m.3' },
  { route: 'users', label: 'Users', reach: 'tenant', scope: 'admin.users:read', bead: 'ast-f7m.6' },
  { route: 'clients', label: 'Clients', reach: 'tenant', scope: 'admin.clients:read', bead: 'ast-f7m.5' },
  // The epic and not a child ticket: no bead carries a tenants screen, and
  // the two spellings this line has had — `ast-f7m.6`, which is the *users*
  // screen — were both wrong. A placeholder naming a closed or nonexistent
  // ticket tells an administrator that a screen is arriving when nobody is
  // building it, so this one names the epic until a ticket exists.
  { route: 'tenants', label: 'Tenants', reach: 'deployment', scope: 'admin.tenants:read', bead: 'ast-f7m' },
  { route: 'keys', label: 'Signing keys', reach: 'tenant', scope: 'admin.keys:read', bead: 'ast-f7m.7' },
  // The screen opens by listing the streams (`admin.ssf:read`); the
  // dead-letter table beneath them is shown when the caller also holds
  // `admin.outbox:read`, and the buttons when it holds the write scopes.
  { route: 'ssf', label: 'Shared signals', reach: 'tenant', scope: 'admin.ssf:read', bead: 'ast-f7m.8' },
  // The trail and its export share one scope, `admin.audit:read`, held by the
  // auditor and the administrators and by nobody else (`ast-lh3.9`).
  { route: 'audit', label: 'Audit trail', reach: 'tenant', scope: 'admin.audit:read', bead: 'ast-f7m.8' },
  { route: 'policy', label: 'Policy', reach: 'tenant', scope: 'admin.tenants:read', bead: 'ast-f7m.9' },
  // A form nobody may save is worse than an absent link, so the settings
  // screen asks for the write scope its only button needs.
  { route: 'settings', label: 'Tenant settings', reach: 'tenant', scope: 'admin.tenants:write', bead: 'ast-bfn' },
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
