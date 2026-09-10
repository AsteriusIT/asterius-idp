/**
 * The navigation, and the authority each destination needs.
 *
 * Role-aware navigation is a *usability* property and is written down here as
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
  /** The bead that fills the screen in. */
  readonly bead: string;
}

/**
 * The role names the schema knows (`crates/domain/src/entities/role.rs`).
 *
 * A closed set on the server, so a closed set here: an unknown role grants
 * nothing rather than being guessed at.
 */
const TENANT_ADMIN = 'tenant_admin';
const DEPLOYMENT_ADMIN = 'deployment_admin';

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
  { route: 'overview', label: 'Overview', reach: 'tenant', bead: 'ast-f7m.3' },
  { route: 'users', label: 'Users', reach: 'tenant', bead: 'ast-f7m.6' },
  { route: 'clients', label: 'Clients', reach: 'tenant', bead: 'ast-f7m.5' },
  // The epic and not a child ticket: no bead carries a tenants screen, and
  // the two spellings this line has had — `ast-f7m.6`, which is the *users*
  // screen — were both wrong. A placeholder naming a closed or nonexistent
  // ticket tells an administrator that a screen is arriving when nobody is
  // building it, so this one names the epic until a ticket exists.
  { route: 'tenants', label: 'Tenants', reach: 'deployment', bead: 'ast-f7m' },
  { route: 'keys', label: 'Signing keys', reach: 'tenant', bead: 'ast-f7m.7' },
  { route: 'ssf', label: 'Shared signals', reach: 'tenant', bead: 'ast-f7m.8' },
  { route: 'policy', label: 'Policy', reach: 'tenant', bead: 'ast-f7m.9' },
  { route: 'settings', label: 'Tenant settings', reach: 'tenant', bead: 'ast-bfn' },
];

/** Whether `roles` reach `destination`. */
export function reaches(roles: readonly string[], destination: Destination): boolean {
  const deployment = roles.includes(DEPLOYMENT_ADMIN);
  if (destination.reach === 'deployment') {
    return deployment;
  }
  return deployment || roles.includes(TENANT_ADMIN);
}

/** The destinations these roles may use. */
export function visibleTo(roles: readonly string[]): readonly Destination[] {
  return DESTINATIONS.filter((destination) => reaches(roles, destination));
}
