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
 * The six that are `bead`-tagged are the children of `ast-f7m`; this scaffold
 * mounts the shell around them and each one fills its own in.
 */
export const DESTINATIONS: readonly Destination[] = [
  { route: 'overview', label: 'Overview', reach: 'tenant', bead: 'ast-f7m.3' },
  { route: 'users', label: 'Users', reach: 'tenant', bead: 'ast-f7m.4' },
  { route: 'clients', label: 'Clients', reach: 'tenant', bead: 'ast-f7m.5' },
  { route: 'tenants', label: 'Tenants', reach: 'deployment', bead: 'ast-f7m.6' },
  { route: 'keys', label: 'Keys', reach: 'tenant', bead: 'ast-f7m.7' },
  { route: 'ssf', label: 'Shared signals', reach: 'tenant', bead: 'ast-f7m.8' },
  { route: 'policy', label: 'Policy', reach: 'tenant', bead: 'ast-f7m.9' },
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
