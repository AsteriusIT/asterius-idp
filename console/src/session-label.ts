import type { Session } from './api';

/** Display the roles the session reports; permission checks still use scopes. */
export function sessionRoleLabel(session: Session): string {
  return session.roles.length > 0
    ? session.roles.map((role) => role.replace(/[_-]/g, ' ')).join(', ')
    : 'No assigned role';
}
