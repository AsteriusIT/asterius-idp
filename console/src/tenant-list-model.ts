/** Renders the feature summary carried by one tenant directory row. */
export function describeFeatures(disabled: readonly string[] | undefined): string {
  if (disabled === undefined) {
    // Compatibility with a rolling deployment where the console bundle has
    // reached a server from before the list document grew this member.
    return '—';
  }
  return disabled.length === 0
    ? 'all on'
    : `off: ${[...disabled].sort((left, right) => left.localeCompare(right)).join(', ')}`;
}

/** The OIDC Discovery document for a tenant. */
export function oidcDiscoveryUrl(issuer: string): string {
  return `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
}

/** A URL-valued member in an OIDC Discovery document. */
export interface OidcLink {
  readonly key: string;
  readonly url: string;
}

/** Extracts every endpoint or URI link advertised by the live document. */
export function oidcLinks(document: Record<string, unknown>): readonly OidcLink[] {
  return Object.entries(document)
    .filter(([key, value]) =>
      (key === 'issuer' || key.endsWith('_endpoint') || key.endsWith('_uri'))
      && typeof value === 'string'
      && value.length > 0,
    )
    .map(([key, value]) => ({ key, url: value as string }));
}
