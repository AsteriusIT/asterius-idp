/** Browser-side courtesy checks; the Rust API remains authoritative. */
export function audienceError(value: string): string | null {
  if (value.length === 0 || value.length > 512 || value.includes('#')) {
    return 'Enter an absolute URL without a fragment.';
  }
  try {
    const parsed = new URL(value);
    return parsed.host.length === 0 ? 'Enter an absolute URL with a host.' : null;
  } catch {
    return 'Enter an absolute URL with a host.';
  }
}

export function parseScopes(value: string): readonly string[] {
  return [...new Set(value.split(/\s+/u).map(scope => scope.trim()).filter(Boolean))].sort();
}

export function scopesError(value: string): string | null {
  const invalid = parseScopes(value).find(scope => scope.length > 128 || !/^[!#-\[\]-~]+$/u.test(scope));
  return invalid === undefined ? null : `'${invalid}' is not an OAuth scope token.`;
}

export function lifetimeError(value: string): string | null {
  if (value.length === 0) return null;
  return /^(?:[1-9]\d*)$/u.test(value) && Number(value) <= 86_400
    ? null
    : 'Enter a whole number from 1 to 86400 seconds, or leave it empty.';
}

export function parseLifetime(value: string): number | null {
  return value.length === 0 ? null : Number(value);
}

/** One client id per line: unlike scopes, OAuth client ids may contain spaces. */
export function parseIntrospectionClients(value: string): readonly string[] {
  return [...new Set(value.split(/\r?\n/u).map(client => client.trim()).filter(Boolean))].sort();
}

export function introspectionClientsError(value: string): string | null {
  const invalid = parseIntrospectionClients(value).find(client =>
    client.length > 512 || [...client].some(character => /[\u0000-\u001f\u007f]/u.test(character)),
  );
  return invalid === undefined ? null : 'Client ids must be at most 512 characters and contain no control characters.';
}
