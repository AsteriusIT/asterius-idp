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
