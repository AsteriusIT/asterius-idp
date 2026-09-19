/** Renders the feature summary carried by one tenant directory row. */
export function describeFeatures(disabled: readonly string[] | undefined): string {
  if (disabled === undefined) {
    // Compatibility with a rolling deployment where the console bundle has
    // reached a server from before the list document grew this member.
    return '—';
  }
  return disabled.length === 0 ? 'all on' : `off: ${[...disabled].sort().join(', ')}`;
}
