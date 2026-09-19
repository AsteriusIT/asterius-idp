/** One audience returned by the tenant's resource-server registry. */
export interface ResourceServerSummary {
  readonly identifier: string;
}

/** One checkbox in the client resource-policy editor. */
export interface ResourceChoice {
  readonly identifier: string;
  readonly registered: boolean;
}

/** Registered audiences plus stale assignments an operator must be able to remove. */
export function resourceChoices(
  registered: readonly ResourceServerSummary[],
  selected: readonly string[],
): readonly ResourceChoice[] {
  const available = new Set(registered.map((resource) => resource.identifier));
  return [...new Set([...available, ...selected])]
    .sort((left, right) => left.localeCompare(right))
    .map((identifier) => ({ identifier, registered: available.has(identifier) }));
}
