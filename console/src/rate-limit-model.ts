/** Settings may lower request maxima; deployment-owned windows never move. */
export type RateOverrides = Readonly<Record<string, Readonly<Record<string, number>>>>;
export type RateBounds = Readonly<Record<string, Readonly<Record<string, { readonly max: number; readonly window_seconds: number }>>>>;
export type RateDraft = Readonly<Record<string, Readonly<Record<string, string>>>>;

export function rateDocument(draft: RateDraft): RateOverrides {
  return Object.fromEntries(Object.entries(draft).map(([group, scopes]) => [group,
    Object.fromEntries(Object.entries(scopes).filter(([, value]) => value !== '').map(([scope, value]) => [scope, Number(value)])),
  ] as const).filter(([, scopes]) => Object.keys(scopes).length > 0));
}

export function rateError(value: string, maximum: number): string | null {
  if (value === '') return null;
  const number = Number(value);
  return !Number.isInteger(number) || number < 1 || number > maximum
    ? `Enter a whole number from 1 to ${maximum}, or leave empty to inherit the deployment limit.` : null;
}
