import type { AssurancePolicy } from './assurance-policy';

import type { RateBounds, RateDraft, RateOverrides } from './rate-limit-model';
/** The ceilings the server sends with a tenant settings document. */
export interface Limits {
  readonly max_authorization_code_lifetime_seconds: number;
  readonly max_access_token_lifetime_seconds: number;
}

/** One tenant's settings, as the admin API describes them. */
export interface Settings {
  readonly acr_policy?: AssurancePolicy;
  readonly tenant_id: string;
  readonly disabled_features: readonly string[];
  readonly authorization_code_lifetime_seconds: number;
  readonly access_token_lifetime_seconds: number;
  /** Optional while an older server may still be present during an upgrade. */
  readonly always_ask_consent?: boolean;
  /** Whether administrators may opt individual applications out of FAPI. */
  readonly allow_non_fapi_clients?: boolean;
  readonly session_policy?: { readonly idle_seconds: number; readonly absolute_seconds: number };
  readonly limits: Limits;
  readonly rate_limits?: RateOverrides;
  readonly rate_limit_bounds?: RateBounds;
  readonly effective_rate_limits?: RateBounds;
}

/** What the settings form holds while it is being edited. */
export interface Draft {
  readonly acrPolicy: AssurancePolicy | undefined;
  readonly disabled: readonly string[];
  readonly code: string;
  readonly token: string;
  readonly alwaysAskConsent: boolean;
  readonly allowNonFapiClients: boolean;
  readonly sessionIdle: string;
  readonly sessionAbsolute: string;

  readonly rateLimits: RateDraft;
}

/** The draft a freshly read document starts as. */
export function draftOf(settings: Settings): Draft {
  return {
    acrPolicy: settings.acr_policy,
    disabled: [...settings.disabled_features],
    code: String(settings.authorization_code_lifetime_seconds),
    token: String(settings.access_token_lifetime_seconds),
    alwaysAskConsent: settings.always_ask_consent ?? false,
    allowNonFapiClients: settings.allow_non_fapi_clients ?? false,
    sessionIdle: String(settings.session_policy?.idle_seconds ?? 3600),
    sessionAbsolute: String(settings.session_policy?.absolute_seconds ?? 43200),

    rateLimits: Object.fromEntries(Object.entries(settings.rate_limits ?? {}).map(([group, scopes]) =>
      [group, Object.fromEntries(Object.entries(scopes).map(([scope, max]) => [scope, String(max)]))])),
  };
}

/** Whether the draft differs from what the server last sent. */
export function isDirty(settings: Settings, draft: Draft): boolean {
  const sameFeatures =
    draft.disabled.length === settings.disabled_features.length &&
    draft.disabled.every((name) => settings.disabled_features.includes(name));
  return (
    draft.sessionIdle !== String(settings.session_policy?.idle_seconds ?? 3600) ||
    draft.sessionAbsolute !== String(settings.session_policy?.absolute_seconds ?? 43200) ||

    JSON.stringify(draft.acrPolicy) !== JSON.stringify(settings.acr_policy) ||
    !sameFeatures ||
    JSON.stringify(draft.rateLimits) !== JSON.stringify(draftOf(settings).rateLimits) ||
    draft.code !== String(settings.authorization_code_lifetime_seconds) ||
    draft.token !== String(settings.access_token_lifetime_seconds) ||
    draft.alwaysAskConsent !== (settings.always_ask_consent ?? false) ||
    draft.allowNonFapiClients !== (settings.allow_non_fapi_clients ?? false)
  );
}
