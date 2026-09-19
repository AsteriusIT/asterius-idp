/** The ceilings the server sends with a tenant settings document. */
export interface Limits {
  readonly max_authorization_code_lifetime_seconds: number;
  readonly max_access_token_lifetime_seconds: number;
}

/** One tenant's settings, as the admin API describes them. */
export interface Settings {
  readonly tenant_id: string;
  readonly disabled_features: readonly string[];
  readonly authorization_code_lifetime_seconds: number;
  readonly access_token_lifetime_seconds: number;
  /** Optional while an older server may still be present during an upgrade. */
  readonly always_ask_consent?: boolean;
  readonly limits: Limits;
}

/** What the settings form holds while it is being edited. */
export interface Draft {
  readonly disabled: readonly string[];
  readonly code: string;
  readonly token: string;
  readonly alwaysAskConsent: boolean;
}

/** The draft a freshly read document starts as. */
export function draftOf(settings: Settings): Draft {
  return {
    disabled: [...settings.disabled_features],
    code: String(settings.authorization_code_lifetime_seconds),
    token: String(settings.access_token_lifetime_seconds),
    alwaysAskConsent: settings.always_ask_consent ?? false,
  };
}

/** Whether the draft differs from what the server last sent. */
export function isDirty(settings: Settings, draft: Draft): boolean {
  const sameFeatures =
    draft.disabled.length === settings.disabled_features.length &&
    draft.disabled.every((name) => settings.disabled_features.includes(name));
  return (
    !sameFeatures ||
    draft.code !== String(settings.authorization_code_lifetime_seconds) ||
    draft.token !== String(settings.access_token_lifetime_seconds) ||
    draft.alwaysAskConsent !== (settings.always_ask_consent ?? false)
  );
}
