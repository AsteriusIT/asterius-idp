/** Public provider metadata returned by the tenant admin API. */
export interface OidcProvider {
  readonly id: string;
  readonly name: string;
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly jwks_uri: string;
  readonly client_id: string;
  readonly username_claim: string | null;
  readonly enabled: boolean;
  readonly allow_registration: boolean;
  readonly secret_configured: boolean;
  readonly callback_url: string;
  readonly created_at: string;
}

export interface ProviderDraft {
  readonly id: string;
  readonly name: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly usernameClaim: string;
  readonly clientSecret: string;
  readonly enabled: boolean;
  readonly allowRegistration: boolean;
}

/** Omitted secret means preserve the stored credential during an edit. */
export function providerCommand(draft: ProviderDraft): Record<string, string | boolean | null> {
  return {
    id: draft.id.trim(),
    name: draft.name.trim(),
    issuer: draft.issuer.trim(),
    client_id: draft.clientId.trim(),
    username_claim: draft.usernameClaim.trim() || null,
    enabled: draft.enabled,
    allow_registration: draft.allowRegistration,
    ...(draft.clientSecret ? { client_secret: draft.clientSecret } : {}),
  };
}

export function draftFor(provider: OidcProvider): ProviderDraft {
  return {
    id: provider.id,
    name: provider.name,
    issuer: provider.issuer,
    clientId: provider.client_id,
    usernameClaim: provider.username_claim ?? '',
    clientSecret: '',
    enabled: provider.enabled,
    allowRegistration: provider.allow_registration,
  };
}
