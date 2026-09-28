/** Public provider metadata returned by the tenant admin API. */
export interface OidcProvider {
  readonly id: string;
  readonly name: string;
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly jwks_uri: string;
  readonly client_id: string;
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
  readonly clientSecret: string;
  readonly enabled: boolean;
  readonly allowRegistration: boolean;
}

/** Omitted secret means preserve the stored credential during an edit. */
export function providerCommand(draft: ProviderDraft): Record<string, string | boolean> {
  return {
    id: draft.id.trim(),
    name: draft.name.trim(),
    issuer: draft.issuer.trim(),
    client_id: draft.clientId.trim(),
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
    clientSecret: '',
    enabled: provider.enabled,
    allowRegistration: provider.allow_registration,
  };
}
