/** One client's registration, as `GET /clients/{client_id}` renders it. */
export interface ClientDocument {
  readonly client_id: string;
  readonly compliance_profile: 'fapi' | 'oidc';
  readonly status: string;
  readonly client_name: string;
  readonly application_type: string;
  readonly token_endpoint_auth_method: string;
  readonly redirect_uris: readonly string[];
  readonly post_logout_redirect_uris: readonly string[];
  readonly grant_types: readonly string[];
  readonly scope: string;
  readonly id_token_signed_response_alg: string;
  readonly userinfo_signed_response_alg?: string;
  readonly request_object_signing_alg?: string;
  readonly tls_client_certificate_bound_access_tokens?: boolean;
  readonly subject_type: string;
  readonly resources: readonly string[];
  readonly authorization_details_types: readonly string[];
  /** `ast-mqt`: whether this client's ID tokens carry the role claims. */
  readonly roles_in_id_token: boolean;
  readonly managed_groups_claim: boolean;
  readonly jwks?: unknown;
  readonly jwks_uri?: string;
  readonly sector_identifier_uri?: string;
  readonly dpop_bound_access_tokens?: boolean;
  readonly use_mtls_endpoint_aliases?: boolean;
  readonly tls_client_auth_subject_dn?: string;
  readonly tls_client_auth_san_dns?: string;
  readonly tls_client_auth_san_uri?: string;
  readonly tls_client_auth_san_ip?: string;
  readonly tls_client_auth_san_email?: string;
  readonly require_pushed_authorization_requests?: boolean;
  readonly response_types?: readonly string[];
  /** Returned only once when a shared secret is created or rotated. */
  readonly client_secret?: string;
  readonly client_secret_expires_at?: number;
}

/** RFC 8705 certificate identities, exactly one for PKI mutual TLS. */
export const TLS_SUBJECT_FIELDS = [
  'tls_client_auth_subject_dn', 'tls_client_auth_san_dns', 'tls_client_auth_san_uri',
  'tls_client_auth_san_ip', 'tls_client_auth_san_email',
] as const;
export type TlsSubjectField = typeof TLS_SUBJECT_FIELDS[number];

/** Inventory presentation; only the effective FAPI profile earns its badge. */
export function profilePresentation(profile: 'fapi' | 'oidc'): {
  readonly label: string;
  readonly fapiBadge: boolean;
} {
  return profile === 'fapi'
    ? { label: 'FAPI', fapiBadge: true }
    : { label: 'Standard OIDC', fapiBadge: false };
}

/** What the form holds while it is being edited. */
export interface Draft {
  readonly compliance_profile: 'fapi' | 'oidc';
  readonly token_endpoint_auth_method: string;
  readonly dpop_bound_access_tokens: boolean | null;
  readonly use_mtls_endpoint_aliases: boolean | null;
  readonly tls_subject_field: TlsSubjectField;
  readonly tls_subject_value: string;
  readonly client_name: string;
  readonly application_type: string;
  readonly redirect_uris: string;
  readonly post_logout_redirect_uris: string;
  readonly grant_types: readonly string[];
  readonly scope: string;
  readonly id_token_signed_response_alg: string;
  /** Empty means the optional registration member was absent. */
  readonly userinfo_signed_response_alg: string;
  /** Empty means the optional registration member was absent. */
  readonly request_object_signing_alg: string;
  /** `null` preserves an absent member from an older API document. */
  readonly tls_client_certificate_bound_access_tokens: boolean | null;
  readonly subject_type: string;
  readonly sector_identifier_uri: string;
  readonly jwks_uri: string;
  readonly jwks: string;
  readonly status: string;
  readonly roles_in_id_token: boolean;
  readonly managed_groups_claim: boolean;
}

/** One URI per line, which is how the textareas hold a list. */
export function linesOf(value: readonly string[]): string {
  return value.join('\n');
}

/** A textarea back into a list, dropping blank lines. */
export function listFrom(value: string): string[] {
  return value
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '');
}

/** The draft a freshly read document starts as. */
export function draftOf(document: ClientDocument): Draft {
  return {
    compliance_profile: document.compliance_profile ?? 'fapi',
    token_endpoint_auth_method: document.token_endpoint_auth_method,
    dpop_bound_access_tokens: document.dpop_bound_access_tokens ?? null,
    use_mtls_endpoint_aliases: document.use_mtls_endpoint_aliases ?? null,
    tls_subject_field: TLS_SUBJECT_FIELDS.find((field) => document[field] !== undefined) ?? 'tls_client_auth_subject_dn',
    tls_subject_value: TLS_SUBJECT_FIELDS.map((field) => document[field]).find((value) => value !== undefined) ?? '',
    client_name: document.client_name,
    application_type: document.application_type,
    redirect_uris: linesOf(document.redirect_uris),
    post_logout_redirect_uris: linesOf(document.post_logout_redirect_uris ?? []),
    grant_types: [...document.grant_types],
    scope: document.scope,
    id_token_signed_response_alg: document.id_token_signed_response_alg,
    userinfo_signed_response_alg: document.userinfo_signed_response_alg ?? '',
    request_object_signing_alg: document.request_object_signing_alg ?? '',
    tls_client_certificate_bound_access_tokens:
      document.tls_client_certificate_bound_access_tokens ?? null,
    subject_type: document.subject_type,
    sector_identifier_uri: document.sector_identifier_uri ?? '',
    jwks_uri: document.jwks_uri ?? '',
    jwks: document.jwks === undefined ? '' : JSON.stringify(document.jwks, null, 2),
    status: document.status,
    roles_in_id_token: document.roles_in_id_token === true,
    managed_groups_claim: document.managed_groups_claim === true,
  };
}

/** The draft a new client starts as: this profile's defaults, spelled out. */
export function emptyDraft(): Draft {
  return {
    compliance_profile: 'fapi',
    token_endpoint_auth_method: 'private_key_jwt',
    dpop_bound_access_tokens: true,
    use_mtls_endpoint_aliases: false,
    tls_subject_field: 'tls_client_auth_subject_dn',
    tls_subject_value: '',
    client_name: '',
    application_type: 'web',
    redirect_uris: '',
    post_logout_redirect_uris: '',
    grant_types: ['authorization_code'],
    scope: 'openid',
    id_token_signed_response_alg: 'EdDSA',
    userinfo_signed_response_alg: '',
    request_object_signing_alg: '',
    tls_client_certificate_bound_access_tokens: false,
    subject_type: 'public',
    sector_identifier_uri: '',
    jwks_uri: '',
    jwks: '',
    status: 'active',
    roles_in_id_token: false,
    managed_groups_claim: false,
  };
}

/** Authentication methods the setup form can offer for this profile/deployment. */
export function clientAuthenticationMethods(
  draft: Draft,
  discoveredMethods: readonly string[] = ['private_key_jwt'],
): string[] {
  return [
    ...(draft.compliance_profile === 'oidc' ? ['client_secret_basic'] : []),
    'private_key_jwt',
    'tls_client_auth',
    'self_signed_tls_client_auth',
  ].filter((method) => method === draft.token_endpoint_auth_method
    // Standard OIDC secret authentication is profile-gated by the server. It
    // need not appear in discovery, whose hardened defaults can advertise only
    // private_key_jwt even when this tenant explicitly enables Standard OIDC.
    || method === 'client_secret_basic'
    || discoveredMethods.includes(method));
}

/** Whether this authentication method itself sends a client certificate. */
function authenticationUsesMtls(method: string): boolean {
  return method === 'tls_client_auth' || method === 'self_signed_tls_client_auth';
}

/** Applies a security-profile selection without carrying incompatible mTLS metadata. */
export function changeComplianceProfile(
  draft: Draft,
  complianceProfile: Draft['compliance_profile'],
): Draft {
  const tokenEndpointAuthMethod = complianceProfile === 'oidc'
    ? 'client_secret_basic'
    : 'private_key_jwt';
  const bearerWasSelected = draft.dpop_bound_access_tokens === false
    && draft.tls_client_certificate_bound_access_tokens !== true;
  return {
    ...draft,
    compliance_profile: complianceProfile,
    token_endpoint_auth_method: tokenEndpointAuthMethod,
    jwks: complianceProfile === 'oidc' ? '' : draft.jwks,
    jwks_uri: complianceProfile === 'oidc' ? '' : draft.jwks_uri,
    tls_subject_value: '',
    dpop_bound_access_tokens: complianceProfile === 'fapi' && bearerWasSelected
      ? true
      : draft.dpop_bound_access_tokens,
    use_mtls_endpoint_aliases: authenticationUsesMtls(tokenEndpointAuthMethod)
      || draft.tls_client_certificate_bound_access_tokens === true,
  };
}

/** Applies a client-authentication selection and derives its mTLS metadata. */
export function changeClientAuthentication(draft: Draft, method: string): Draft {
  return {
    ...draft,
    token_endpoint_auth_method: method,
    tls_subject_value: method === 'tls_client_auth' ? draft.tls_subject_value : '',
    use_mtls_endpoint_aliases: authenticationUsesMtls(method)
      || draft.tls_client_certificate_bound_access_tokens === true,
  };
}

/** Applies the selected sender constraint and derives its mTLS metadata. */
export function changeSenderConstraint(draft: Draft, constraint: 'dpop' | 'mtls' | 'bearer'): Draft {
  const certificateBound = constraint === 'mtls';
  return {
    ...draft,
    dpop_bound_access_tokens: constraint === 'dpop',
    tls_client_certificate_bound_access_tokens: certificateBound,
    use_mtls_endpoint_aliases: certificateBound
      || authenticationUsesMtls(draft.token_endpoint_auth_method),
  };
}

/**
 * The registration document a draft posts.
 *
 * Optional security metadata is emitted only when the draft represents a
 * present value. This matters for older documents: a whole-document `PUT`
 * must not turn an absent member into a value merely because the console read
 * it. New drafts explicitly carry the server's safe certificate-binding
 * default (`false`). Unknown algorithms are ordinary strings here so a console
 * from an older release can preserve a value introduced by a newer server.
 *
 * Both key sources are preserved when supplied so the server can refuse the
 * conflict instead of silently selecting a source.
 *
 * @throws SyntaxError if the JWK Set box does not hold JSON.
 */
export function documentFrom(draft: Draft): Record<string, unknown> {
  const document: Record<string, unknown> = {
    compliance_profile: draft.compliance_profile,
    token_endpoint_auth_method: draft.token_endpoint_auth_method,
    require_pushed_authorization_requests: draft.compliance_profile === 'fapi',
    client_name: draft.client_name,
    application_type: draft.application_type,
    redirect_uris: listFrom(draft.redirect_uris),
    post_logout_redirect_uris: listFrom(draft.post_logout_redirect_uris),
    grant_types: [...draft.grant_types],
    scope: draft.scope,
    id_token_signed_response_alg: draft.id_token_signed_response_alg,
    subject_type: draft.subject_type,
    status: draft.status,
    roles_in_id_token: draft.roles_in_id_token,
    managed_groups_claim: draft.managed_groups_claim,
  };
  if (draft.dpop_bound_access_tokens !== null) {
    document.dpop_bound_access_tokens = draft.dpop_bound_access_tokens;
  }
  if (draft.use_mtls_endpoint_aliases !== null) {
    document.use_mtls_endpoint_aliases = draft.use_mtls_endpoint_aliases;
  }
  if (draft.tls_subject_value !== '') {
    document[draft.tls_subject_field] = draft.tls_subject_value;
  }
  if (draft.userinfo_signed_response_alg !== '') {
    document.userinfo_signed_response_alg = draft.userinfo_signed_response_alg;
  }
  if (draft.request_object_signing_alg !== '') {
    document.request_object_signing_alg = draft.request_object_signing_alg;
  }
  if (draft.tls_client_certificate_bound_access_tokens !== null) {
    document.tls_client_certificate_bound_access_tokens =
      draft.tls_client_certificate_bound_access_tokens;
  }
  if (draft.sector_identifier_uri.trim() !== '') {
    document.sector_identifier_uri = draft.sector_identifier_uri.trim();
  }
  if (draft.token_endpoint_auth_method !== 'client_secret_basic' && draft.jwks.trim() !== '') {
    document.jwks = JSON.parse(draft.jwks) as unknown;
  }
  if (draft.token_endpoint_auth_method !== 'client_secret_basic' && draft.jwks_uri.trim() !== '') {
    document.jwks_uri = draft.jwks_uri.trim();
  }
  return document;
}
