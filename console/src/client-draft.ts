/** One client's registration, as `GET /clients/{client_id}` renders it. */
export interface ClientDocument {
  readonly client_id: string;
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
  readonly jwks?: unknown;
  readonly jwks_uri?: string;
  readonly sector_identifier_uri?: string;
}

/** What the form holds while it is being edited. */
export interface Draft {
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
  };
}

/** The draft a new client starts as: this profile's defaults, spelled out. */
export function emptyDraft(): Draft {
  return {
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
 * `jwks` is parsed into an object and takes precedence over `jwks_uri`, matching
 * the existing form behaviour.
 *
 * @throws SyntaxError if the JWK Set box does not hold JSON.
 */
export function documentFrom(draft: Draft): Record<string, unknown> {
  const document: Record<string, unknown> = {
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
  };
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
  if (draft.jwks.trim() !== '') {
    document.jwks = JSON.parse(draft.jwks) as unknown;
  } else if (draft.jwks_uri.trim() !== '') {
    document.jwks_uri = draft.jwks_uri.trim();
  }
  return document;
}
