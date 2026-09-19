import type { ClientDocument, Draft } from './client-draft';

export interface ClientDiscovery {
  readonly issuer: string;
  readonly token_endpoint_auth_methods_supported: readonly string[];
  readonly mtls_endpoint_aliases?: Readonly<Record<string, string>>;
}

/** Discovery comes from this workspace, never a URL supplied in client metadata. */
export async function readClientDiscovery(): Promise<ClientDiscovery> {
  const response = await fetch('../.well-known/openid-configuration', {
    credentials: 'same-origin', redirect: 'error', headers: { Accept: 'application/json' },
  });
  if (!response.ok) throw new Error('Discovery could not be read. Reload to retry.');
  const body = await response.json() as ClientDiscovery;
  const issuer = new URL(body.issuer);
  if (issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.search || issuer.hash
    || !Array.isArray(body.token_endpoint_auth_methods_supported)) {
    throw new Error('Discovery is incomplete. Check this tenant’s issuer configuration.');
  }
  return body;
}

/** Export an explicit allowlist from saved metadata; never serialize arbitrary API members or keys. */
export function clientConfiguration(saved: ClientDocument, discovery: ClientDiscovery): Record<string, unknown> {
  return {
    issuer: discovery.issuer,
    discovery_url: `${discovery.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`,
    client_id: saved.client_id,
    client_name: saved.client_name,
    application_type: saved.application_type,
    token_endpoint_auth_method: saved.token_endpoint_auth_method,
    redirect_uris: [...saved.redirect_uris],
    post_logout_redirect_uris: [...saved.post_logout_redirect_uris],
    grant_types: [...saved.grant_types],
    scope: saved.scope,
    id_token_signed_response_alg: saved.id_token_signed_response_alg,
    userinfo_signed_response_alg: saved.userinfo_signed_response_alg,
    request_object_signing_alg: saved.request_object_signing_alg,
    require_pushed_authorization_requests: saved.require_pushed_authorization_requests ?? true,
    code_challenge_method: 'S256',
    dpop_bound_access_tokens: saved.dpop_bound_access_tokens ?? true,
    tls_client_certificate_bound_access_tokens: saved.tls_client_certificate_bound_access_tokens ?? false,
    use_mtls_endpoint_aliases: saved.use_mtls_endpoint_aliases ?? false,
    tls_client_auth_subject_dn: saved.tls_client_auth_subject_dn,
    tls_client_auth_san_dns: saved.tls_client_auth_san_dns,
    tls_client_auth_san_uri: saved.tls_client_auth_san_uri,
    tls_client_auth_san_ip: saved.tls_client_auth_san_ip,
    tls_client_auth_san_email: saved.tls_client_auth_san_email,
  };
}

/** Map the validator's stable metadata field prefix to the responsible control. */
export function clientFieldError(message: string | null, field: string): string | null {
  if (message === null) return null;
  const reported = message.match(/\b([a-z][a-z0-9_]*)(?:\[\d+\])?(?::| is required)/)?.[1];
  return reported === field || (field === 'redirect_uris' && reported === 'redirect_uri')
    ? message : null;
}

/** Early public-material hints; the domain validator remains authoritative. */
export function publicKeyError(draft: Draft): string | null {
  if (draft.jwks.trim() && draft.jwks_uri.trim()) return 'Choose inline public keys or a JWK Set URL, never both.';
  if (!draft.jwks.trim()) return null;
  let value: unknown;
  try { value = JSON.parse(draft.jwks); } catch { return 'Paste a complete public JWK Set as JSON, including its keys array.'; }
  if (typeof value !== 'object' || value === null || !('keys' in value)
    || !Array.isArray(value.keys) || value.keys.length === 0) {
    return 'A public JWK Set needs a non-empty keys array.';
  }
  for (const key of value.keys as unknown[]) {
    if (typeof key !== 'object' || key === null || !('kty' in key)) return 'Each public key needs a kty member.';
    if (key.kty === 'oct' || ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((field) => field in key)) {
      return 'Remove private or symmetric key material. Paste only the public JWK Set; keep private keys in your application.';
    }
  }
  return null;
}
