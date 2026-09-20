import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  clientAuthenticationMethods,
  changeClientAuthentication,
  changeComplianceProfile,
  changeSenderConstraint,
  documentFrom,
  draftOf,
  emptyDraft,
  profilePresentation,
  type ClientDocument,
} from '../src/client-draft.ts';

function client(overrides: Partial<ClientDocument> = {}): ClientDocument {
  return {
    client_id: 'console-test',
    compliance_profile: 'fapi',
    status: 'active',
    client_name: 'Console test',
    application_type: 'web',
    token_endpoint_auth_method: 'private_key_jwt',
    redirect_uris: ['https://client.example/callback'],
    post_logout_redirect_uris: [],
    grant_types: ['authorization_code'],
    scope: 'openid',
    id_token_signed_response_alg: 'EdDSA',
    subject_type: 'public',
    resources: [],
    authorization_details_types: [],
    roles_in_id_token: false,
    managed_groups_claim: false,
    ...overrides,
  };
}

test('hydrates optional security metadata without inventing absent values', () => {
  const absent = draftOf(client());
  assert.equal(absent.userinfo_signed_response_alg, '');
  assert.equal(absent.request_object_signing_alg, '');
  assert.equal(absent.tls_client_certificate_bound_access_tokens, null);

  const future = draftOf(client({
    userinfo_signed_response_alg: 'FutureUserInfoAlg',
    request_object_signing_alg: 'FutureRequestAlg',
    tls_client_certificate_bound_access_tokens: true,
  }));
  assert.equal(future.userinfo_signed_response_alg, 'FutureUserInfoAlg');
  assert.equal(future.request_object_signing_alg, 'FutureRequestAlg');
  assert.equal(future.tls_client_certificate_bound_access_tokens, true);
});

test('creates a safe new-client payload with optional algorithms unset', () => {
  const payload = documentFrom(emptyDraft());

  assert.equal('userinfo_signed_response_alg' in payload, false);
  assert.equal('request_object_signing_alg' in payload, false);
  assert.equal(payload.tls_client_certificate_bound_access_tokens, false);
  assert.equal(payload.managed_groups_claim, false);
  assert.equal(payload.compliance_profile, 'fapi');
  assert.equal(payload.require_pushed_authorization_requests, true);
});

test('standard OIDC payloads omit key metadata and never earn the FAPI badge', () => {
  const draft = changeComplianceProfile({
    ...emptyDraft(),
    jwks: '{"keys":[{"kty":"EC"}]}',
    jwks_uri: 'https://app.example/keys',
  }, 'oidc');
  const payload = documentFrom(draft);

  assert.equal(payload.require_pushed_authorization_requests, false);
  assert.equal(payload.token_endpoint_auth_method, 'client_secret_basic');
  assert.equal(payload.use_mtls_endpoint_aliases, false);
  assert.equal('jwks' in payload, false);
  assert.equal('jwks_uri' in payload, false);
  assert.deepEqual(profilePresentation('oidc'), {
    label: 'Non-FAPI exception',
    fapiBadge: false,
  });
  assert.equal(profilePresentation('fapi').fapiBadge, true);
});

test('standard OIDC offers shared-secret authentication when discovery is hardened', () => {
  const standard = changeComplianceProfile(emptyDraft(), 'oidc');

  assert.deepEqual(clientAuthenticationMethods(standard, ['private_key_jwt']), [
    'client_secret_basic',
    'private_key_jwt',
  ]);
  assert.deepEqual(clientAuthenticationMethods(emptyDraft(), ['private_key_jwt']), [
    'private_key_jwt',
  ]);
});

test('security selections enable mTLS aliases only when they use mTLS', () => {
  const standard = changeComplianceProfile({
    ...emptyDraft(),
    token_endpoint_auth_method: 'tls_client_auth',
    tls_subject_value: 'CN=old-client',
    use_mtls_endpoint_aliases: true,
  }, 'oidc');
  assert.equal(standard.token_endpoint_auth_method, 'client_secret_basic');
  assert.equal(standard.tls_subject_value, '');
  assert.equal(standard.use_mtls_endpoint_aliases, false);

  const tlsAuth = changeClientAuthentication(standard, 'tls_client_auth');
  assert.equal(tlsAuth.use_mtls_endpoint_aliases, true);
  const selfSigned = changeClientAuthentication(standard, 'self_signed_tls_client_auth');
  assert.equal(selfSigned.use_mtls_endpoint_aliases, true);
  const sharedSecret = changeClientAuthentication(tlsAuth, 'client_secret_basic');
  assert.equal(sharedSecret.use_mtls_endpoint_aliases, false);

  const certificateBound = changeSenderConstraint(standard, 'mtls');
  assert.equal(certificateBound.use_mtls_endpoint_aliases, true);
  const dpopBound = changeSenderConstraint(certificateBound, 'dpop');
  assert.equal(dpopBound.use_mtls_endpoint_aliases, false);
  const bearer = changeSenderConstraint(dpopBound, 'bearer');
  assert.equal(bearer.dpop_bound_access_tokens, false);
  assert.equal(bearer.tls_client_certificate_bound_access_tokens, false);
  assert.equal(bearer.use_mtls_endpoint_aliases, false);
  const backToFapi = changeComplianceProfile(bearer, 'fapi');
  assert.equal(backToFapi.dpop_bound_access_tokens, true);
  assert.equal(backToFapi.tls_client_certificate_bound_access_tokens, false);

  const tlsAuthWithDpop = changeSenderConstraint(tlsAuth, 'dpop');
  assert.equal(tlsAuthWithDpop.use_mtls_endpoint_aliases, true);
});

test('round-trips the managed group release opt-in', () => {
  const enabled = draftOf(client({ managed_groups_claim: true }));
  assert.equal(enabled.managed_groups_claim, true);
  assert.equal(documentFrom(enabled).managed_groups_claim, true);
});

test('editing an existing client round-trips known and unknown security metadata', () => {
  const hydrated = draftOf(client({
    userinfo_signed_response_alg: 'ES256',
    request_object_signing_alg: 'FutureRequestAlg',
    tls_client_certificate_bound_access_tokens: true,
  }));
  const edited = {
    ...hydrated,
    userinfo_signed_response_alg: 'PS256',
    tls_client_certificate_bound_access_tokens: false,
  };

  const payload = documentFrom(edited);
  assert.equal(payload.userinfo_signed_response_alg, 'PS256');
  assert.equal(payload.request_object_signing_alg, 'FutureRequestAlg');
  assert.equal(payload.tls_client_certificate_bound_access_tokens, false);
});

test('saving an older client preserves absent security metadata', () => {
  const payload = documentFrom(draftOf(client()));

  assert.equal('userinfo_signed_response_alg' in payload, false);
  assert.equal('request_object_signing_alg' in payload, false);
  assert.equal('tls_client_certificate_bound_access_tokens' in payload, false);
});

test('preserves authentication, sender binding and every certificate identity variant', () => {
  for (const subject of ['tls_client_auth_subject_dn', 'tls_client_auth_san_dns', 'tls_client_auth_san_uri', 'tls_client_auth_san_ip', 'tls_client_auth_san_email']) {
    const saved = client({ token_endpoint_auth_method: 'tls_client_auth',
      dpop_bound_access_tokens: false, tls_client_certificate_bound_access_tokens: true,
      use_mtls_endpoint_aliases: true, [subject]: 'certificate identity' });
    const payload = documentFrom(draftOf(saved));
    assert.equal(payload.token_endpoint_auth_method, 'tls_client_auth');
    assert.equal(payload.dpop_bound_access_tokens, false);
    assert.equal(payload.tls_client_certificate_bound_access_tokens, true);
    assert.equal(payload.use_mtls_endpoint_aliases, true);
    assert.equal(payload[subject], 'certificate identity');
    assert.equal(payload.require_pushed_authorization_requests, true);
  }
});

test('does not silently drop conflicting key sources before server validation', () => {
  const payload = documentFrom({ ...emptyDraft(), jwks: '{"keys":[{"kty":"EC"}]}', jwks_uri: 'https://app.example/keys' });
  assert.deepEqual(payload.jwks, { keys: [{ kty: 'EC' }] });
  assert.equal(payload.jwks_uri, 'https://app.example/keys');
});
