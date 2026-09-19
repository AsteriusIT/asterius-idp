import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  documentFrom,
  draftOf,
  emptyDraft,
  type ClientDocument,
} from '../src/client-draft.ts';

function client(overrides: Partial<ClientDocument> = {}): ClientDocument {
  return {
    client_id: 'console-test',
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
