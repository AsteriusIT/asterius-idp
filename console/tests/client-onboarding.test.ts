import assert from 'node:assert/strict';
import { test } from 'node:test';
import { emptyDraft, type ClientDocument } from '../src/client-draft.ts';
import { clientConfiguration, clientFieldError, publicKeyError } from '../src/client-onboarding.ts';

const saved: ClientDocument = {
  client_id: 'stored-client', client_name: 'Persisted app', status: 'active', application_type: 'web',
  token_endpoint_auth_method: 'tls_client_auth', redirect_uris: ['https://app.example/callback'],
  post_logout_redirect_uris: ['https://app.example/logout'], grant_types: ['authorization_code'],
  scope: 'openid profile', id_token_signed_response_alg: 'ES256', subject_type: 'public',
  resources: [], authorization_details_types: [], roles_in_id_token: false,
  dpop_bound_access_tokens: false, tls_client_certificate_bound_access_tokens: true,
  use_mtls_endpoint_aliases: true, tls_client_auth_san_dns: 'app.example',
};
const discovery = { issuer: 'https://id.example/t/workspace', token_endpoint_auth_methods_supported: ['tls_client_auth'] };

test('exports stored metadata and FAPI connection parameters without key or token material', () => {
  const config = clientConfiguration({ ...saved, jwks: { keys: [{ d: 'private-sentinel' }] },
    client_secret: 'secret-sentinel', registration_access_token: 'token-sentinel',
  } as ClientDocument, discovery);
  assert.equal(config.client_id, saved.client_id);
  assert.equal(config.issuer, discovery.issuer);
  assert.equal(config.discovery_url, `${discovery.issuer}/.well-known/openid-configuration`);
  assert.deepEqual(config.redirect_uris, saved.redirect_uris);
  assert.deepEqual(config.post_logout_redirect_uris, saved.post_logout_redirect_uris);
  assert.equal(config.token_endpoint_auth_method, 'tls_client_auth');
  assert.equal(config.tls_client_auth_san_dns, 'app.example');
  assert.equal(config.dpop_bound_access_tokens, false);
  assert.equal(config.tls_client_certificate_bound_access_tokens, true);
  assert.equal(config.require_pushed_authorization_requests, true);
  assert.equal(config.code_challenge_method, 'S256');
  assert.doesNotMatch(JSON.stringify(config), /sentinel|client_secret|registration_access_token|jwks/);
});

test('field errors match exact validator fields and missing required values', () => {
  assert.equal(clientFieldError('redirect_uri: use https', 'redirect_uris'), 'redirect_uri: use https');
  assert.equal(clientFieldError('redirect_uris[2]: duplicate', 'redirect_uris'), 'redirect_uris[2]: duplicate');
  assert.equal(clientFieldError('post_logout_redirect_uris[0]: use https', 'post_logout_redirect_uris'), 'post_logout_redirect_uris[0]: use https');
  assert.equal(clientFieldError('invalid_client_metadata: dpop_bound_access_tokens: binding required', 'dpop_bound_access_tokens'), 'invalid_client_metadata: dpop_bound_access_tokens: binding required');
  assert.equal(clientFieldError('invalid_redirect_uri: redirect_uris[0]: use https', 'redirect_uris'), 'invalid_redirect_uri: redirect_uris[0]: use https');
  assert.equal(clientFieldError('jwks is required', 'jwks'), 'jwks is required');
  assert.equal(clientFieldError('tls_client_auth_san_dns: required', 'tls_client_auth_san_dns'), 'tls_client_auth_san_dns: required');
  assert.equal(clientFieldError('post_logout_redirect_uris: use https', 'redirect_uris'), null);
  assert.equal(clientFieldError('scope: unknown', 'jwks'), null);
});

test('key guidance catches malformed, empty, conflicting and private keys', () => {
  for (const jwks of ['not json', '{}', '{"keys":[]}', '{"keys":[{"kty":"EC","d":"secret"}]}', '{"keys":[{"kty":"oct","k":"secret"}]}']) {
    assert.ok(publicKeyError({ ...emptyDraft(), jwks }));
  }
  assert.match(publicKeyError({ ...emptyDraft(), jwks: '{"keys":[{"kty":"EC"}]}', jwks_uri: 'https://app.example/keys' })!, /never both/);
  assert.equal(publicKeyError({ ...emptyDraft(), jwks: '{"keys":[{"kty":"EC","x":"public","y":"public"}]}' }), null);
});
