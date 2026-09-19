import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  describeFeatures,
  oidcDiscoveryUrl,
  oidcLinks,
} from '../src/tenant-list-model.ts';

test('renders the disabled feature summary without mutating the API row', () => {
  const disabled = ['mtls', 'dpop_nonce'] as const;
  assert.equal(describeFeatures(disabled), 'off: dpop_nonce, mtls');
  assert.deepEqual(disabled, ['mtls', 'dpop_nonce']);
  assert.equal(describeFeatures([]), 'all on');
});

test('renders an explicit unknown state for an older list document', () => {
  assert.equal(describeFeatures(undefined), '—');
});

test('builds the OIDC discovery URL from a path-based issuer', () => {
  const issuer = 'https://as.example/t/demo';
  assert.equal(oidcDiscoveryUrl(issuer), `${issuer}/.well-known/openid-configuration`);
});

test('does not duplicate a trailing slash in an issuer', () => {
  const issuer = 'https://login.example/';
  assert.equal(oidcDiscoveryUrl(issuer), 'https://login.example/.well-known/openid-configuration');
});

test('extracts every URL-valued discovery member', () => {
  assert.deepEqual(oidcLinks({
    issuer: 'https://as.example/t/demo',
    authorization_endpoint: 'https://as.example/t/demo/authorize',
    token_endpoint: 'https://as.example/t/demo/token',
    userinfo_endpoint: 'https://as.example/t/demo/userinfo',
    jwks_uri: 'https://as.example/t/demo/jwks',
    scopes_supported: ['openid'],
    unrelated_url: 'https://as.example/not-an-endpoint',
  }), [
    { key: 'issuer', url: 'https://as.example/t/demo' },
    { key: 'authorization_endpoint', url: 'https://as.example/t/demo/authorize' },
    { key: 'token_endpoint', url: 'https://as.example/t/demo/token' },
    { key: 'userinfo_endpoint', url: 'https://as.example/t/demo/userinfo' },
    { key: 'jwks_uri', url: 'https://as.example/t/demo/jwks' },
  ]);
});
