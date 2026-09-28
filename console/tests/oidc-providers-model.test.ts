import assert from 'node:assert/strict';
import test from 'node:test';
import { draftFor, providerCommand, type OidcProvider } from '../src/oidc-providers-model.ts';

test('editing a provider does not send a replacement secret unless entered', () => {
    const provider: OidcProvider = {
      id: 'workforce', name: 'Workforce', issuer: 'https://login.example.com',
      authorization_endpoint: 'https://login.example.com/authorize',
      token_endpoint: 'https://login.example.com/token',
      jwks_uri: 'https://login.example.com/jwks', client_id: 'asterius',
      enabled: true, allow_registration: false, secret_configured: true,
      callback_url: 'https://id.example.com/t/acme/oidc/upstream/callback/workforce',
      created_at: '2026-09-28T00:00:00Z',
    };
    const draft = draftFor(provider);
    assert.equal(draft.clientSecret, '');
    assert.equal(Object.hasOwn(providerCommand(draft), 'client_secret'), false);
    assert.equal(providerCommand({ ...draft, clientSecret: 'replacement' }).client_secret, 'replacement');
    assert.equal(providerCommand(draft).allow_registration, false);
});
