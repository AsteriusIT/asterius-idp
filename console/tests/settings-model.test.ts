import assert from 'node:assert/strict';
import { test } from 'node:test';
import { draftOf, isDirty, type Settings } from '../src/settings-model.ts';

function settings(overrides: Partial<Settings> = {}): Settings {
  return {
    tenant_id: 'console-test',
    disabled_features: [],
    authorization_code_lifetime_seconds: 60,
    access_token_lifetime_seconds: 300,
    limits: {
      max_authorization_code_lifetime_seconds: 60,
      max_access_token_lifetime_seconds: 900,
    },
    ...overrides,
  };
}

test('an older settings response defaults always-ask consent off', () => {
  const stored = settings();

  const draft = draftOf(stored);

  assert.equal(draft.alwaysAskConsent, false);
  assert.equal(isDirty(stored, draft), false);
});

test('the consent switch hydrates and participates in dirty state', () => {
  const stored = settings({ always_ask_consent: true });
  const draft = draftOf(stored);

  assert.equal(draft.alwaysAskConsent, true);
  assert.equal(isDirty(stored, draft), false);
  assert.equal(isDirty(stored, { ...draft, alwaysAskConsent: false }), true);
});


test('session clocks hydrate, retain defaults and participate in dirty state', () => {
  const legacy = draftOf(settings());
  assert.equal(legacy.sessionIdle, '3600');
  assert.equal(legacy.sessionAbsolute, '43200');
  const stored = settings({session_policy: {idle_seconds: 120, absolute_seconds: 600}});
  const draft = draftOf(stored);
  assert.equal(draft.sessionIdle, '120');
  assert.equal(draft.sessionAbsolute, '600');
  assert.equal(isDirty(stored, draft), false);
  assert.equal(isDirty(stored, {...draft, sessionIdle: '180'}), true);
  assert.equal(isDirty(stored, {...draft, sessionAbsolute: '900'}), true);
});

test('assurance settings hydrate, preserve unknown context names and detect changes', () => {
  const acr_policy = { amr_in_id_token: true, levels: [{ value: 'tenant:custom', amr: ['swk', 'user'] }] };
  const stored = settings({ acr_policy });
  const draft = draftOf(stored);
  assert.deepEqual(draft.acrPolicy, acr_policy);
  assert.equal(isDirty(stored, draft), false);
  assert.equal(isDirty(stored, { ...draft, acrPolicy: { ...acr_policy, amr_in_id_token: false } }), true);
  assert.equal(draftOf(settings()).acrPolicy, undefined);
});

test('stored rate overrides hydrate and editing marks settings dirty', () => {
  const stored = settings({ rate_limits: { token: { per_client: 20 } } });
  const draft = draftOf(stored);
  assert.deepEqual(draft.rateLimits, { token: { per_client: '20' } });
  assert.equal(isDirty(stored, draft), false);
  assert.equal(isDirty(stored, { ...draft, rateLimits: { token: { per_client: '10' } } }), true);
});
