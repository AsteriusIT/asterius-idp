import assert from 'node:assert/strict';
import { test } from 'node:test';
import { enableAuthenticator, moveAssuranceLevel, type AssuranceLevel } from '../src/assurance-policy-model.ts';

const levels: readonly AssuranceLevel[] = [
  { value: 'low', amr: ['pwd'] },
  { value: 'medium', amr: ['swk'] },
  { value: 'high', amr: ['swk', 'user'] },
];

test('assurance levels move in either direction without mutating the policy', () => {
  assert.deepEqual(moveAssuranceLevel(levels, 0, 2).map(({ value }) => value), ['medium', 'high', 'low']);
  assert.deepEqual(moveAssuranceLevel(levels, 2, 0).map(({ value }) => value), ['high', 'low', 'medium']);
  assert.deepEqual(levels.map(({ value }) => value), ['low', 'medium', 'high']);
});

test('an invalid or no-op assurance move preserves the original list', () => {
  assert.equal(moveAssuranceLevel(levels, 1, 1), levels);
  assert.equal(moveAssuranceLevel(levels, -1, 1), levels);
  assert.equal(moveAssuranceLevel(levels, 1, levels.length), levels);
});


test('enabling TOTP preserves existing contexts and inserts below passkeys', () => {
  const policy = { levels, amr_in_id_token: false };
  const enabled = enableAuthenticator(policy);
  assert.deepEqual(enabled.levels.map(level => level.amr), [['pwd'], ['pwd', 'otp'], ['swk'], ['swk', 'user']]);
  assert.equal(enabled.amr_in_id_token, false);
  assert.equal(policy.levels.length, 3);
  assert.equal(enableAuthenticator(enabled), enabled);
});

test('enabling TOTP handles custom names and the server level limit', () => {
  const policy = { amr_in_id_token: true, levels: [{ value: 'urn:asterius:acr:pwd-otp', amr: ['pwd'] }] };
  assert.equal(enableAuthenticator(policy).levels[1]?.value, 'urn:asterius:acr:pwd-otp-2');
  const full = { ...policy, levels: Array.from({ length: 32 }, (_, i) => ({ value: `custom-${i}`, amr: ['pwd'] })) };
  assert.equal(enableAuthenticator(full), full);
});
