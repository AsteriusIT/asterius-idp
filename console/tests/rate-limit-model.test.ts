import assert from 'node:assert/strict';
import { test } from 'node:test';
import { rateDocument, rateError } from '../src/rate-limit-model.ts';

test('rate overrides preserve configured maxima and omit inherited blank controls', () => {
  const configured = { login: { per_account: 3 }, token: { per_client: 15 } };
  assert.deepEqual(rateDocument({ login: { per_account: '3' }, token: { per_client: '15' } }), configured);
  assert.deepEqual(rateDocument({ login: { per_address: '' }, token: { per_client: '2' } }), { token: { per_client: 2 } });
  assert.deepEqual(rateDocument({ login: { per_account: '' } }), {});
});

test('rate validation rejects disabling weakening and fractional maxima', () => {
  for (const value of ['0', '-1', '11', '1.2', 'not-a-number']) assert.ok(rateError(value, 10));
  for (const value of ['', '1', '10']) assert.equal(rateError(value, 10), null);
  assert.ok(Number.isNaN(rateDocument({ token: { per_client: 'wrong' } }).token?.per_client));
});
