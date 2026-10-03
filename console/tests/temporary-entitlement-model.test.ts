import assert from 'node:assert/strict';
import { test } from 'node:test';
import { activationDuration, approverUsernames, boundedReason, eligibilityInterval } from '../src/temporary-entitlement-model.ts';

test('temporary activation duration respects whole-minute bounds', () => {
  assert.equal(activationDuration('1'), 60);
  assert.equal(activationDuration('60'), 3600);
  for (const raw of ['0', '61', '1.5', '-1', '01', '']) assert.throws(() => activationDuration(raw));
});

test('approval policy names distinct independently selected accounts', () => {
  assert.deepEqual(approverUsernames(' alice@example.test\n\nbob@example.test '), ['alice@example.test', 'bob@example.test']);
  assert.throws(() => approverUsernames('alice\nalice'));
  assert.throws(() => approverUsernames(''));
  assert.throws(() => approverUsernames(Array.from({ length: 17 }, (_, index) => `user${index}`).join('\n')));
});

test('revocation reason uses the server byte bound without control characters', () => {
  assert.equal(boundedReason('  End of maintenance  '), 'End of maintenance');
  assert.equal(boundedReason('é'.repeat(512)).length, 512);
  for (const raw of ['', 'é'.repeat(513), 'bad\u0000reason']) assert.throws(() => boundedReason(raw));
});

test('eligibility interval requires a later exclusive end', () => {
  assert.deepEqual(eligibilityInterval('2026-10-03T10:00:00Z', '2026-10-03T11:00:00Z'), { not_before: 1791021600, expires_at: 1791025200 });
  assert.throws(() => eligibilityInterval('invalid', '2026-10-03T11:00:00Z'));
  assert.throws(() => eligibilityInterval('2026-10-03T11:00:00Z', '2026-10-03T10:00:00Z'));
  assert.throws(() => eligibilityInterval('2026-10-03T11:00:00Z', '2026-10-03T11:00:00Z'));
});
