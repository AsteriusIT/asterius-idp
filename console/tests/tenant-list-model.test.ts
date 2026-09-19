import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describeFeatures } from '../src/tenant-list-model.ts';

test('renders the disabled feature summary without mutating the API row', () => {
  const disabled = ['mtls', 'dpop_nonce'] as const;
  assert.equal(describeFeatures(disabled), 'off: dpop_nonce, mtls');
  assert.deepEqual(disabled, ['mtls', 'dpop_nonce']);
  assert.equal(describeFeatures([]), 'all on');
});

test('renders an explicit unknown state for an older list document', () => {
  assert.equal(describeFeatures(undefined), '—');
});
