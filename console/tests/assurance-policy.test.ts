import assert from 'node:assert/strict';
import { test } from 'node:test';
import { moveAssuranceLevel, type AssuranceLevel } from '../src/assurance-policy-model.ts';

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
