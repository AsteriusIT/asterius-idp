import assert from 'node:assert/strict';
import { test } from 'node:test';
import { audienceError, parseScopes, scopesError } from '../src/resource-server-model.ts';

test('accepts an absolute audience and rejects fragments and relative values', () => {
  assert.equal(audienceError('https://api.example/accounts'), null);
  assert.notEqual(audienceError('/accounts'), null);
  assert.notEqual(audienceError('https://api.example/#fragment'), null);
});

test('normalises supported scopes without widening them', () => {
  assert.deepEqual(parseScopes('write read read'), ['read', 'write']);
  assert.notEqual(scopesError('account read"'), null);
});
