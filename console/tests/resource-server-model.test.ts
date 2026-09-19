import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  audienceError,
  introspectionClientsError,
  lifetimeError,
  parseIntrospectionClients,
  parseLifetime,
  parseScopes,
  scopesError,
} from '../src/resource-server-model.ts';

test('accepts an absolute audience and rejects fragments and relative values', () => {
  assert.equal(audienceError('https://api.example/accounts'), null);
  assert.notEqual(audienceError('/accounts'), null);
  assert.notEqual(audienceError('https://api.example/#fragment'), null);
});

test('normalises supported scopes without widening them', () => {
  assert.deepEqual(parseScopes('write read read'), ['read', 'write']);
  assert.notEqual(scopesError('account read"'), null);
});

test('validates the optional resource-specific token lifetime', () => {
  assert.equal(lifetimeError(''), null);
  assert.equal(parseLifetime(''), null);
  assert.equal(lifetimeError('300'), null);
  assert.equal(parseLifetime('300'), 300);
  assert.notEqual(lifetimeError('0'), null);
  assert.notEqual(lifetimeError('86401'), null);
  assert.notEqual(lifetimeError('1.5'), null);
});

test('normalises one introspection client id per line', () => {
  assert.deepEqual(parseIntrospectionClients('c.reports\nc.gateway\nc.reports'), ['c.gateway', 'c.reports']);
  assert.equal(introspectionClientsError('c.reports\nc.gateway'), null);
  assert.notEqual(introspectionClientsError(`c.reports\n${'x'.repeat(513)}`), null);
});
