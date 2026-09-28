import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_ROUTE, paramsOf, routeOf } from '../src/routes.ts';

test('empty fragments open the overview', () => {
  assert.equal(routeOf(''), DEFAULT_ROUTE);
  assert.equal(routeOf('#'), DEFAULT_ROUTE);
  assert.equal(routeOf('#/?tenant=demo'), DEFAULT_ROUTE);
});

test('known and unknown routes retain their names and query parameters', () => {
  assert.equal(routeOf('#/users'), 'users');
  assert.equal(routeOf('#/settings?tenant=demo'), 'settings');
  assert.equal(paramsOf('#/settings?tenant=demo').get('tenant'), 'demo');
  assert.equal(routeOf('#/unlisted?tenant=demo'), 'unlisted');
  assert.equal(paramsOf('#/unlisted?tenant=demo').get('tenant'), 'demo');
});
