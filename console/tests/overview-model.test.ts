import assert from 'node:assert/strict';
import { test } from 'node:test';
import { applicationPolicyPresentation, loadingMetrics, updateMetric, visibleMetrics } from '../src/overview-model.ts';

test('presents the tenant application policy as a compliance state', () => {
  assert.deepEqual(applicationPolicyPresentation(false), {
    label: 'FAPI-only applications', tone: 'ok',
  });
  assert.deepEqual(applicationPolicyPresentation(true), {
    label: 'Non-FAPI exceptions enabled', tone: 'warn',
  });
});

test('offers only overview requests independently authorized by the session', () => {
  const metrics = visibleMetrics({ scopes: ['admin.users:read', 'admin.sessions:read'] });
  assert.deepEqual(metrics.map((metric) => metric.path), ['overview/users', 'overview/sessions']);
  assert.equal(metrics.some((metric) => metric.path.includes('authentication')), false);
  assert.equal(metrics.some((metric) => metric.path.includes('delivery')), false);
});

test('a restricted session makes no overview request when it holds no metric scope', () => {
  assert.deepEqual(visibleMetrics({ scopes: ['admin.session:read'] }), []);
});

test('one failed metric leaves successful and loading neighbours intact', () => {
  const definitions = visibleMetrics({ scopes: ['admin.users:read', 'admin.sessions:read', 'admin.clients:read'] });
  let states = loadingMetrics(definitions);
  states = updateMetric(states, 'overview/users', {
    kind: 'ready',
    document: { metric: 'enabled_users', value: 0, definition: 'Active accounts.', window_seconds: null, collected_at: 1 },
  });
  states = updateMetric(states, 'overview/sessions', { kind: 'failed', message: 'unavailable' });

  assert.equal(states.get('overview/users')?.kind, 'ready');
  assert.equal(states.get('overview/sessions')?.kind, 'failed');
  assert.equal(states.get('overview/applications')?.kind, 'loading');
  assert.equal(states.size, 3);
});
