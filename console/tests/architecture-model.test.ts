import assert from 'node:assert/strict';
import test from 'node:test';
import { bffPreset, contextOnlyNode, contextOnlyConnection, integrationCredentials, missingIntegrationCredentials, connectionLabel, validConnection, type Graph, type Kind } from '../src/architecture-model.ts';

function graph(source: Kind, target: Kind): Graph {
  return { schema_version: 1, nodes: [
    { id: 'a', kind: source, label: 'A', identifier: 'a', mode: 'managed', x: 0, y: 0, settings: {} },
    { id: 'b', kind: target, label: 'B', identifier: 'b', mode: 'managed', x: 1, y: 1, settings: {} },
  ], edges: [] };
}

test('only meaningful object relationships can be drawn', () => {
  assert.equal(validConnection(graph('application', 'api'), 'a', 'b'), true);
  assert.equal(validConnection(graph('application', 'role'), 'a', 'b'), true);
  assert.equal(validConnection(graph('group', 'role'), 'a', 'b'), true);
  assert.equal(validConnection(graph('api', 'application'), 'a', 'b'), false);
  assert.equal(validConnection(graph('application', 'api'), 'a', 'missing'), false);
});

test('a connection cannot be repeated', () => {
  const value = graph('group', 'role');
  value.edges.push({ id: 'e', source: 'a', target: 'b' });
  assert.equal(validConnection(value, 'a', 'b'), false);
});


test('identity providers connect only to groups or users, and roles are leaves', () => {
  const kinds: Kind[] = ['application', 'api', 'role', 'group', 'user', 'identity_provider', 'stream', 'gateway'];
  for (const kind of kinds) {
    assert.equal(validConnection(graph('identity_provider', kind), 'a', 'b'), kind === 'group' || kind === 'user');
    assert.equal(validConnection(graph('role', kind), 'a', 'b'), false);
  }
});

test('API chains and gateways allow calls but never role or identity links', () => {
  for (const [source, target] of [['api', 'api'], ['api', 'gateway'], ['application', 'gateway'], ['gateway', 'api']] as [Kind, Kind][]) {
    const value = graph(source, target);
    assert.equal(validConnection(value, 'a', 'b'), true);
    assert.equal(validConnection(value, 'a', 'a'), false);
  }
  for (const kind of ['user', 'role', 'identity_provider', 'application', 'group'] as Kind[]) {
    assert.equal(validConnection(graph('gateway', kind), 'a', 'b'), false);
  }
});


test('BFF expands into provisionable resources with explicit missing deployment values', () => {
  let counter = 0;
  const preset = bffPreset(() => `node-${counter++}`, 500);
  assert.equal(preset.nodes.length, 2);
  const [app, api] = preset.nodes;
  assert.equal(app?.kind, 'application');
  assert.equal(api?.kind, 'api');
  assert.equal(app?.mode, 'managed');
  assert.equal(api?.mode, 'managed');
  assert.deepEqual(app?.settings, { redirect_uris: [], jwks_uri: '' });
  assert.equal(api?.identifier, '');
  assert.deepEqual(api?.settings, { scopes: ['bff.access'], default_token_lifetime_seconds: 300 });
  assert(preset.nodes.every(node => node.y === 500));
  assert(validConnection({ ...preset, edges: [] }, preset.edges[0]!.source, preset.edges[0]!.target));
  assert(!connectionLabel('application', 'api').includes('context only'));
  for (const [source, target] of [['api', 'api'], ['api', 'gateway'], ['gateway', 'api'], ['application', 'gateway']] as [Kind, Kind][]) {
    assert(connectionLabel(source, target).includes('context only'));
  }
});


test('legacy integrations stay context until explicitly configured and edges stay descriptive', () => {
  assert(contextOnlyNode('identity_provider', {}));
  assert(contextOnlyNode('stream', {}));
  assert(!contextOnlyNode('identity_provider', { integration: true }));
  assert(!contextOnlyNode('stream', { integration: true }));
  assert(contextOnlyConnection('identity_provider', 'user'));
  assert(contextOnlyConnection('application', 'stream'));
});

test('apply credentials exclude unchanged, referenced and unrelated nodes', () => {
  const plan = { flow_id: 'flow', revision: 2, digest: 'digest', applicable: true, steps: [
    { id: 'create', kind: 'identity_provider', action: 'create' as const, label: 'Create', scope: 'admin.oidc_providers:write', resource_id: null, explanation: '', live: { requires_credential: true } },
    { id: 'same', kind: 'identity_provider', action: 'unchanged' as const, label: 'Same', scope: '', resource_id: null, explanation: '' },
    { id: 'stream', kind: 'stream', action: 'create' as const, label: 'Stream', scope: '', resource_id: null, explanation: '' },
  ] };
  assert(missingIntegrationCredentials(plan, {}));
  assert(!missingIntegrationCredentials(plan, { create: 'apply-only' }));
  assert.deepEqual(integrationCredentials(plan, { create: 'apply-only', same: 'ignored', stream: 'ignored', unrelated: 'ignored' }), { create: 'apply-only' });
});
