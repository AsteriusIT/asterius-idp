import assert from 'node:assert/strict';
import test from 'node:test';
import { validConnection, type Graph, type Kind } from '../src/architecture-model.ts';

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
  const kinds: Kind[] = ['application', 'api', 'role', 'group', 'user', 'identity_provider', 'stream'];
  for (const kind of kinds) {
    assert.equal(validConnection(graph('identity_provider', kind), 'a', 'b'), kind === 'group' || kind === 'user');
    assert.equal(validConnection(graph('role', kind), 'a', 'b'), false);
  }
});
