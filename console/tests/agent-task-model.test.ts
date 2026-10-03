import { test } from 'node:test';
import assert from 'node:assert/strict';
import { snapshotAge, taskPageQuery, lineageTree, type GrantNode } from '../src/agent-task-model.ts';

test('current authority observation becomes stale independently of recorded history', () => {
  const observed = '2026-10-03T12:00:00Z';
  const instant = Date.parse(observed);
  assert.equal(snapshotAge(observed, instant), 'Observed recently');
  assert.equal(snapshotAge(observed, instant + 30_000), 'Observed recently');
  assert.equal(snapshotAge(observed, instant + 30_001), 'Refresh required');
  assert.equal(snapshotAge(observed, instant - 1), 'Refresh required');
  assert.equal(snapshotAge('invalid', instant), 'Refresh required');
});

test('task page bounds cannot be expanded through a cursor', () => {
  const query = new URLSearchParams(taskPageQuery('cursor&limit=1000').slice(1));
  assert.equal(query.get('limit'), '25');
  assert.equal(query.get('cursor'), 'cursor&limit=1000');
  assert.equal(query.getAll('limit').length, 1);
});

test('bounded lineage tree joins paths without inventing missing parent authority', () => {
  const node = (id: string, path: readonly string[]): GrantNode => ({
    grant_id: id, parent_grant_id: path.length>1 ? path[path.length-2] ?? null : null,
    client_id:'agent', depth:path.length-1, ancestry:path, state:'active', expires_at:null, revoked_at:null,
    recorded_ceiling:{scopes:[],resources:[],actions:[],resource_ceilings:[],max_delegation_depth:2},
    current_issuance_ceiling:{scopes:[],resources:[],actions:[],resource_ceilings:[],max_delegation_depth:2},
  });
  const roots = lineageTree([node('child',['root','child']),node('sibling',['root','sibling'])]);
  assert.equal(roots.length,1);
  assert.equal(roots[0]?.id,'root');
  assert.equal(roots[0]?.node,undefined);
  assert.deepEqual(roots[0]?.children.map(child=>child.id),['child','sibling']);
  const unsafe=lineageTree([node('cycle',['cycle','other','cycle'])]);
  assert.equal(unsafe[0]?.children.length,0);
  assert.equal(lineageTree(Array.from({length:51},(_,index)=>node(String(index),[String(index)]))).length,50);
});
