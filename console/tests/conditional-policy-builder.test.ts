import assert from 'node:assert/strict';
import { test } from 'node:test';
import { addScope, builderDocument, conditionKind, newCondition, patchScope, removeScope, scopeChanges } from '../src/conditional-policy-builder-model.ts';
const original = { version: 1, rules: [{ id: 'base', effect: 'deny', when: { future: true } }], future: { keep: true }, conditional_scopes: [
  { id: 'scope-1', mode: 'active', rules: [{ id: 'r', effect: 'permit', when: { all: [{ any: [{ network_zone: 'office' }, { not: { device_compliance: 'compliant' } }] }, { future: [1, 2] }] }, acr_values: ['custom'], extension: 1 }], network_zones: { office: ['192.0.2.0/24'] }, assurance_remedy: 'custom', extension: { keep: true } },
  { id: 'sibling', mode: 'active', rules: [] },
] };
test('scope patches preserve base rules, unknown fields, nested conditions and sibling scopes', () => {
  const next = JSON.parse(patchScope(JSON.stringify(original), 0, { mode: 'report_only' }));
  assert.deepEqual(next, { ...original, conditional_scopes: [{ ...original.conditional_scopes[0], mode: 'report_only' }, original.conditional_scopes[1]] });
  assert.equal(original.conditional_scopes[0]?.mode, 'active');
  const rules = JSON.parse(JSON.stringify(original.conditional_scopes[0]?.rules));
  rules[0].when.all[0].any[1].not.device_compliance = 'non_compliant';
  const edited = JSON.parse(patchScope(JSON.stringify(original), 0, { rules }));
  assert.deepEqual(edited.conditional_scopes[0].rules[0].when.all[1], { future: [1, 2] });
  assert.equal(edited.conditional_scopes[0].rules[0].extension, 1);
  assert.deepEqual(edited.conditional_scopes[0].rules[0].acr_values, ['custom']);
});
test('adding defaults to report-only with a unique ID; deleting removes only the selected scope', () => {
  const added = JSON.parse(addScope(JSON.stringify(original)));
  assert.equal(added.conditional_scopes[2].id, 'scope-2');
  assert.equal(added.conditional_scopes[2].mode, 'report_only');
  assert.deepEqual(JSON.parse(removeScope(JSON.stringify(original), 0)), { ...original, conditional_scopes: [original.conditional_scopes[1]] });
});
test('unsupported expressions and malformed drafts never get rewritten by recognition', () => {
  for (const input of ['{', 'null', '[]', '{"rules":[],"conditional_scopes":{}}']) {
    assert.equal(builderDocument(input), null);
    assert.throws(() => addScope(input));
  }
  for (const value of [{ all: [], future: true }, { network_zone: ['office'] }, { future: 1 }, { all: 'no' }]) assert.equal(conditionKind(value), null);
  assert.equal(conditionKind({ all: [] }), 'all');
  assert.equal(conditionKind({ any: [] }), 'any');
  assert.deepEqual(newCondition('all'), { all: [] });
  assert.deepEqual(newCondition('any'), { any: [] });
  assert.deepEqual(newCondition('not'), { not: { application_sensitivity: 'critical' } });
});
test('review includes targets, modes, conditions and unknown-field changes without dropping duplicate IDs', () => {
  const next = patchScope(JSON.stringify(original), 0, { id: 'renamed', mode: 'report_only', clients: ['app'], extension: { keep: false } });
  const changes = scopeChanges(JSON.stringify(original), next);
  for (const field of ['id', 'mode', 'clients', 'extension']) assert.ok(changes.some(row => row.change === `renamed: ${field}`));
  assert.deepEqual(scopeChanges(next, next), []);
  assert.equal(scopeChanges(JSON.stringify(original), removeScope(JSON.stringify(original), 1)).at(-1)?.after, 'Not present');
});
