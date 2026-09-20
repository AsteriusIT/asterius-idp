import assert from 'node:assert/strict';
import test from 'node:test';
import {
  groupRoleWithdrawPath,
  hasDirectSource,
  memberPath,
  sourceLabel,
} from '../src/groups-model.ts';

test('group and member paths encode identifiers independently', () => {
  assert.equal(memberPath('group/id', 'user id'), 'groups/group%2Fid/members/user%20id');
  assert.equal(
    groupRoleWithdrawPath('g', 'approve:payment', 'billing/api'),
    'groups/g/clients/billing%2Fapi/app-roles/approve%3Apayment',
  );
});

test('inherited-only assignments cannot be withdrawn as direct grants', () => {
  const inherited = { name: 'reader', client_id: null, sources: [{ type: 'group' as const, group_id: 'g-1' }] };
  const mixed = { ...inherited, sources: [{ type: 'direct' as const }, ...inherited.sources] };

  assert.equal(hasDirectSource(inherited), false);
  assert.equal(hasDirectSource(mixed), true);
  assert.equal(sourceLabel(inherited.sources[0]), 'Group g-1');
});
