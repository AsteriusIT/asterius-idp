import assert from 'node:assert/strict';
import test from 'node:test';
import {applicationResult,mayApply,mayDecide,sourceLabel,targetSubject,type ReviewItem} from '../src/access-reviews-model.ts';
const item={assigned_reviewer:'reviewer',decision:null,apply_status:'pending'} as ReviewItem;
test('review assignment never substitutes for server write authority',()=>{
 assert.equal(mayDecide(item,'reviewer',false),false);
 assert.equal(mayDecide(item,'someone-else',true),false);
 assert.equal(mayDecide(item,'reviewer',true),true);
});
test('recording removal is separate from applying a pending decision',()=>{
 assert.equal(mayApply(item,'reviewer',true),false);
 const decided={...item,decision:'remove' as const};
 assert.equal(mayDecide(decided,'reviewer',true),false);
 assert.equal(mayApply(decided,'reviewer',true),true);
 for(const apply_status of ['removed','conflict','protected'] as const)assert.equal(mayApply({...decided,apply_status},'reviewer',true),false);
 assert.match(applicationResult('conflict'),/new review/);
 assert.match(applicationResult('protected'),/controller/);
});
test('source identity remains distinct when two people hold the same role',()=>{
 const a={kind:'user_tenant_role' as const,user_id:'one',name:'reader'};const b={...a,user_id:'two'};
 const names=new Map([['one','Alice'],['two','Bob']]);
 assert.equal(sourceLabel(a),sourceLabel(b));
 assert.notEqual(targetSubject(a,names),targetSubject(b,names));
 assert.equal(targetSubject({kind:'membership',group_id:'engineering',user_id:'one'},names),'Alice in engineering');
});
