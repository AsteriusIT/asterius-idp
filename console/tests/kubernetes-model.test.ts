import assert from 'node:assert/strict';
import {test} from 'node:test';
import {authenticationLabel, loginCommand, mapBounded, profileChange, profilePath, shellQuote, type ClusterProfile} from '../src/kubernetes-model.ts';

test('profile saves retain the saved cluster identity and CAS revision, including groups outside a visible page',()=>{
  const saved={cluster_id:'prod',revision:7} as ClusterProfile;
  assert.deepEqual(profileChange(saved,'replacement','tools',['outside-page','visible','outside-page']),{cluster_id:'prod',namespace:'tools',group_ids:['outside-page','visible'],revision:7});
  assert.equal(profileChange(null,'new','default',[]).revision,0);
});
test('client identifiers remain one encoded path segment and login aliases remain quoted shell data',()=>{
  assert.equal(profilePath('a/b?c'),'clients/a%2Fb%3Fc/kubernetes');
  assert.equal(shellQuote("o'brien"),"'o'\\''brien'");
  assert.ok(loginCommand('prod',"a'; echo unsafe").includes("--account 'a'\\''; echo unsafe'"));
});
test('online and temporary modes describe saved state without implying immediate revocation',()=>{
  assert.equal(authenticationLabel(null,false),'Signed tokens');
  assert.equal(authenticationLabel({enabled:false,reviewer_client_id:'r',revision:'v'},false),'Signed tokens');
  assert.equal(authenticationLabel({enabled:true,reviewer_client_id:'r',revision:'v'},false),'Online checks enabled');
  assert.equal(authenticationLabel(null,true),'Temporary identity');
});
test('cluster profile fanout is bounded and retains catalogue order',async()=>{
  let active=0,max=0;
  const values=await mapBounded(Array.from({length:12},(_,i)=>i),async i=>{active++;max=Math.max(max,active);await new Promise(resolve=>setTimeout(resolve,2));active--;return i*2;});
  assert.equal(max,4);assert.deepEqual(values,Array.from({length:12},(_,i)=>i*2));
  assert.deepEqual(await mapBounded([],async()=>0),[]);
  await assert.rejects(mapBounded([1],async()=>{throw new Error('refused');}),/refused/);
});
