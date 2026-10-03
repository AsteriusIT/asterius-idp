import assert from 'node:assert/strict';
import { test } from 'node:test';
import { conditionalScopes, stageMode, factExamples } from '../src/conditional-policy-model.ts';
import { replacePolicy, ApiError, type Session } from '../src/api.ts';

test('staging preserves complete policy and affects only the selected scope without publishing', () => {
  const policy={version:1,rules:[{id:'base',effect:'deny',when:{attribute:{value:'private fixture'}}}],conditional_scopes:[{id:'protected',mode:'report_only',clients:['app'],actions:['authorize'],required_facts:['device_compliance'],rules:[{id:'permit',effect:'permit'}]},{id:'other',mode:'active',clients:['different'],actions:['refresh_token'],rules:[]}],future_preview:{preserved:true}};
  const staged=JSON.parse(stageMode(JSON.stringify(policy),'protected','active'));
  assert.deepEqual(staged,{...policy,conditional_scopes:[{...policy.conditional_scopes[0],mode:'active'},policy.conditional_scopes[1]]});
  assert.equal(policy.conditional_scopes[0]?.mode,'report_only');
  assert.equal(conditionalScopes(JSON.stringify(staged))?.[0]?.mode,'active');
  assert.throws(()=>stageMode('{"conditional_scopes":[{"id":"same"},{"id":"same"}]}','same','active'),/uniquely named/);
});

test('hypothetical evidence never encodes directory or grant authority and missing states omit values', () => {
  const payload=factExamples({authentication_age:{availability:'known',value:'0'},network_zone:{availability:'known',value:'office, remote'},device_compliance:{availability:'stale',value:'ignored private value'},...({groups:{availability:'known',value:'forged-group'}} as object)});
  assert.deepEqual(payload,{authentication_age:{availability:'known',value:0},network_zone:{availability:'known',value:['office','remote']},device_compliance:{availability:'stale'}});
  for(const age of ['-1','1.5','604801','NaN']) assert.throws(()=>factExamples({authentication_age:{availability:'known',value:age}}),/whole seconds/);
});

test('policy publication binds the exact reviewed snapshot and never retries a stale write', async t=>{
  const originalFetch=globalThis.fetch;
  const originalWindow=Object.getOwnPropertyDescriptor(globalThis,'window');
  Object.defineProperty(globalThis,'window',{configurable:true,value:{location:new URL('https://id.example/t/review/admin/')}});
  const calls:RequestInit[]=[];
  globalThis.fetch=async (_url,init)=>{calls.push(init!);return new Response('{}',{status:200});};
  t.after(()=>{globalThis.fetch=originalFetch;if(originalWindow)Object.defineProperty(globalThis,'window',originalWindow);else Reflect.deleteProperty(globalThis,'window');});
  const session={csrf_token:'fixture'} as Session;
  const revision='sha256:'+'a'.repeat(64);
  await replacePolicy(session,{version:1,rules:[]},revision);
  assert.equal(new Headers(calls[0]?.headers).get('If-Match'),'"'+revision+'"');
  assert.equal(new Headers(calls[0]?.headers).get('If-None-Match'),null);
  await replacePolicy(session,{version:1,rules:[]},null);
  assert.equal(new Headers(calls[1]?.headers).get('If-None-Match'),'*');
  await assert.rejects(replacePolicy(session,{},'attacker-controlled-revision'),/Read the current policy revision/);
  assert.equal(calls.length,2);
  globalThis.fetch=async (_url,init)=>{calls.push(init!);return new Response('{}',{status:412});};
  await assert.rejects(replacePolicy(session,{},revision),error=>error instanceof ApiError&&error.status===412);
  assert.equal(calls.length,3);
});
