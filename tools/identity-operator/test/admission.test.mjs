import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {setTimeout as delay} from 'node:timers/promises';
import test from 'node:test';
import {crds,examples,namespaceDocuments} from '../schema.mjs';

test('checked-in structural schemas and examples match their generator', () => {
  for (const [file,items] of [['crds.json',crds],['namespace-acme.json',namespaceDocuments('identity-acme')],['examples.json',examples]]) {
    const path = new URL(`../../../deploy/operator/${file}`,import.meta.url);
    assert.deepEqual(JSON.parse(readFileSync(path,'utf8')),{apiVersion:'v1',kind:'List',items});
  }
});

test('Kubernetes 1.35 enforces schema, RBAC and admission boundaries', {skip:!process.env.ASTERIUS_CRD_KUBECONFIG}, async () => {
  const kubeconfig=process.env.ASTERIUS_CRD_KUBECONFIG;
  const calls=[];
  function kubectl(args,object,asWriter=false) {
    const auth=asWriter ? ['--as=gitops-fixture','--as-group=asterius-gitops:identity-acme'] : [];
    try {
      return {ok:true,output:execFileSync('kubectl',['--kubeconfig',kubeconfig,...auth,...args],
        {input:object ? JSON.stringify(object):undefined,encoding:'utf8',stdio:['pipe','pipe','pipe']})};
    } catch (error) {return {ok:false,output:String(error.stderr)};}
  }
  function pass(label,result) {assert.equal(result.ok,true,`${label}: ${result.output}`);calls.push(label);return result;}
  function deny(label,result,pattern) {assert.equal(result.ok,false,`${label} unexpectedly succeeded`);assert.match(result.output,pattern);calls.push(label);}
  const list=items=>({apiVersion:'v1',kind:'List',items});
  pass('structural CRDs including transition CEL accepted',kubectl(['apply','-f','-'],list(crds)));
  for (const crd of crds) pass('CRD established',kubectl(['wait','--for=condition=Established',`crd/${crd.metadata.name}`,'--timeout=30s']));
  pass('trusted namespace and binding accepted',kubectl(['apply','-f','-'],list(examples.slice(0,2))));
  pass('least-privilege RBAC and fail-closed admission accepted',kubectl(['apply','-f','-'],list(namespaceDocuments('identity-acme'))));
  // Allow API-server policy informer to observe newly installed trusted parameter.
  let positive;
  for(let i=0;i<30;i++) {
    positive=kubectl(['create','--dry-run=server','-f','-'],examples[2],true);
    if(positive.ok) break;
    await delay(500);
  }
  pass('GitOps author can create valid application through admission',positive);
  const policy=JSON.parse(pass('admission typechecking completed',kubectl(['get','validatingadmissionpolicy','asterius-identity-acme','-o','json'])).output);
  assert.deepEqual(policy.status?.typeChecking?.expressionWarnings ?? [],[]);
  for(const object of examples.slice(2)) pass(`positive ${object.kind} example`,kubectl(['create','-f','-'],object,true));
  const app=structuredClone(examples[2]);
  app.metadata.name='cross-tenant';app.spec.tenantRef='other';
  deny('foreign tenantRef denied',kubectl(['create','-f','-'],app,true),/Unsupported value|tenantRef/);
  app.spec.tenantRef='default';app.metadata.namespace='default';
  deny('cross-namespace write denied by RBAC',kubectl(['create','-f','-'],app,true),/Forbidden|forbidden/);
  deny('GitOps cannot read credential Secrets',kubectl(['get','secret','asterius-auth-key','-n','identity-acme'],null,true),/Forbidden|forbidden/);
  const binding=structuredClone(examples[1]);binding.spec.issuer='https://evil.example/t/acme';
  deny('GitOps cannot alter binding',kubectl(['apply','-f','-'],binding,true),/Forbidden|forbidden/);
  deny('administrator cannot change immutable tenant issuer',kubectl(['apply','-f','-'],binding),/immutable/);
  const resource=structuredClone(examples[3]);resource.spec.identifier='https://other.example/';
  deny('immutable resource audience cannot change',kubectl(['apply','-f','-'],resource,true),/immutable/);
  const privateApp=structuredClone(examples[2]);privateApp.metadata.name='inline-secret';privateApp.spec.clientSecret='never-allowed';
  deny('strict validation refuses inline private credential field',kubectl(['create','--validate=strict','-f','-'],privateApp,true),/unknown field|unknown.*clientSecret/);
  const both=structuredClone(examples[2]);both.metadata.name='two-jwks';both.spec.publicJwksSecretRef={name:'public-jwks',key:'jwks.json'};
  deny('ambiguous public-key source denied',kubectl(['create','-f','-'],both,true),/exactly one/);
  const status={status:{observedGeneration:99}};
  deny('GitOps cannot forge readiness status',kubectl(['patch','application','billing','-n','identity-acme','--subresource=status','--type=merge','-p',JSON.stringify(status)],null,true),/Forbidden|forbidden/);
  pass('trusted administrator removes binding',kubectl(['delete','asteriustenantbinding','default','-n','identity-acme']));
  const missing=structuredClone(examples[2]);missing.metadata.name='missing-binding';
  let missingResult;
  for(let i=0;i<30;i++) {
    missingResult=kubectl(['create','--dry-run=server','-f','-'],missing,true);
    if(!missingResult.ok) break;
    await delay(500);
  }
  deny('missing tenant parameter fails closed',missingResult,/no params|parameter|denied|binding/i);
  console.log(JSON.stringify({target:'Kubernetes v1.35.0',checks:calls}));
});
