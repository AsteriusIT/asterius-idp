'use strict';
(async () => {
 const plan = await fetch('plan.json', {cache:'no-store'}).then(r => {if(!r.ok)throw new Error('Setup plan unavailable');return r.json();});
 if(plan.tenant!=='demo'||plan.issuer!==location.origin+'/t/demo')throw new Error('Setup plan tenant/issuer does not match this canonical operator host');
 const base = '/t/demo/admin/api/v1/';
 const status = document.getElementById('status');
 document.getElementById('plan').textContent = JSON.stringify({tenant:plan.tenant,resources:plan.resources,clients:plan.clients.map(c=>({name:c.registration.client_name,grant_types:c.registration.grant_types,scope:c.registration.scope,resources:c.resources,redirect_uris:c.registration.redirect_uris,public_key_id:c.registration.jwks.keys[0].kid}))},null,2);
 async function api(path, method='GET', body, key) {
  const headers = {Accept:'application/json'};
  if(method !== 'GET'){headers['X-CSRF-Token']=session.csrf_token;headers['Content-Type']='application/json';}
  if(key) headers['Idempotency-Key']=key;
  const r=await fetch(base+path,{method,headers,credentials:'same-origin',redirect:'error',...(body===undefined?{}:{body:JSON.stringify(body)})});
  const result=await r.json();
  if(!r.ok) throw new Error(`${method} ${path}: ${r.status} ${result.error?.message||'Request refused; check sign-in and permissions'}`);
  return result;
 }
 let session;
 try {session=await api('session');if(!session.scopes.includes('admin.clients:write')||!session.scopes.includes('admin.resource_servers:write'))throw new Error('Client and resource-server write permissions required');status.textContent=`Signed in as ${session.username} in ${session.workspace}. Review the plan, then apply.`;document.getElementById('apply').disabled=false;}
 catch(error){status.textContent=error.message+'\nSign in using the console link, then reload this page.';}
 document.getElementById('create-user').disabled=!session?.scopes.includes('admin.users:write');
 let userAttempt;
 document.getElementById('user-form').onsubmit=async(event)=>{
  event.preventDefault();const button=document.getElementById('create-user');const output=document.getElementById('user-status');button.disabled=true;
  const username=document.getElementById('tour-username').value.trim();const password=document.getElementById('tour-password').value;
  try{
   if(!/^tour-[A-Za-z0-9._-]+$/.test(username)||password.length<12)throw new Error('Choose a tour-* login and a password of at least 12 characters; Asterius applies its password policy.');
   session=await api('session');if(!session.scopes.includes('admin.users:write'))throw new Error('User write permission required');
   const body={username,password,claims:{name:{value:'Playground user',verified:false}}};
   const encoded=JSON.stringify(body);
   if(!userAttempt||userAttempt.body!==encoded)userAttempt={body:encoded,key:crypto.randomUUID()};
   const created=await api('users','POST',body,userAttempt.key);
   output.textContent='Created '+created.username+' in demo with no administrator role. Use your chosen password to sign in to the playground apps. User ID: '+created.user_id;
   document.getElementById('tour-password').value='';userAttempt=undefined;
  }catch(error){output.textContent=error.message+'\nExisting users were not reset. If interrupted, retry the same login and password; use the console to inspect an uncertain result.';}
  finally{button.disabled=!session?.scopes.includes('admin.users:write');}
 };
 const storageKey='asterius-playground-setup-'+plan.run_id;
 const samePublicKeys=(a,b)=>Array.isArray(a)&&a.length===b.length&&b.every(expected=>a.some(actual=>['kty','crv','x','y','kid','alg','use'].every(k=>actual[k]===expected[k])));
 const saved=JSON.parse(localStorage.getItem(storageKey)||'{}');
 document.getElementById('apply').onclick=async()=>{
  document.getElementById('apply').disabled=true;
  try{
   session=await api('session');
   for(const c of plan.clients){
    status.textContent='Registering '+c.registration.client_name;
    if(!saved[c.key]){const result=await api('clients','POST',c.registration,c.idempotency_key);saved[c.key]=result.client_id;localStorage.setItem(storageKey,JSON.stringify(saved));}
    // Refuse stale or foreign identifiers before any idempotent replacement.
    if(typeof saved[c.key]!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(saved[c.key]))throw new Error('Unexpected saved client identifier; stop and ask the operator');
    const current=await api('clients/'+encodeURIComponent(saved[c.key]));
    if(current.dpop_bound_access_tokens!==true||current.require_pushed_authorization_requests!==true||current.token_endpoint_auth_method!=='private_key_jwt'||JSON.stringify([...(current.grant_types||[])].sort())!==JSON.stringify([...c.registration.grant_types].sort())||JSON.stringify([...(current.redirect_uris||[])].sort())!==JSON.stringify([...c.registration.redirect_uris].sort())||current.client_name!==c.registration.client_name||!samePublicKeys(current.jwks?.keys,c.registration.jwks.keys))throw new Error('Saved client ownership/key mismatch: stop and ask the operator');
   }
   const existing=(await api('resource-servers')).items;
   for(const r of plan.resources){
    const expected={scopes:r.scopes,default_token_lifetime_seconds:r.default_token_lifetime_seconds,introspection_clients:r.clients.map(k=>saved[k])};
    const found=existing.find(x=>x.identifier===r.identifier);
    if(found){
     const setEqual=(a,b)=>Array.isArray(a)&&a.length===b.length&&a.every(x=>b.includes(x));
     if(!setEqual(found.scopes,expected.scopes)||found.default_token_lifetime_seconds!==expected.default_token_lifetime_seconds||!setEqual(found.introspection_clients,expected.introspection_clients))throw new Error('Existing resource policy differs; ask the operator before changing it: '+r.identifier);
    }else await api('resource-servers/'+encodeURIComponent(r.identifier),'PUT',expected);
   }
   for(const c of plan.clients)await api('clients/'+encodeURIComponent(saved[c.key])+'/resources','PUT',{resources:c.resources});
   status.textContent='Setup complete. Registered public client identifiers:\n'+JSON.stringify(saved,null,2)+'\nTell the operator setup is complete; private keys are already held outside this browser.';
  }catch(error){status.textContent=error.message+'\nProgress is saved. Do not create replacements manually; inspect and retry this exact plan.';document.getElementById('apply').disabled=false;}
 };
})().catch(error=>{document.getElementById('status').textContent=error.message;});
