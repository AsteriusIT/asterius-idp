import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

// The optional path lets an isolated test worktree exercise an unmerged setup
// implementation. The normal command tests the setup.js beside this file.
const source = await readFile(process.env.SETUP_SCRIPT || new URL('./setup.js', import.meta.url), 'utf8');
const origin = 'https://operator.example.test';
const apiBase = '/t/demo/admin/api/v1/';
const clone = value => structuredClone(value);
const publicKey = (kid, coordinate) => ({kty:'EC', crv:'P-256', x:coordinate, y:'public-y', kid, alg:'ES256', use:'sig'});
function makePlan() {
  const clients = ['demo-a', 'financial-api'].map((key, index) => ({
    key, idempotency_key:`fixed-create-${key}`,
    registration:{client_name:`Playground · ${key}`, token_endpoint_auth_method:'private_key_jwt',
      jwks:{keys:[publicKey(`${key}-key`, `${index}-public-x`)]},
      grant_types:['authorization_code', 'refresh_token'], response_types:['code'],
      scope:'openid profile', redirect_uris:[`${origin}:8446/${key}/callback`],
      dpop_bound_access_tokens:true, require_pushed_authorization_requests:true},
    resources:[index === 0 ? `${origin}/t/demo/userinfo` : `${origin}:8446/financial-api`],
  }));
  return {run_id:'public-test-run', tenant:'demo', issuer:origin+'/t/demo', clients,
    resources:clients.map(c => ({identifier:c.resources[0], scopes:c.key === 'demo-a' ? ['openid','profile'] : ['accounts:read','accounts:write'],
      default_token_lifetime_seconds:300, clients:c.key === 'financial-api' ? [c.key] : []}))};
}
function createServer(plan) {
  const requests = [], clients = new Map(), idempotency = new Map(), resources = new Map(), users = new Map();
  let nextId = 1;
  const session = {username:'operator', workspace:'demo', csrf_token:'mock-csrf', scopes:['admin.clients:write','admin.resource_servers:write','admin.users:write']};
  const state = {requests, clients, idempotency, resources, users, session, userFailureStatus:null,
    failCreateAfterCommit:null, failAssignmentOnce:false, currentTransform:value => value};
  const response = (status, body) => ({ok:status >= 200 && status < 300, status, json:async () => clone(body)});
  state.fetch = async (url, options = {}) => {
    const method = options.method || 'GET';
    const body = options.body === undefined ? undefined : JSON.parse(options.body);
    requests.push({url, method, body, headers:clone(options.headers || {})});
    if (url === 'plan.json') return response(200, plan);
    assert.ok(url.startsWith(apiBase), 'setup must use the same-origin tenant API');
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.redirect, 'error');
    if (method !== 'GET') {
      assert.equal(options.headers['X-CSRF-Token'], session.csrf_token);
      assert.equal(options.headers['Content-Type'], 'application/json');
    }
    const path = url.slice(apiBase.length);
    if (path === 'session' && method === 'GET') return response(200, session);
    if (path === 'users' && method === 'POST') {
      assert.ok(options.headers['Idempotency-Key']);
      assert.deepEqual(Object.keys(body).sort(), ['claims','password','username']);
      assert.deepEqual(body.claims, {name:{value:'Playground user',verified:false}});
      if (state.userFailureStatus) return response(state.userFailureStatus, {error:{message:'mock user create refused'}});
      if (users.has(body.username)) return response(409, {error:{message:'Username already exists'}});
      const created = {username:body.username, user_id:'20000000-0000-4000-8000-000000000001'};
      users.set(body.username, {...clone(created), password:body.password});
      return response(201, created);
    }
    if (path === 'clients' && method === 'POST') {
      const key = options.headers['Idempotency-Key'];
      assert.ok(key, 'every create must carry its fixed idempotency key');
      let id = idempotency.get(key);
      if (!id) {
        id = `10000000-0000-4000-8000-${String(nextId++).padStart(12,'0')}`;
        idempotency.set(key, id); clients.set(id, {...clone(body), client_id:id});
      }
      if (state.failCreateAfterCommit === body.client_name) {
        state.failCreateAfterCommit = null;
        throw new Error('mock transport lost the committed create response');
      }
      return response(201, clients.get(id));
    }
    if (path.startsWith('clients/') && method === 'GET') {
      const current = clients.get(decodeURIComponent(path.slice('clients/'.length)));
      return current ? response(200, state.currentTransform(clone(current))) : response(404, {error:{message:'Not found'}});
    }
    if (path === 'resource-servers' && method === 'GET') return response(200, {items:[...resources.values()]});
    if (path.startsWith('resource-servers/') && method === 'PUT') {
      assert.deepEqual(Object.keys(body).sort(), ['default_token_lifetime_seconds','introspection_clients','scopes']);
      const identifier = decodeURIComponent(path.slice('resource-servers/'.length));
      resources.set(identifier, {identifier,...clone(body)});
      return response(200, resources.get(identifier));
    }
    if (/^clients\/[^/]+\/resources$/.test(path) && method === 'PUT') {
      assert.deepEqual(Object.keys(body), ['resources']);
      assert.ok(body.resources.every(identifier => resources.has(identifier)), 'audiences must exist before assignment');
      if (state.failAssignmentOnce) {
        state.failAssignmentOnce = false;
        return response(503, {error:{message:'mock resource assignment unavailable'}});
      }
      return response(200, {resources:body.resources});
    }
    assert.fail(`Unexpected request: ${method} ${path}`);
  };
  return state;
}
async function page(plan, server, {storage=new Map(), pageOrigin=origin} = {}) {
  const elements = new Map(['status','plan','apply','create-user','user-form','user-status','tour-username','tour-password']
    .map(id => [id,{textContent:'', value:'', disabled:id === 'apply' || id === 'create-user'}]));
  let userKey = 0;
  const context = {crypto:{randomUUID:() => `mock-user-attempt-${++userKey}`}, fetch:server.fetch, location:{origin:pageOrigin}, document:{getElementById:id => elements.get(id)},
    localStorage:{getItem:key => storage.get(key) ?? null, setItem:(key,value) => storage.set(key,String(value))}};
  await vm.runInNewContext(source, context, {timeout:1000, filename:'setup.js'});
  return {elements, storage, apply:() => elements.get('apply').onclick(), status:() => elements.get('status').textContent,
    createUser:async (username,password) => {
      elements.get('tour-username').value = username; elements.get('tour-password').value = password;
      let prevented = false;
      await elements.get('user-form').onsubmit({preventDefault:() => {prevented = true;}});
      assert.ok(prevented, 'user submission must suppress browser navigation');
    }, userStatus:() => elements.get('user-status').textContent};
}
const writes = server => server.requests.filter(r => r.method !== 'GET');
const resourceWrites = server => writes(server).filter(r => r.url.includes('/resource-servers/'));
const creates = server => writes(server).filter(r => r.url === apiBase+'clients');

test('normal administrator setup creates bounded audiences and assignments with CSRF', async () => {
  const plan = makePlan(), server = createServer(plan), ui = await page(plan, server);
  assert.equal(ui.elements.get('apply').disabled, false);
  await ui.apply();
  assert.match(ui.status(), /Setup complete/);
  assert.equal(creates(server).length, 2);
  assert.equal(resourceWrites(server).length, 2);
  for (const resource of plan.resources) {
    const stored = server.resources.get(resource.identifier);
    assert.deepEqual(stored.scopes, resource.scopes);
    assert.equal(stored.default_token_lifetime_seconds, 300);
    assert.deepEqual(stored.introspection_clients, resource.clients.map(key => server.idempotency.get(`fixed-create-${key}`)));
  }
  const assignments = writes(server).filter(r => /\/clients\/[^/]+\/resources$/.test(r.url));
  assert.deepEqual(assignments.map(r => r.body.resources), plan.clients.map(c => c.resources));
});

test('stored JWKS property and key-array order does not change ownership', async () => {
  const plan = makePlan();
  plan.clients[0].registration.jwks.keys.push(publicKey('second-signing-key', 'second-public-x'));
  const server = createServer(plan);
  server.currentTransform = current => ({...current, grant_types:[...current.grant_types].reverse(),
    jwks:{keys:current.jwks.keys.toReversed().map(key => Object.fromEntries(Object.entries(key).reverse()))}});
  const ui = await page(plan, server); await ui.apply();
  assert.match(ui.status(), /Setup complete/);
});

test('a foreign existing audience policy is refused without replacing its registration', async () => {
  const plan = makePlan(), server = createServer(plan);
  const foreign = {...plan.resources[0], scopes:['unrelated:scope'], introspection_clients:['existing-foreign-client']};
  delete foreign.clients; server.resources.set(foreign.identifier, clone(foreign));
  const ui = await page(plan, server); await ui.apply();
  assert.match(ui.status(), /Existing resource policy differs/);
  assert.equal(resourceWrites(server).length, 0);
  assert.deepEqual(server.resources.get(foreign.identifier), foreign);
  assert.equal(writes(server).filter(r => /\/clients\/[^/]+\/resources$/.test(r.url)).length, 0);
});

test('wrong operator host refuses before any administrator API request', async () => {
  const plan = makePlan(), server = createServer(plan);
  const ui = await page(plan, server, {pageOrigin:'https://foreign.example.test'});
  assert.match(ui.status(), /tenant\/issuer does not match/);
  assert.deepEqual(server.requests.map(r => r.url), ['plan.json']);
  assert.equal(ui.elements.get('apply').disabled, true);
});

test('lost create response retries the fixed key and retains already saved client IDs', async () => {
  const plan = makePlan(), server = createServer(plan), storage = new Map();
  server.failCreateAfterCommit = plan.clients[1].registration.client_name;
  const first = await page(plan, server, {storage}); await first.apply();
  assert.match(first.status(), /Progress is saved/);
  assert.equal(server.clients.size, 2, 'both creates committed, including the lost response');
  const resumed = await page(plan, server, {storage}); await resumed.apply();
  assert.match(resumed.status(), /Setup complete/);
  const posted = creates(server);
  assert.equal(posted.filter(r => r.body.client_name === plan.clients[0].registration.client_name).length, 1);
  assert.deepEqual(posted.filter(r => r.body.client_name === plan.clients[1].registration.client_name).map(r => r.headers['Idempotency-Key']),
    [plan.clients[1].idempotency_key, plan.clients[1].idempotency_key]);
  assert.equal(server.clients.size, 2, 'retry must not create replacement identities');
  const complete = await page(plan, server, {storage}); await complete.apply();
  assert.match(complete.status(), /Setup complete/);
  assert.equal(creates(server).length, posted.length, 'reload uses persisted IDs');
  assert.equal(resourceWrites(server).length, 2, 'equal existing resource policies are preserved');
});

test('assignment failure resumes with saved IDs and preserves created resource policies', async () => {
  const plan = makePlan(), server = createServer(plan), storage = new Map();
  server.failAssignmentOnce = true;
  const first = await page(plan, server, {storage}); await first.apply();
  assert.match(first.status(), /503/);
  const retry = await page(plan, server, {storage}); await retry.apply();
  assert.match(retry.status(), /Setup complete/);
  assert.equal(creates(server).length, 2);
  assert.equal(resourceWrites(server).length, 2);
});

test('a saved client with a different public key cannot receive resource grants', async () => {
  const plan = makePlan(), server = createServer(plan);
  server.currentTransform = current => ({...current, jwks:{keys:[publicKey('foreign-key','foreign-x')]}});
  const ui = await page(plan, server); await ui.apply();
  assert.match(ui.status(), /ownership\/key mismatch/);
  assert.equal(resourceWrites(server).length, 0);
  assert.equal(writes(server).filter(r => r.url.endsWith('/resources')).length, 0);
});

test('an administrator missing resource-write permission cannot apply through the page', async () => {
  const plan = makePlan(), server = createServer(plan);
  server.session.scopes = ['admin.clients:write'];
  const ui = await page(plan, server);
  assert.equal(ui.elements.get('apply').disabled, true);
  assert.match(ui.status(), /write permissions required/);
  assert.equal(writes(server).length, 0);
});


test('ordinary user creation clears the password and never persists it in browser storage', async () => {
  const plan = makePlan(), server = createServer(plan), ui = await page(plan, server);
  await ui.apply(); // Exercise the page's actual localStorage write path too.
  const password = 'mock-password-never-store-1234';
  await ui.createUser('tour-owned-user', password);
  assert.match(ui.userStatus(), /^Created tour-owned-user in demo with no administrator role/);
  assert.equal(ui.elements.get('tour-password').value, '');
  assert.equal(ui.elements.get('create-user').disabled, false);
  assert.ok(!JSON.stringify([...ui.storage]).includes(password));
  assert.ok(!ui.userStatus().includes(password));
  const posted = server.requests.filter(r => r.url === apiBase+'users');
  assert.equal(posted.length, 1);
  assert.deepEqual(posted[0].body, {username:'tour-owned-user', password, claims:{name:{value:'Playground user',verified:false}}});
  assert.equal(posted[0].method, 'POST');
});

test('HTTP failure never reports a user created and same-body retry keeps its attempt key', async () => {
  const plan = makePlan(), server = createServer(plan), ui = await page(plan, server);
  server.userFailureStatus = 503;
  const password = 'mock-failed-password-1234';
  await ui.createUser('tour-retry-user', password);
  assert.match(ui.userStatus(), /503/);
  assert.doesNotMatch(ui.userStatus(), /^Created /);
  assert.equal(server.users.size, 0);
  assert.equal(ui.elements.get('create-user').disabled, false);
  assert.ok(!JSON.stringify([...ui.storage]).includes(password));
  server.userFailureStatus = null;
  await ui.createUser('tour-retry-user', password);
  assert.match(ui.userStatus(), /^Created tour-retry-user/);
  const posted = server.requests.filter(r => r.url === apiBase+'users');
  assert.equal(posted.length, 2);
  assert.equal(posted[0].headers['Idempotency-Key'], posted[1].headers['Idempotency-Key']);
});

test('existing username conflicts never reset its password; changed bodies use a new attempt key', async () => {
  const plan = makePlan(), server = createServer(plan), ui = await page(plan, server);
  const existing = {username:'tour-existing-user', user_id:'existing-user-id', password:'existing-password-unchanged'};
  server.users.set(existing.username, clone(existing));
  await ui.createUser(existing.username, 'mock-first-password-1234');
  assert.match(ui.userStatus(), /409/);
  assert.doesNotMatch(ui.userStatus(), /^Created /);
  await ui.createUser(existing.username, 'mock-changed-password-5678');
  assert.match(ui.userStatus(), /409/);
  assert.deepEqual(server.users.get(existing.username), existing);
  const posted = server.requests.filter(r => r.url.startsWith(apiBase+'users'));
  assert.deepEqual(posted.map(r => [r.url,r.method]), [[apiBase+'users','POST'],[apiBase+'users','POST']]);
  assert.notEqual(posted[0].headers['Idempotency-Key'], posted[1].headers['Idempotency-Key']);
});

test('user form validates the tour prefix and minimum password before a create request', async () => {
  const plan = makePlan(), server = createServer(plan), ui = await page(plan, server);
  await ui.createUser('existing-operator', 'mock-password-long-enough');
  assert.match(ui.userStatus(), /Choose a tour-\* login/);
  await ui.createUser('tour-owned-user', 'short');
  assert.match(ui.userStatus(), /at least 12 characters/);
  assert.equal(server.requests.filter(r => r.url === apiBase+'users').length, 0);
});

test('user creation requires fresh user-write authority and makes no mutation without it', async () => {
  const plan = makePlan(), server = createServer(plan), ui = await page(plan, server);
  server.session.scopes = ['admin.clients:write','admin.resource_servers:write'];
  await ui.createUser('tour-owned-user', 'mock-password-long-enough');
  assert.match(ui.userStatus(), /User write permission required/);
  assert.equal(ui.elements.get('create-user').disabled, true);
  assert.equal(server.requests.filter(r => r.url === apiBase+'users').length, 0);
});
