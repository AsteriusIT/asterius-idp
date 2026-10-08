// Verify native browser form Origin with the production gateway referrer policy.
// Uses disposable localhost pages only; no IdP, CSRF credential or live flow.
// Run: node scripts/testing/playground-form-origin-browser.mjs (Chrome required).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const config = await readFile(resolve(root, 'deploy/playground/nginx.conf'), 'utf8');
const policies = [...config.matchAll(/add_header Referrer-Policy ([^;\s]+)(?: always)?;/g)].map(match => match[1]);
assert(policies.length && policies.every(value => value === 'same-origin'));
const productionPolicy = policies[0];
const profile = await mkdtemp(resolve(tmpdir(), 'asterius-transfer-browser-'));
const observed = [];
const server = createServer(async (request, response) => {
  const origin = `http://127.0.0.1:${server.address().port}`;
  const url = new URL(request.url, origin);
  if (request.method === 'POST') {
    let body = ''; for await (const chunk of request) body += chunk;
    const admitted = request.headers.origin === origin && new URLSearchParams(body).get('csrf') === 'owned-test-challenge';
    observed.push({ origin: request.headers.origin, admitted });
    response.writeHead(admitted ? 200 : 403, { 'Content-Type': 'text/html' }).end(admitted ? '<p>Accepted</p>' : '<p>Refused</p>');
    return;
  }
  const policy = url.pathname === '/old-policy' ? 'no-referrer' : productionPolicy;
  response.writeHead(200, { 'Content-Type': 'text/html', 'Referrer-Policy': policy });
  response.end('<!doctype html><form method="post" action="/submit"><input type="hidden" name="csrf" value="owned-test-challenge"><button>Send</button></form>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const chrome = spawn(process.env.CHROME_BIN || 'google-chrome', ['--headless', '--no-sandbox', '--disable-gpu', '--no-first-run', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
let socket;
try {
  const devtools = await new Promise((resolve, reject) => {
    let output = '';
    const timeout = setTimeout(() => reject(new Error('Chrome did not expose DevTools')), 15000);
    chrome.on('error', reject);
    chrome.stderr.on('data', chunk => {
      output += chunk;
      const match = output.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) { clearTimeout(timeout); resolve(new URL(match[1])); }
    });
  });
  const targets = await (await fetch(`http://${devtools.host}/json/list`)).json();
  socket = new WebSocket(targets.find(target => target.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  let id = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const result = JSON.parse(event.data);
    if (pending.has(result.id)) { const { resolve, reject } = pending.get(result.id); pending.delete(result.id); result.error ? reject(new Error(result.error.message)) : resolve(result.result); }
  });
  function command(method, params = {}) { return new Promise((resolve, reject) => { const requestId = ++id; pending.set(requestId, { resolve, reject }); socket.send(JSON.stringify({ id: requestId, method, params })); }); }
  async function evaluate(expression) {
    const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
    return result.result.value;
  }
  async function until(expression) {
    for (let attempt = 0; attempt < 100; attempt++) { if (await evaluate(expression)) return; await new Promise(resolve => setTimeout(resolve, 50)); }
    throw new Error(`Browser condition failed: ${expression}`);
  }
  await command('Page.enable');
  await command('Network.enable');
  await command('Network.setBlockedURLs', { urls: ['*fonts.googleapis.com*', '*fonts.gstatic.com*'] });
  for (const scenario of ['old-policy', 'production', 'bad-csrf']) {
    await command('Page.navigate', { url: `${origin}/${scenario}` });
    await until("Boolean(document.querySelector('form button'))");
    if (scenario === 'bad-csrf') await evaluate("document.querySelector('input[name=csrf]').value = 'invalid'");
    await evaluate("document.querySelector('form button').click()");
    await until("document.body.innerText.includes('Accepted') || document.body.innerText.includes('Refused')");
    const result = observed.at(-1);
    assert.equal(result.origin, scenario === 'old-policy' ? 'null' : origin);
    assert.equal(result.admitted, scenario === 'production');
    console.log(`PASS form Origin browser: ${scenario}`);
  }
  for (const supplied of [undefined, 'null', 'https://foreign.example']) {
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (supplied !== undefined) headers.Origin = supplied;
    const response = await fetch(`${origin}/submit`, { method: 'POST', headers, body: 'csrf=owned-test-challenge' });
    assert.equal(response.status, 403);
  }
  console.log('PASS form Origin: absent, null and foreign origin refused with valid test CSRF');

} finally {
  socket?.close();
  chrome.kill('SIGTERM');
  if (chrome.exitCode === null) await new Promise(resolve => chrome.once('exit', resolve));
  await new Promise(resolve => server.close(resolve));
  await rm(profile, { recursive: true, force: true });
}
