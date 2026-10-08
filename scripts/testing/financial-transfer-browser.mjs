// Controlled browser checks for the built example. No IdP, credentials or live ledger.
// Run npm ci && npm run build in examples/webapp, then node this file.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const dist = resolve(root, 'examples/webapp/dist');
const profile = await mkdtemp(resolve(tmpdir(), 'asterius-transfer-browser-'));
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    const asset = path.startsWith('/financial/assets/') ? path.slice('/financial/'.length) : 'index.html';
    assert(!asset.includes('..'));
    response.setHeader('Content-Type', asset.endsWith('.js') ? 'text/javascript' : asset.endsWith('.css') ? 'text/css' : 'text/html');
    response.end(await readFile(resolve(dist, asset)));
  } catch { response.writeHead(404).end(); }
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
  for (const scenario of ['rejected', 'forbidden', 'success', 'signed-out']) {
    const injected = await command('Page.addScriptToEvaluateOnNewDocument', { source: `
      window.testPosts = []; window.testHistory = [];
      window.fetch = async (url, options = {}) => {
        const status = ${JSON.stringify(scenario)};
        const reply = (body, code = 200) => new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } });
        if (String(url).endsWith('/api/session')) return reply({ authenticated: status !== 'signed-out' });
        if (status === 'signed-out') return reply({ error: 'login_required' }, 401);
        if (String(url).endsWith('/api/accounts')) return reply({ accounts: [{id:'checking',name:'Checking',currency:'EUR',balance:100},{id:'savings',name:'Savings',currency:'EUR',balance:50}] });
        if (options.method === 'POST') {
          window.testPosts.push({ url, options, body: JSON.parse(options.body) });
          if (status === 'rejected') return reply({error:'invalid_transfer'},400);
          if (status === 'forbidden') return reply({error:'insufficient_scope'},403);
          const transfer = { id:'owned-fixture', ...JSON.parse(options.body) }; window.testHistory.push(transfer); return reply(transfer,201);
        }
        return reply({ transfers: window.testHistory });
      };` });
    await command('Page.navigate', { url: `${origin}/financial/transfers` });
    if (scenario === 'signed-out') {
      await until("document.body.innerText.includes('sign in with Asterius') && !document.querySelector('.transfer-form')");
      assert.equal(await evaluate('window.testPosts.length'), 0);
    } else {
      await until("Boolean(document.querySelector('.transfer-form input[type=number]'))");
      await evaluate(`(() => { const input = document.querySelector('input[type=number]'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'5'); input.dispatchEvent(new Event('input',{bubbles:true})); const ref = document.querySelector('input[type=text]'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(ref,'browser-fixture'); ref.dispatchEvent(new Event('input',{bubbles:true})); })()`);
      await evaluate("document.querySelector('button[type=submit]').click()");
      await until("Boolean(document.querySelector('[role=alert], [role=status]')) && !document.body.innerText.includes('Sending…')");
      const post = await evaluate('window.testPosts[0]');
      assert.equal(post.options.credentials, 'include');
      assert.equal(post.options.headers['Content-Type'], 'application/json');
      assert.deepEqual(post.body, { from: 'checking', to: 'savings', amount: 5, reference: 'browser-fixture' });
      if (scenario === 'success') {
        await until("Boolean(document.querySelector('.transfer'))");
        assert.equal(await evaluate("document.querySelector('[role=status]').textContent"), 'Transfer recorded.');
        assert.equal(await evaluate("document.querySelector('input[type=number]').value"), '');
        assert.equal(await evaluate("document.querySelector('.transfer').textContent.includes('browser-fixture')"), true);
      } else {
        assert.equal(await evaluate("Boolean(document.querySelector('[role=status]'))"), false);
        assert.equal(await evaluate("document.querySelectorAll('.transfer').length"), 0);
        assert.equal(await evaluate("document.querySelector('input[type=number]').value"), '5');
        assert.equal(await evaluate('window.testHistory.length'), 0);
        if (scenario === 'forbidden') assert.equal(await evaluate("document.querySelector('fieldset').disabled"), true);
      }
    }
    console.log(`PASS financial browser: ${scenario}`);
    await command('Page.removeScriptToEvaluateOnNewDocument', { identifier: injected.identifier });
  }
} finally {
  socket?.close();
  chrome.kill('SIGTERM');
  if (chrome.exitCode === null) await new Promise(resolve => chrome.once('exit', resolve));
  await new Promise(resolve => server.close(resolve));
  await rm(profile, { recursive: true, force: true });
}
