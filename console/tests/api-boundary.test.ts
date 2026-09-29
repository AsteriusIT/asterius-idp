import assert from 'node:assert/strict';
import { test } from 'node:test';
import { read, readUrl, mutate, type Session } from '../src/api.ts';

test('console requests cannot escape the current workspace or send writes to public endpoints', async t => {
  const originalFetch = globalThis.fetch;
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { location: new URL('https://id.example/t/review/admin/#/users') } });
  const calls: string[] = [];
  globalThis.fetch = async target => { calls.push(String(target)); return new Response('{}', { status: 200 }); };
  t.after(() => {
    globalThis.fetch = originalFetch;
    if (originalWindow) Object.defineProperty(globalThis, 'window', originalWindow);
    else Reflect.deleteProperty(globalThis, 'window');
  });
  for (const path of ['../../../../t/other/admin/api/v1/users', '%2e%2e/%2e%2e/logout', 'users#fragment']) {
    await assert.rejects(read(path), /current console workspace/);
  }
  for (const url of ['https://outside.example/.well-known/openid-configuration', 'https://person:password@id.example/.well-known/openid-configuration', 'https://id.example/account', 'https://id.example/.well-known/openid-configuration?untrusted=yes']) {
    await assert.rejects(readUrl(url), /current console workspace/);
  }
  await assert.rejects(mutate('../../.well-known/openid-configuration', 'PUT', { csrf_token: 'fixture' } as Session), /current console workspace/);
  assert.equal(calls.length, 0);
  await read('users/alex?section=sessions');
  await readUrl('https://id.example/t/review/.well-known/openid-configuration');
  assert.deepEqual(calls, ['https://id.example/t/review/admin/api/v1/users/alex?section=sessions', 'https://id.example/t/review/.well-known/openid-configuration']);
});
