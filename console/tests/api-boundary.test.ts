import assert from 'node:assert/strict';
import { test } from 'node:test';
import { read, readUrl, mutate, ApiError, type Session } from '../src/api.ts';

test('console requests cannot escape the current workspace or send writes to public endpoints', async t => {
  const originalFetch = globalThis.fetch;
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { location: new URL('https://id.example/t/review/admin/#/users') } });
  const calls: string[] = [];
  globalThis.fetch = async target => { calls.push(new URL(String(target), 'https://id.example/t/review/admin/').href); return new Response('{}', { status: 200 }); };
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


test('API failures expose only validated server support references', async t => {
  const originalFetch = globalThis.fetch;
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { location: new URL('https://id.example/t/review/admin/#/audit') } });
  t.after(() => {
    globalThis.fetch = originalFetch;
    if (originalWindow) Object.defineProperty(globalThis, 'window', originalWindow);
    else Reflect.deleteProperty(globalThis, 'window');
  });
  const reference = 'a'.repeat(32);
  globalThis.fetch = async () => new Response('{"error":{"message":"Access denied"}}', { status: 403, headers: { 'X-Asterius-Request-ID': reference } });
  await assert.rejects(read('audit/events'), error => error instanceof ApiError && error.status === 403 && error.supportReference === reference && error.message.includes(reference));
  globalThis.fetch = async () => new Response('{}', { status: 403, headers: { 'X-Asterius-Request-ID': 'caller-owned-echo' } });
  await assert.rejects(read('audit/events'), error => error instanceof ApiError && error.supportReference === undefined && !error.message.includes('caller-owned-echo'));
});
