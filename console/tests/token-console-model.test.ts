import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeJwt } from '../src/token-console-model.ts';

test('JWT inspection decodes Unicode claims without interpreting the signature', () => {
  const header = { alg: 'ES256', typ: 'JWT' };
  const claims = { sub: 'user-1', name: 'Zoë', asterius_test: true };
  const jwt = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.unverified`;
  assert.deepEqual(decodeJwt(jwt), { header, claims });
});

test('JWT inspection rejects incomplete or malformed payloads', () => {
  for (const value of ['', 'header.payload', 'a.b.c.d', 'a..c', '%%%._.sig']) {
    assert.equal(decodeJwt(value), null);
  }
});
