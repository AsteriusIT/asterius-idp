import assert from 'node:assert/strict';
import test from 'node:test';
import { cookies, escapeHtml, sessionCookie } from './demo.mjs';

test('session cookies are host-safe and cross-site resistant', () => {
  assert.equal(sessionCookie('demo_a', 'session', '/demo-a', true), 'demo_a=session; Path=/demo-a; HttpOnly; SameSite=Lax; Secure');
  assert.deepEqual(cookies('a=1; demo_a=abc'), { a: '1', demo_a: 'abc' });
});

test('dynamic claims are escaped before rendering', () => {
  assert.equal(escapeHtml('<script>"x" & y</script>'), '&lt;script&gt;&quot;x&quot; &amp; y&lt;/script&gt;');
});
