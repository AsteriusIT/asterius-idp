import assert from 'node:assert/strict';
import test from 'node:test';
import { userIdForUsername } from '../src/user-lookup.ts';
import type { Directory, UserRow } from '../src/users.tsx';

function user(username: string, userId: string): UserRow {
  return { user_id: userId, username, email: null, email_verified: false,
    status: 'active', can_authenticate: true, claims: 0, created_at: 0, updated_at: 0 };
}

test('username lookup scans pages for an exact name and keeps the ID internal', async () => {
  const paths: string[] = [];
  const id = await userIdForUsername('alex', async (path): Promise<Directory> => {
    paths.push(path);
    return paths.length === 1
      ? { items: [user('alexander', 'wrong')], next_cursor: 'next/page' }
      : { items: [user('alex', 'internal-id')], next_cursor: null };
  });
  assert.equal(id, 'internal-id');
  assert.deepEqual(paths, ['users?q=alex&limit=100', 'users?q=alex&limit=100&cursor=next%2Fpage']);
});

test('username lookup returns no match after the final page', async () => {
  assert.equal(await userIdForUsername('missing', async () => ({ items: [], next_cursor: null })), null);
});
