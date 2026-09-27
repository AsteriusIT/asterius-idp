import type { Directory } from './users';

/** Find an exact username across search pages; API mutations still use the ID. */
export async function userIdForUsername(
  username: string,
  readPage: (path: string) => Promise<Directory>,
): Promise<string | null> {
  const seen = new Set<string>();
  let cursor: string | null = null;
  do {
    const query = new URLSearchParams({ q: username, limit: '100' });
    if (cursor !== null) query.set('cursor', cursor);
    const page = await readPage(`users?${query}`);
    const match = page.items.find((item) => item.username === username);
    if (match) return match.user_id;
    cursor = page.next_cursor;
    if (cursor !== null) {
      if (seen.has(cursor)) throw new Error('The user search repeated a page. Try again.');
      seen.add(cursor);
    }
  } while (cursor !== null);
  return null;
}
