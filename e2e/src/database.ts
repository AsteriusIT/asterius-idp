/**
 * The one way a browser test reads the database under test.
 *
 * Two specs need a fact the browser is deliberately never told: the audit
 * trail a refusal left (`ast-qwu`), and the recovery link a mailbox would have
 * received (`ast-ndk.4`) — that link exists nowhere else, because the token is
 * stored as a digest.
 *
 * There is no read API for either, and inventing a production endpoint so that
 * a test can look would be a surface built for a test. So this reads the
 * tables, the way `scripts/browser-tests.sh` already seeds them.
 *
 * `psql`, and deliberately not the compose-container fallback that script
 * keeps for seeding: that one connects to the container's own `asterius`
 * database and ignores the connection string, which is harmless for a seed and
 * not harmless here — reading a *different* database would find nothing and
 * blame the server for it. A missing client is a precondition with a sentence
 * attached instead.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

/** Which database is under test. Set by `scripts/browser-tests.sh`. */
const DATABASE_URL = process.env.E2E_DATABASE_URL ?? '';

/** Quotes a value into an SQL literal. */
export function quote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

/** Runs one query and returns its rows, which the query itself makes JSON. */
export async function query(sql: string): Promise<unknown[]> {
  if (DATABASE_URL === '') {
    throw new Error(
      'E2E_DATABASE_URL is unset: run this spec through scripts/browser-tests.sh, ' +
        'which knows which database the server under test is using.',
    );
  }
  const wrapped = `select coalesce(json_agg(row_to_json(q)), '[]'::json)::text from (${sql}) q`;
  const { stdout } = await run('psql', [
    DATABASE_URL,
    '--quiet',
    '--no-psqlrc',
    '--tuples-only',
    '--no-align',
    '-c',
    wrapped,
  ]).catch((error: NodeJS.ErrnoException) => {
    throw error.code === 'ENOENT'
      ? new Error('psql is required to read the database from a browser test')
      : error;
  });
  return JSON.parse(stdout.trim() || '[]') as unknown[];
}
