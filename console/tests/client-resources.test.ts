import assert from 'node:assert/strict';
import test from 'node:test';
import { resourceChoices } from '../src/client-resources.ts';

test('resource choices include registered audiences and stale assignments', () => {
  assert.deepEqual(
    resourceChoices(
      [
        { identifier: 'https://api.example/payments' },
        { identifier: 'https://api.example/accounts' },
      ],
      ['https://api.example/withdrawn', 'https://api.example/accounts'],
    ),
    [
      { identifier: 'https://api.example/accounts', registered: true },
      { identifier: 'https://api.example/payments', registered: true },
      { identifier: 'https://api.example/withdrawn', registered: false },
    ],
  );
});

test('resource choices deduplicate assignments', () => {
  assert.deepEqual(
    resourceChoices([], ['https://api.example', 'https://api.example']),
    [{ identifier: 'https://api.example', registered: false }],
  );
});
