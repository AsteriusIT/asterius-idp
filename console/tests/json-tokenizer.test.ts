import assert from 'node:assert/strict';
import { test } from 'node:test';
import { tokenizeJson } from '../src/json-tokenizer.ts';

function kinds(source: string): readonly (readonly [string, string])[] {
  return tokenizeJson(source)
    .filter((token) => token.kind !== 'plain')
    .map((token) => [token.kind, token.text]);
}

test('distinguishes keys from strings containing escaped quotes', () => {
  assert.deepEqual(kinds('{"message":"say \\"hello\\""}'), [
    ['punctuation', '{'],
    ['key', '"message"'],
    ['punctuation', ':'],
    ['string', '"say \\"hello\\""'],
    ['punctuation', '}'],
  ]);
});

test('recognises negative exponent numbers, booleans and null', () => {
  assert.deepEqual(kinds('[-12.5e+3,true,false,null]'), [
    ['punctuation', '['],
    ['number', '-12.5e+3'],
    ['punctuation', ','],
    ['boolean', 'true'],
    ['punctuation', ','],
    ['boolean', 'false'],
    ['punctuation', ','],
    ['null', 'null'],
    ['punctuation', ']'],
  ]);
});

test('preserves empty objects and nested arrays byte for byte', () => {
  for (const source of ['{}', '[[1],[],[{"ok":true}]]']) {
    assert.equal(
      tokenizeJson(source)
        .map((token) => token.text)
        .join(''),
      source,
    );
  }
});

