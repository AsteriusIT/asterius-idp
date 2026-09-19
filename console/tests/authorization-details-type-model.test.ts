import assert from 'node:assert/strict';
import { test } from 'node:test';
import { draftError, parseSchema, typeNameError } from '../src/authorization-details-type-model.ts';

test('type names follow the server token rules', () => {
  assert.equal(typeNameError('payment_initiation'), null);
  assert.notEqual(typeNameError('payment type'), null);
  assert.notEqual(typeNameError('quoted"type'), null);
});

test('schema input must be a JSON object', () => {
  assert.deepEqual(parseSchema('{"type":"object"}'), { type: 'object' });
  assert.throws(() => parseSchema('[]'), /JSON object/);
  assert.match(draftError({ name: 'payment', schema: '{', consentTemplate: '' }) ?? '', /not valid JSON/);
});
