import assert from 'node:assert/strict';
import test from 'node:test';
import { documentOf, draftOf, isDirty, refusalField, validateDraft, type ThemeDocument, type ThemeSchema } from '../src/branding-model.ts';

const theme: ThemeDocument = {
  palette: { background: '#ffffff', text: '#18181b', muted_text: '#71717a', accent: '#3f3fbf', accent_text: '#ffffff', danger: '#b42318' },
  font: 'geist', radius_px: 8, spacing_px: 8,
};
const schema: ThemeSchema = { properties: { font: { enum: ['geist', 'system-sans'] }, product_name: { maxLength: 64 }, support: { properties: { help_url: { maxLength: 256 } } } } };

test('a draft round trip keeps the effective saved document', () => {
  assert.deepEqual(documentOf(draftOf(theme)), theme);
  assert.equal(isDirty(theme, draftOf(theme)), false);
});

test('invalid colours, contrast, links and scales identify their fields', () => {
  const draft = { ...draftOf(theme), palette: { ...theme.palette, accent: '#fff', muted_text: '#eeeeee' }, radius: '25', helpUrl: 'javascript:alert(1)' };
  const errors = validateDraft(draft, schema);
  assert.match(errors.accent ?? '', /six-digit/);
  assert.match(errors.muted_text ?? '', /contrast/);
  assert.match(errors.radius ?? '', /0 to 24/);
  assert.match(errors.helpUrl ?? '', /HTTPS/);
});

test('a server JSON pointer is returned to the matching field', () => {
  assert.equal(refusalField('`/support/privacy_url` is not an absolute https URL'), 'privacyUrl');
  assert.equal(refusalField('storage unavailable'), null);
});
