/** Lossless presentation patches, never a second policy validator/evaluator. */
export type JsonObject = Record<string, unknown>;
export function object(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
export function builderDocument(text: string): JsonObject | null {
  try {
    const value: unknown = JSON.parse(text);
    return object(value) && Array.isArray(value['rules']) &&
      (value['conditional_scopes'] === undefined || Array.isArray(value['conditional_scopes'])) ? value : null;
  } catch { return null; }
}
export function writeDocument(value: JsonObject): string { return JSON.stringify(value, null, 2) + '\n'; }
export function scopeObjects(doc: JsonObject): unknown[] {
  return Array.isArray(doc['conditional_scopes']) ? doc['conditional_scopes'] : [];
}
export function uniqueID(prefix: string, values: unknown[]): string {
  const ids = new Set(values.filter(object).map(value => value['id']));
  let index = 1;
  while (ids.has(`${prefix}-${index}`)) index++;
  return `${prefix}-${index}`;
}
export function patchScope(text: string, index: number, patch: JsonObject): string {
  const doc = builderDocument(text);
  if (!doc) throw new Error('Open a readable policy document first.');
  const scopes = [...scopeObjects(doc)];
  if (!object(scopes[index])) throw new Error('This scope needs the JSON editor.');
  scopes[index] = { ...scopes[index], ...patch };
  return writeDocument({ ...doc, conditional_scopes: scopes });
}
export function addScope(text: string): string {
  const doc = builderDocument(text);
  if (!doc) throw new Error('Open a readable policy document first.');
  const scopes = scopeObjects(doc);
  return writeDocument({ ...doc, conditional_scopes: [...scopes, {
    id: uniqueID('scope', scopes), mode: 'report_only', clients: [], actions: [], rules: [],
  }] });
}
export function removeScope(text: string, index: number): string {
  const doc = builderDocument(text);
  if (!doc) throw new Error('Open a readable policy document first.');
  return writeDocument({ ...doc, conditional_scopes: scopeObjects(doc).filter((_, i) => i !== index) });
}
export const CONDITION_LABELS = {
  all: 'All conditions', any: 'Any condition', not: 'Not',
  application_sensitivity: 'Application sensitivity', acr_at_least: 'Authentication assurance',
  authentication_age_at_most: 'Maximum authentication age', network_zone: 'Network zone', device_compliance: 'Device compliance',
} as const;
export type ConditionKind = keyof typeof CONDITION_LABELS;
/** Recognize only structures we can edit without erasing siblings or data. */
export function conditionKind(value: unknown): ConditionKind | null {
  if (!object(value) || Object.keys(value).length !== 1) return null;
  const key = Object.keys(value)[0] as ConditionKind;
  const child = value[key];
  if (key === 'all' || key === 'any') return Array.isArray(child) ? key : null;
  if (key === 'not') return key;
  if (!Object.hasOwn(CONDITION_LABELS, key)) return null;
  if (key === 'authentication_age_at_most') return typeof child === 'number' || child === '' ? key : null;
  return typeof child === 'string' ? key : null;
}
export function newCondition(kind: ConditionKind): JsonObject {
  if (kind === 'all' || kind === 'any') return { [kind]: [] };
  if (kind === 'not') return { not: { application_sensitivity: 'critical' } };
  return { [kind]: kind === 'application_sensitivity' ? 'critical' : kind === 'device_compliance' ? 'compliant' : kind === 'authentication_age_at_most' ? 300 : '' };
}
export function stringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(item => typeof item === 'string');
}
export interface ScopeChange { readonly key: string; readonly change: string; readonly before: string; readonly after: string }
export function scopeChanges(baseline: string, draft: string): ScopeChange[] {
  const oldDoc = builderDocument(baseline), nextDoc = builderDocument(draft);
  if (!oldDoc || !nextDoc) return [];
  const oldScopes = scopeObjects(oldDoc), nextScopes = scopeObjects(nextDoc);
  const display = (value: unknown) => value === undefined ? 'Not present' : JSON.stringify(value);
  // Index-based comparison deliberately keeps duplicate/renamed IDs visible; it never guesses identity.
  return Array.from({ length: Math.max(oldScopes.length, nextScopes.length) }, (_, i) => {
    const before = oldScopes[i], after = nextScopes[i];
    if (JSON.stringify(before) === JSON.stringify(after)) return [];
    const name = object(after) && typeof after['id'] === 'string' ? after['id'] : `Scope ${i + 1}`;
    if (!object(before) || !object(after)) return [{ key: `${i}`, change: `${name}: ${before === undefined ? 'added' : after === undefined ? 'removed' : 'replaced'}`, before: display(before), after: display(after) }];
    return [...new Set([...Object.keys(before), ...Object.keys(after)])].flatMap(field =>
      JSON.stringify(before[field]) === JSON.stringify(after[field]) ? [] : [{ key: `${i}-${field}`, change: `${name}: ${field}`, before: display(before[field]), after: display(after[field]) }]);
  }).flat();
}
