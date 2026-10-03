/** Presentation only. The server remains the rule-language validator. */
export type ConditionalMode = 'active' | 'report_only';
export const ENFORCEMENT_ACTIONS = ['authorize', 'authorization_code', 'refresh_token', 'device_code', 'ciba', 'token_exchange', 'client_credentials', 'jwt_bearer', 'access_evaluation'] as const;
export type EnforcementAction = typeof ENFORCEMENT_ACTIONS[number];
export const EXAMPLE_FACTS = ['assurance', 'authentication_age', 'application_sensitivity', 'network_zone', 'device_compliance'] as const;
export type ExampleFactName = typeof EXAMPLE_FACTS[number];
export type Availability = 'known' | 'absent' | 'stale' | 'unavailable' | 'invalid';
export interface FactExample { readonly availability: Availability; readonly value: string }
export interface ScopePreview {
  readonly id: string; readonly mode: string; readonly clients: readonly string[];
  readonly actions: readonly string[]; readonly required_facts: readonly string[];
}
export function conditionalScopes(text: string): readonly ScopePreview[] | null {
  try {
    const value = JSON.parse(text) as { conditional_scopes?: unknown };
    if (value.conditional_scopes === undefined) return [];
    if (!Array.isArray(value.conditional_scopes)) return null;
    return value.conditional_scopes.map((scope: unknown) => {
      if (scope === null || typeof scope !== 'object') throw new Error('invalid preview');
      const s = scope as Record<string, unknown>;
      const names = (v: unknown) => Array.isArray(v) ? v.filter((n): n is string => typeof n === 'string') : [];
      return { id: typeof s['id'] === 'string' ? s['id'] : '(unnamed)', mode: typeof s['mode'] === 'string' ? s['mode'] : 'unknown', clients: names(s['clients']), actions: names(s['actions']), required_facts: names(s['required_facts']) };
    });
  } catch { return null; }
}
export function stageMode(text: string, id: string, mode: ConditionalMode): string {
  const doc = JSON.parse(text) as { conditional_scopes?: Record<string, unknown>[] };
  if (!Array.isArray(doc.conditional_scopes) || doc.conditional_scopes.filter(scope => scope['id'] === id).length !== 1) {
    throw new Error('Choose one uniquely named conditional scope in a valid JSON draft.');
  }
  return JSON.stringify({ ...doc, conditional_scopes: doc.conditional_scopes.map(scope => scope['id'] === id ? { ...scope, mode } : scope) }, null, 2) + '\n';
}
export function hasConditionalScopes(text: string): boolean { return (conditionalScopes(text)?.length ?? 0) > 0; }
export function factExamples(examples: Readonly<Partial<Record<ExampleFactName, FactExample>>>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const name of EXAMPLE_FACTS) {
    const example = examples[name];
    if (!example) continue;
    if (example.availability !== 'known') { result[name] = { availability: example.availability }; continue; }
    let value: unknown = example.value;
    if (name === 'authentication_age') {
      if (!/^\d+$/.test(example.value) || Number(example.value) > 604800) throw new Error('Authentication age must be whole seconds from 0 to 604800.');
      value = Number(example.value);
    } else if (name === 'network_zone') value = example.value.split(',').map(s => s.trim()).filter(Boolean);
    result[name] = { availability: example.availability, value };
  }
  return result;
}
