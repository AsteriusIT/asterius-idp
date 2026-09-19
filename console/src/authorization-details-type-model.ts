export interface AuthorizationDetailsTypeDraft {
  readonly name: string;
  readonly schema: string;
  readonly consentTemplate: string;
}

export function typeNameError(name: string): string | null {
  if (name.length === 0 || name.length > 128 || !/^[!-~]+$/.test(name) || /["\\]/.test(name)) {
    return 'Use 1–128 printable ASCII characters, without quotes or backslashes.';
  }
  return null;
}

export function parseSchema(source: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(source);
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('The schema must be a JSON object.');
  }
  return parsed as Record<string, unknown>;
}

export function draftError(draft: AuthorizationDetailsTypeDraft): string | null {
  const name = typeNameError(draft.name);
  if (name !== null) return name;
  if ([...draft.consentTemplate].length > 512) return 'The consent template must be at most 512 characters.';
  try {
    parseSchema(draft.schema);
    return null;
  } catch (error) {
    return error instanceof SyntaxError ? `The schema is not valid JSON: ${error.message}` : (error as Error).message;
  }
}
