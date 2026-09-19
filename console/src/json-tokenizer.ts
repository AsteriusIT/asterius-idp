/** The six lexical kinds a JSON document can display. */
export type JsonTokenKind =
  | 'key'
  | 'string'
  | 'number'
  | 'boolean'
  | 'null'
  | 'punctuation'
  | 'plain';

/** One contiguous piece of JSON source, preserved byte for byte. */
export interface JsonToken {
  readonly kind: JsonTokenKind;
  readonly text: string;
}

const STRING = /"(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\])*"/y;
const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

interface TokenMatch {
  readonly kind: JsonTokenKind;
  readonly text: string;
  readonly end: number;
}

function whitespaceEnd(source: string, start: number): number {
  let end = start;
  while (end < source.length && /\s/u.test(source[end] ?? '')) {
    end += 1;
  }
  return end;
}

function stringToken(source: string, cursor: number): TokenMatch | null {
  if (source[cursor] !== '"') {
    return null;
  }
  STRING.lastIndex = cursor;
  const match = STRING.exec(source);
  if (match === null) {
    return null;
  }
  const after = whitespaceEnd(source, STRING.lastIndex);
  return {
    kind: source[after] === ':' ? 'key' : 'string',
    text: match[0],
    end: STRING.lastIndex,
  };
}

function numberToken(source: string, cursor: number): TokenMatch | null {
  NUMBER.lastIndex = cursor;
  const match = NUMBER.exec(source);
  return match === null
    ? null
    : { kind: 'number', text: match[0], end: NUMBER.lastIndex };
}

function keywordToken(source: string, cursor: number): TokenMatch | null {
  const keyword = ['true', 'false', 'null'].find((word) => source.startsWith(word, cursor));
  return keyword === undefined
    ? null
    : {
        kind: keyword === 'null' ? 'null' : 'boolean',
        text: keyword,
        end: cursor + keyword.length,
      };
}

function tokenAt(source: string, cursor: number): TokenMatch {
  const end = whitespaceEnd(source, cursor);
  if (end !== cursor) {
    return { kind: 'plain', text: source.slice(cursor, end), end };
  }

  const matched = stringToken(source, cursor) ?? numberToken(source, cursor) ?? keywordToken(source, cursor);
  if (matched !== null) {
    return matched;
  }

  const character = source[cursor] ?? '';
  return {
    kind: '{}[],:'.includes(character) ? 'punctuation' : 'plain',
    text: character,
    end: cursor + 1,
  };
}

/**
 * Splits valid JSON source for presentation without parsing or rewriting it.
 *
 * The caller normally supplies `JSON.stringify` output, but unmatched input
 * is deliberately returned as `plain` rather than throwing: highlighting is
 * presentation and must never become a second JSON validator.
 */
export function tokenizeJson(source: string): readonly JsonToken[] {
  const tokens: JsonToken[] = [];
  let cursor = 0;

  const push = (kind: JsonTokenKind, text: string): void => {
    const previous = tokens.at(-1);
    if (previous?.kind === kind) {
      tokens[tokens.length - 1] = { kind, text: previous.text + text };
    } else {
      tokens.push({ kind, text });
    }
  };

  while (cursor < source.length) {
    const token = tokenAt(source, cursor);
    push(token.kind, token.text);
    cursor = token.end;
  }

  return tokens;
}
