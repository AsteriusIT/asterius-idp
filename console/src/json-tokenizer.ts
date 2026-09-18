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
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

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
    const character = source[cursor];
    if (character === undefined) {
      break;
    }

    if (/\s/u.test(character)) {
      let end = cursor + 1;
      while (end < source.length && /\s/u.test(source[end] ?? '')) {
        end += 1;
      }
      push('plain', source.slice(cursor, end));
      cursor = end;
      continue;
    }

    if (character === '"') {
      STRING.lastIndex = cursor;
      const match = STRING.exec(source);
      if (match !== null) {
        const text = match[0];
        let after = STRING.lastIndex;
        while (after < source.length && /\s/u.test(source[after] ?? '')) {
          after += 1;
        }
        push(source[after] === ':' ? 'key' : 'string', text);
        cursor = STRING.lastIndex;
        continue;
      }
    }

    NUMBER.lastIndex = cursor;
    const number = NUMBER.exec(source);
    if (number !== null) {
      push('number', number[0]);
      cursor = NUMBER.lastIndex;
      continue;
    }

    const keyword = ['true', 'false', 'null'].find((word) => source.startsWith(word, cursor));
    if (keyword !== undefined) {
      push(keyword === 'null' ? 'null' : 'boolean', keyword);
      cursor += keyword.length;
      continue;
    }

    if ('{}[],:'.includes(character)) {
      push('punctuation', character);
    } else {
      push('plain', character);
    }
    cursor += 1;
  }

  return tokens;
}

