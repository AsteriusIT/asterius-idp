import type { JSX } from 'react';
import { tokenizeJson } from '../json-tokenizer';
import { CodePanel } from './code-panel';

function serialise(value: unknown, pretty: boolean): string {
  const rendered = JSON.stringify(value, null, pretty ? 2 : undefined);
  return rendered ?? 'null';
}

function Highlighted({ source }: Readonly<{ source: string }>): JSX.Element {
  return (
    <>
      {tokenizeJson(source).map((token, index) => (
        <span className={`json-token json-${token.kind}`} key={`${index}-${token.kind}`}>
          {token.text}
        </span>
      ))}
    </>
  );
}

/** Compact syntax-highlighted JSON for a table cell or description value. */
export function JsonValue({ value }: Readonly<{ value: unknown }>): JSX.Element {
  const source = serialise(value, false);
  return (
    <code className="json-inline" title={source}>
      <Highlighted source={source} />
    </code>
  );
}

/**
 * A readable JSON document whose own region scrolls instead of widening the
 * page. Long string tokens may wrap, so a single RSA modulus does not turn the
 * region into a several-screen-wide strip.
 */
export function JsonView({ value, label }: Readonly<{ value: unknown; label: string }>): JSX.Element {
  const source = serialise(value, true);
  return <JsonSourceView source={source} label={label} />;
}

/** A pre-serialized policy revision retains its original source representation. */
export function JsonSourceView({ source, label }: Readonly<{ source: string; label: string }>): JSX.Element {
  return <CodePanel source={source} label={label} language="JSON" renderLine={line => <Highlighted source={line} />} />;
}
