import type { JSX } from 'react';
import { CopyIcon } from 'lucide-react';
import { tokenizeJson } from '../json-tokenizer';
import { Button } from '../ui';
import { toast } from './ui/toast';

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
  const lines = source.split('\n').length;

  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(source);
      toast.success('JSON copied');
    } catch {
      toast.error('Could not copy the JSON');
    }
  };

  return (
    <div className="json-view">
      <div className="json-toolbar">
        <span className="muted">
          {lines} {lines === 1 ? 'line' : 'lines'}
        </span>
        <Button small onClick={() => void copy()} aria-label={`Copy ${label}`}>
          <CopyIcon aria-hidden="true" />
          Copy
        </Button>
      </div>
      <pre className="json-code" tabIndex={0} role="region" aria-label={label}>
        <code>
          <Highlighted source={source} />
        </code>
      </pre>
    </div>
  );
}
