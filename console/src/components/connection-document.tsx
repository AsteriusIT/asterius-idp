import type { ReactNode } from 'react';
import { ArrowUpRightIcon } from 'lucide-react';
import { CopyValue } from './copy-value';

/** A consistent reference row for values developers transfer to their application. */
export function ConnectionDocument({ entries }: Readonly<{
  entries: readonly { label: string; value: string; description?: ReactNode; href?: string }[];
}>) {
  return <dl className="connection-document">
    {entries.map(entry => <div className="connection-entry" key={entry.label}>
      <dt>{entry.label}{entry.description && <span className="muted">{entry.description}</span>}</dt>
      <dd><code>{entry.value}</code>
        <span className="connection-entry-actions">
          {entry.href && <a href={entry.href} target="_blank" rel="noreferrer" aria-label={`Open ${entry.label}`} title={`Open ${entry.label}`}><ArrowUpRightIcon aria-hidden="true" /></a>}
          <CopyValue value={entry.value} label={`Copy ${entry.label}`} iconOnly />
        </span>
      </dd>
    </div>)}
  </dl>;
}
