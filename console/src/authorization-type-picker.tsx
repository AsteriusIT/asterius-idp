import { useEffect, useState } from 'react';
import { read, type Session } from './api';
import { LoadFailure, Panel } from './ui';

export function AuthorizationTypePicker({ session, selected, disabled, onChange }: Readonly<{
  session: Session; selected: readonly string[]; disabled: boolean; onChange: (values: readonly string[]) => void;
}>) {
  const [types, setTypes] = useState<readonly string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const allowed = session.scopes.includes('admin.authorization_details_types:read');
  useEffect(() => {
    let active = true;
    setError(null);
    if (allowed) read('authorization-details-types').then(value => {
      if (active) setTypes((value as { items: { type: string }[] }).items.map(item => item.type));
    }, reason => { if (active) setError(reason instanceof Error ? reason.message : 'Registered types could not be read.'); });
    return () => { active = false; };
  }, [allowed, retry]);
  return <Panel title="Allowed authorization detail types" description="Select the registered request types this application may use. Changes apply when the application is saved.">
    {!allowed && <p>Reading available types requires authorization-details read access. Existing selections are preserved.</p>}
    {error && <LoadFailure message={error} onRetry={() => setRetry(retry + 1)} />}
    {[...new Set([...types, ...selected])].map(type => <label className="permission" key={type}>
      <input type="checkbox" disabled={disabled || !allowed || error !== null} checked={selected.includes(type)} onChange={event => onChange(event.target.checked ? [...selected, type] : selected.filter(value => value !== type))} />
      <span>{type}{!types.includes(type) && ' (not present in the loaded catalogue)'}</span>
    </label>)}
    {allowed && !error && types.length === 0 && selected.length === 0 && <p>No types are available in the loaded catalogue.</p>}
  </Panel>;
}
