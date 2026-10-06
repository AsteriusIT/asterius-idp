import { useEffect, useState } from 'react';
import { read, type Session } from './api';
import { hrefOf } from './routes';
import { Badge, Panel, Timestamp } from './ui';

export function UserAccessSummary({ userId, grants, session }: Readonly<{ userId: string; grants: number; session: Session }>) {
  const mayAudit = session.scopes.includes('admin.audit:read');
  const [recent, setRecent] = useState<{ id?: string | number; occurred_at: string; outcome: string; opaque?: string }[]>([]);
  const [last, setLast] = useState<string | null>(null);
  const [status, setStatus] = useState('Reading the audit trail…');
  useEffect(() => {
    let active = true;
    setRecent([]); setLast(null); setStatus('Reading the audit trail…');
    if (mayAudit) void (async () => {
      let cursor: string | null = null;
      try {
        for (let page = 0; page < 10 && active; page++) {
          const query = new URLSearchParams({ user: userId, type: 'auth.login', limit: '100' });
          if (cursor) query.set('cursor', cursor);
          const value = await read(`audit/events?${query}`) as { items: { id?: string | number; opaque?: string; occurred_at: string; outcome: string }[]; next_cursor: string | null };
          if (!active) return;
          setRecent(previous => [...previous, ...value.items.filter(event => !event.opaque && event.occurred_at && event.outcome)].slice(0, 5));
          const event = value.items.find(event => !event.opaque && event.outcome === 'success');
          if (event) { setLast(event.occurred_at); return; }
          if (!value.next_cursor) { setStatus('No successful sign-in was found in the retained audit trail.'); return; }
          cursor = value.next_cursor;
        }
        if (active) setStatus('No success in the latest 1,000 attempts. Open Audit to inspect older events.');
      } catch { if (active) setStatus('The last recorded sign-in could not be read.'); }
    })();
    return () => { active = false; };
  }, [mayAudit, userId]);
  return <Panel title="Access overview" description="Review assigned access and recorded activity. Roles and grants do not by themselves guarantee an access-policy decision.">
    <dl className="stats">
      <div><dt>Connected application grants</dt><dd><a href={hrefOf('users', { id: userId, tab: 'grants' })}>{grants} grants</a></dd></div>
      <div><dt>Last recorded sign-in</dt><dd>{!mayAudit ? 'Requires audit access.' : last ? <Timestamp value={last} /> : status}</dd></div>
    </dl>
    {mayAudit && recent.length > 0 && <section className="signin-activity"><h3>Recent sign-ins</h3><ol aria-label="Recent sign-in activity">{recent.map((event, index) => <li key={event.id ?? index}><Badge tone={event.outcome === 'success' ? 'ok' : 'neutral'}>{event.outcome}</Badge><Timestamp value={event.occurred_at} />{event.id && <a href={hrefOf('audit', { id: String(event.id) })}>Inspect event</a>}</li>)}</ol></section>}
    {session.scopes.includes('admin.app_roles:read') && <a href={hrefOf('users', { id: userId, tab: 'roles' })}>Review direct and group-inherited roles →</a>}
  </Panel>;
}
