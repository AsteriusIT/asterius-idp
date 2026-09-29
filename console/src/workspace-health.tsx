import { useEffect, useState } from 'react';
import { read, type Session } from './api';
import { visibleTo } from './navigation';
import { hrefOf } from './routes';
import { Badge, Button, Panel, Screen, Skeleton } from './ui';

const milestones = [
  { path: 'overview/users', route: 'users', label: 'Active account', detail: 'At least one person can use this workspace.' },
  { path: 'overview/applications', route: 'clients', label: 'Registered application', detail: 'An application is ready to configure.' },
  { path: 'overview/keys', route: 'keys', label: 'Active signing key', detail: 'Tokens can be signed with an active key.' },
] as const;

type Status = 'loading' | 'present' | 'missing' | 'unavailable';
export function WorkspaceHealth({ session }: Readonly<{ session: Session }>) {
  const [statuses, setStatuses] = useState<Record<string, Status>>({});
  const [refresh, setRefresh] = useState(0);
  const allowed = new Set(visibleTo(session).map(item => item.route));
  useEffect(() => {
    let active = true;
    setStatuses({});
    for (const milestone of milestones.filter(item => allowed.has(item.route))) {
      read(milestone.path).then(value => {
        if (active) setStatuses(current => ({ ...current, [milestone.path]: (value as { value: number }).value > 0 ? 'present' : 'missing' }));
      }, () => { if (active) setStatuses(current => ({ ...current, [milestone.path]: 'unavailable' })); });
    }
    return () => { active = false; };
  }, [session.workspace, refresh]);
  const visible = milestones.filter(item => allowed.has(item.route));
  return <Screen title="Workspace health" description="Configuration milestones you can inspect with your current access." actions={<Button onClick={() => setRefresh(value => value + 1)}>Refresh checks</Button>}>
    <Panel title="Workspace setup checklist" description="These checks describe saved configuration. They do not certify production readiness.">
      {visible.length === 0 ? <p>No setup checks are available to this role.</p> : <div className="health-grid">{visible.map(item => {
        const state = statuses[item.path] ?? 'loading';
        return <article className="health-card" key={item.path}>
          <div><h4>{item.label}</h4><p className="muted">{item.detail}</p></div>
          {state === 'loading' ? <Skeleton rows={1} label={`Checking ${item.label}`} /> : <Badge tone={state === 'present' ? 'ok' : state === 'missing' ? 'warn' : 'neutral'}>{state === 'present' ? 'Present' : state === 'missing' ? 'Needs setup' : 'Unavailable'}</Badge>}
          <a href={hrefOf(item.route)}>Open {item.label.toLowerCase()} →</a>
        </article>;
      })}</div>}
    </Panel>
  </Screen>;
}
