import { useEffect, useState } from 'react';
import type { JSX } from 'react';
import { read, type Session } from './api';
import { hrefOf } from './routes';

export interface FlowOriginLink {
  flow_id: string;
  flow_name: string;
  node_id: string;
  relation: 'managed' | 'reference';
  state: 'pending' | 'applied';
}

export function FlowOrigin({ session, kind, resource }: {
  session: Session; kind: 'application' | 'api' | 'group' | 'role' | 'identity_provider' | 'stream'; resource: string;
}): JSX.Element | null {
  const [links, setLinks] = useState<FlowOriginLink[]>([]);
  useEffect(() => {
    if (!session.scopes.includes('admin.flows:read') || !resource) return;
    let active = true;
    read(`flow-origins?${new URLSearchParams({ kind, id: resource })}`).then(
      value => { if (active) setLinks((value as { items: FlowOriginLink[] }).items); },
      () => { if (active) setLinks([]); },
    );
    return () => { active = false; };
  }, [kind, resource, session.scopes]);
  if (links.length === 0) return null;
  return <div className="flow-origin">{links.map(link =>
    <a key={`${link.flow_id}:${link.node_id}`} href={hrefOf('architecture', { flow: link.flow_id, node: link.node_id })}>
      {link.relation === 'managed' ? 'Created by' : 'Referenced in'} {link.flow_name}
      {link.state === 'pending' ? ' · apply pending' : ''} →
    </a>)}</div>;
}
