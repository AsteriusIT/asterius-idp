import { useEffect, useState } from 'react';
import type { JSX } from 'react';
import { read, readUrl } from './api';
import { oidcDiscoveryUrl, oidcLinks, type OidcLink } from './tenant-list-model';
import { LoadFailure, Panel, Skeleton } from './ui';

interface TenantIdentity {
  readonly issuer: string;
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly issuer: string; readonly links: readonly OidcLink[] }
  | { readonly kind: 'failed'; readonly message: string };

function label(key: string): string {
  return key
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

/** Loads and presents the tenant's live OIDC Discovery URL members. */
export function OidcDetails({ tenant }: Readonly<{ tenant: string }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let current = true;
    setLoad({ kind: 'loading' });
    const tenantPath = `tenants/${encodeURIComponent(tenant)}`;
    read(tenantPath)
      .then((value) => readUrl(oidcDiscoveryUrl((value as TenantIdentity).issuer)))
      .then((value) => {
        if (!current) return;
        const document = value as Record<string, unknown>;
        const issuer = typeof document.issuer === 'string' ? document.issuer : null;
        if (issuer === null) {
          setLoad({ kind: 'failed', message: 'the OIDC document did not contain an issuer' });
          return;
        }
        setLoad({ kind: 'ready', issuer, links: oidcLinks(document) });
      })
      .catch((error: unknown) => {
        if (current) {
          setLoad({
            kind: 'failed',
            message: error instanceof Error ? error.message : 'the OIDC document could not be read',
          });
        }
      });
    return () => {
      current = false;
    };
  }, [attempt, tenant]);

  if (load.kind === 'loading') {
    return (
      <Panel title="OIDC endpoints" description="Loading the tenant's OpenID Connect discovery document.">
        <Skeleton rows={5} label="Reading the OIDC document." />
      </Panel>
    );
  }

  if (load.kind === 'failed') {
    return (
      <Panel title="OIDC endpoints" description="The tenant's discovery document could not be loaded.">
        <LoadFailure message={load.message} onRetry={() => setAttempt((value) => value + 1)} />
      </Panel>
    );
  }

  return (
    <Panel
      title="OIDC endpoints"
      description="Every URL advertised by this tenant's live OpenID Connect discovery document."
    >
      <p>
        <strong>Discovery document</strong>{' '}
        <a href={oidcDiscoveryUrl(load.issuer)}>{oidcDiscoveryUrl(load.issuer)}</a>
      </p>
      <dl className="oidc-links">
        {load.links.map((link) => (
          <div key={link.key}>
            <dt>{label(link.key)}</dt>
            <dd><a href={link.url}><code>{link.url}</code></a></dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}
