import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { PencilIcon, PlusIcon } from 'lucide-react';
import { mutate, read, type Session } from './api';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './components/ui/dialog';
import { draftError, parseSchema } from './authorization-details-type-model';
import { Button, Field, LoadFailure, Message, Panel, Screen, Skeleton } from './ui';

interface RegisteredType {
  readonly type: string;
  readonly schema: Record<string, unknown>;
  readonly consent_template: string | null;
}

type Load = { readonly kind: 'loading' } | { readonly kind: 'failed'; readonly message: string }
  | { readonly kind: 'ready'; readonly items: readonly RegisteredType[] };

const EMPTY_SCHEMA = JSON.stringify({ type: 'object' }, null, 2);

export function AuthorizationDetailsTypes({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [name, setName] = useState('');
  const [schema, setSchema] = useState(EMPTY_SCHEMA);
  const [template, setTemplate] = useState('');
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mayWrite = session.scopes.includes('admin.authorization_details_types:write');

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read('authorization-details-types').then(
      value => setLoad({ kind: 'ready', items: (value as { items: readonly RegisteredType[] }).items }),
      reason => setLoad({ kind: 'failed', message: reason instanceof Error ? reason.message : 'The registered types could not be read.' }),
    );
  }, []);
  useEffect(refresh, [refresh]);

  const clearDraft = (): void => {
    setName('');
    setSchema(EMPTY_SCHEMA);
    setTemplate('');
    setEditing(false);
    setError(null);
  };

  const openCreate = (): void => {
    clearDraft();
    setEditorOpen(true);
  };

  const save = async (): Promise<void> => {
    const validation = draftError({ name, schema, consentTemplate: template });
    if (validation !== null) { setError(validation); return; }
    setBusy(true); setError(null); setNotice(null);
    try {
      await mutate(`authorization-details-types/${encodeURIComponent(name)}`, 'PUT', session, {
        schema: parseSchema(schema), consent_template: template === '' ? null : template,
      });
      setNotice(`${name} is registered.`); setEditorOpen(false); clearDraft(); refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The authorization details type could not be saved.');
    } finally { setBusy(false); }
  };

  const withdraw = async (type: string): Promise<void> => {
    setBusy(true); setError(null); setNotice(null);
    try {
      await mutate(`authorization-details-types/${encodeURIComponent(type)}`, 'DELETE', session);
      setNotice(`${type} was withdrawn.`); refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The authorization details type could not be withdrawn.');
    } finally { setBusy(false); }
  };

  const edit = (item: RegisteredType): void => {
    setName(item.type); setSchema(JSON.stringify(item.schema, null, 2)); setTemplate(item.consent_template ?? '');
    setEditing(true); setError(null); setEditorOpen(true);
  };

  // These are the authorization detail types defined by RFC 9396. Keep that
  // implementation reference here; the operator-facing copy uses product
  // language instead of asking its reader to interpret a specification number.
  return <Screen
    title="Authorization details"
    description={`Structured authorization request types accepted by ${session.workspace}.`}
    actions={mayWrite && <Button variant="primary" onClick={openCreate}><PlusIcon aria-hidden="true" /> Register type</Button>}
  >
    {notice !== null && <Message tone="success">{notice}</Message>}
    {error !== null && !editorOpen && <Message tone="error">{error}</Message>}
    <Panel title="Registered types">
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading the authorization details types." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && (load.items.length === 0 ? <p className="muted">No authorization details types are registered.</p> :
        <table><caption className="visually-hidden">Registered authorization details types</caption><thead><tr><th>Type</th><th>Consent</th><th>Schema</th>{mayWrite && <th>Actions</th>}</tr></thead>
          <tbody>{load.items.map(item => <tr key={item.type}><td><code>{item.type}</code></td><td>{item.consent_template ?? 'Undescribed'}</td><td><code>{JSON.stringify(item.schema)}</code></td>
            {mayWrite && <td><Button small className="size-8 p-0" disabled={busy} aria-label={`Edit ${item.type}`} title="Edit" onClick={() => edit(item)}><PencilIcon aria-hidden="true" /></Button> <Button small variant="danger" disabled={busy} onClick={() => void withdraw(item.type)}>Withdraw</Button></td>}</tr>)}</tbody></table>)}
    </Panel>
    {mayWrite && <Dialog open={editorOpen} onOpenChange={(open) => {
      if (busy) return;
      setEditorOpen(open);
      if (!open) clearDraft();
    }}>
      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{editing ? 'Edit authorization details type' : 'Register authorization details type'}</DialogTitle>
          <DialogDescription>Schemas use the supported JSON Schema subset and are validated again by the server.</DialogDescription>
        </DialogHeader>
        {error !== null && <Message tone="error">{error}</Message>}
        <Field label="Type name">{props => <input {...props} value={name} disabled={editing} onChange={event => setName(event.target.value)} placeholder="payment_initiation" />}</Field>
        <Field label="Consent template" hint="A user-facing sentence, up to 512 characters. Leave blank to mark the type undescribed.">{props => <input {...props} value={template} maxLength={512} onChange={event => setTemplate(event.target.value)} placeholder="Initiate the described payment" />}</Field>
        <Field label="JSON Schema" hint="Supported: type, required, properties, additionalProperties, enum, maxLength, items, maxItems, title, description.">{props => <textarea {...props} rows={12} value={schema} onChange={event => setSchema(event.target.value)} spellCheck={false} />}</Field>
        <DialogFooter>
          <Button disabled={busy} onClick={() => { setEditorOpen(false); clearDraft(); }}>Cancel</Button>
          <Button variant="primary" disabled={busy} onClick={() => void save()}>{busy ? 'Validating…' : editing ? 'Save changes' : 'Validate and register'}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>}
  </Screen>;
}
