import { useUnsavedChanges } from './navigation-guard';
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { PencilIcon, PlusIcon } from 'lucide-react';
import { mutate, probe, read, type Session } from './api';

import { draftError, parseSchema } from './authorization-details-type-model';
import { Button, ConfirmDialog, Field, LoadFailure, Message, Panel, Screen, Skeleton } from './ui';

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
  const [sample, setSample] = useState('{}');
  const [sampleResult, setSampleResult] = useState<{ valid: boolean; message?: string } | null>(null);
  const [checking, setChecking] = useState(false);
  const [name, setName] = useState('');
  const [schema, setSchema] = useState(EMPTY_SCHEMA);
  const [template, setTemplate] = useState('');
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState(false);
  const [withdrawing, setWithdrawing] = useState<string | null>(null);
  const [baseline, setBaseline] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const leave = useUnsavedChanges(editorOpen && JSON.stringify([name, schema, template]) !== baseline);
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
    setSample('{}'); setSampleResult(null);
    setName('');
    setSchema(EMPTY_SCHEMA);
    setTemplate('');
    setEditing(false);
    setError(null);
  };

  const openCreate = (): void => {
    clearDraft();
    setBaseline(JSON.stringify(['', EMPTY_SCHEMA, '']));
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

  const validateSample = async (): Promise<void> => {
    setChecking(true); setSampleResult(null);
    try {
      const result = await probe('authorization-details-types/validate-sample', session, {
        schema: parseSchema(schema), sample: JSON.parse(sample),
      });
      setSampleResult(result as { valid: boolean; message?: string });
    } catch (reason) { setSampleResult({ valid: false, message: reason instanceof Error ? reason.message : 'Validation failed.' }); }
    finally { setChecking(false); }
  };

  const withdraw = async (type: string): Promise<void> => {
    setBusy(true); setError(null); setNotice(null);
    try {
      await mutate(`authorization-details-types/${encodeURIComponent(type)}`, 'DELETE', session);
      setNotice(`${type} was withdrawn.`); setWithdrawing(null); refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The authorization details type could not be withdrawn.');
    } finally { setBusy(false); }
  };

  const edit = (item: RegisteredType): void => {
    setBaseline(JSON.stringify([item.type, JSON.stringify(item.schema, null, 2), item.consent_template ?? '']));
    setName(item.type); setSchema(JSON.stringify(item.schema, null, 2)); setTemplate(item.consent_template ?? '');
    setEditing(true); setError(null); setEditorOpen(true);
  };

  // These are the authorization detail types defined by RFC 9396. Keep that
  // implementation reference here; the operator-facing copy uses product
  // language instead of asking its reader to interpret a specification number.
  return <Screen
    title="Authorization details"
    description={`Structured authorization request types accepted by ${session.workspace}.`}
    actions={mayWrite && !editorOpen && <Button variant="primary" onClick={openCreate}><PlusIcon aria-hidden="true" /> Register type</Button>}
  >
    {notice !== null && <Message tone="success">{notice}</Message>}
    {error !== null && !editorOpen && <Message tone="error">{error}</Message>}
    {withdrawing !== null && <ConfirmDialog title={`Withdraw ${withdrawing}?`}
      body={<><p>This removes the registration from {session.workspace}. Applications depending on it may no longer obtain the expected access. Already issued tokens retain their existing validity.</p>{error && <Message tone="error">{error}</Message>}</>}
      confirmLabel="Withdraw registration" busy={busy} onCancel={() => { setWithdrawing(null); setError(null); }} onConfirm={() => void withdraw(withdrawing)} />}
    {!editorOpen && <Panel title="Registered types">
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading the authorization details types." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && (load.items.length === 0 ? <p className="muted">No authorization details types are registered.</p> :
        <div className="table-wrap"><table><caption className="visually-hidden">Registered authorization details types</caption><thead><tr><th>Type</th><th>Consent</th><th>Schema</th>{mayWrite && <th>Actions</th>}</tr></thead>
          <tbody>{load.items.map(item => <tr key={item.type}><td><code>{item.type}</code></td><td>{item.consent_template ?? 'Undescribed'}</td><td><code>{JSON.stringify(item.schema)}</code></td>
            {mayWrite && <td><Button small className="size-8 p-0" disabled={busy} aria-label={`Edit ${item.type}`} title="Edit" onClick={() => edit(item)}><PencilIcon aria-hidden="true" /></Button> <Button small variant="danger" disabled={busy} onClick={() => setWithdrawing(item.type)}>Withdraw</Button></td>}</tr>)}</tbody></table></div>)}
    </Panel>}
    {mayWrite && editorOpen && <section className="schema-editor" aria-label="Authorization type editor">
      <h3>{editing ? 'Edit authorization details type' : 'Register authorization details type'}</h3>
      <p className="muted">Validate the schema and review the consent wording before saving. The server validates the supported schema rules.</p>
        {error !== null && <Message tone="error">{error}</Message>}
        <Field label="Type name">{props => <input {...props} value={name} disabled={editing} onChange={event => setName(event.target.value)} placeholder="payment_initiation" />}</Field>
        <Field label="Consent template" hint="A user-facing sentence, up to 512 characters. Leave blank to mark the type undescribed.">{props => <input {...props} value={template} maxLength={512} onChange={event => setTemplate(event.target.value)} placeholder="Initiate the described payment" />}</Field>
        <Field label="JSON Schema" hint="Supported: type, required, properties, additionalProperties, enum, maxLength, items, maxItems, title, description.">{props => <textarea {...props} rows={12} value={schema} disabled={checking} onChange={event => { setSchema(event.target.value); setSampleResult(null); }} spellCheck={false} />}</Field>
        <Panel title="Test a sample" description="Uses the server’s authorization schema validator. This does not save the schema, issue a token or authorize a request.">
          <Field label="Sample JSON">{props => <textarea {...props} rows={6} value={sample} spellCheck={false} disabled={checking} onChange={event => { setSample(event.target.value); setSampleResult(null); }} />}</Field>
          <Button disabled={checking || busy} onClick={() => void validateSample()}>{checking ? 'Checking sample…' : 'Validate sample'}</Button>
          {sampleResult && <Message tone={sampleResult.valid ? 'success' : 'error'}>{sampleResult.valid ? 'The sample matches the schema.' : sampleResult.message ?? 'The sample does not match the schema.'}</Message>}
        </Panel>
        <Panel title="Consent wording preview" description="This is the operator-provided wording; the actual request may also show its actions, data and locations.">
          <p>{template.trim() || 'Perform an action this server has no description for'}</p><code>{name || 'Type name'}</code>
        </Panel>
        <div className="actions">
          <Button disabled={busy} onClick={() => leave(() => { setEditorOpen(false); clearDraft(); })}>Cancel</Button>
          <Button variant="primary" disabled={busy} onClick={() => void save()}>{busy ? 'Validating…' : editing ? 'Save changes' : 'Validate and register'}</Button>
        </div>
    </section>}
  </Screen>;
}
