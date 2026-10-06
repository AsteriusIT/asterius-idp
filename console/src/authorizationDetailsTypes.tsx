import { JsonDraftEditor } from './components/json-draft-editor';
import { DetailSheet } from './components/detail-sheet';
import { JsonView } from './components/json-view';
import { FieldGroup } from './components/ui/field';
import { useUnsavedChanges } from './navigation-guard';
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { PencilIcon, PlusIcon } from 'lucide-react';
import { mutate, probe, read, type Session } from './api';

import { draftError, parseSchema } from './authorization-details-type-model';
import { Actions, Button, ConfirmDialog, DataTable, EmptyState, Field, LoadFailure, Message, Panel, Screen, Skeleton } from './ui';

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
  const [inspecting, setInspecting] = useState<RegisteredType | null>(null);
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
    setSample('{}'); setSampleResult(null);
    setBaseline(JSON.stringify([item.type, JSON.stringify(item.schema, null, 2), item.consent_template ?? '']));
    setName(item.type); setSchema(JSON.stringify(item.schema, null, 2)); setTemplate(item.consent_template ?? '');
    setEditing(true); setError(null); setEditorOpen(true);
  };
  const closeEditor = (): void => leave(() => { setEditorOpen(false); clearDraft(); });

  // These are the authorization detail types defined by RFC 9396. Keep that
  // implementation reference here; the operator-facing copy uses product
  // language instead of asking its reader to interpret a specification number.
  return <Screen
    title={editorOpen ? (editing ? `Edit ${name}` : 'Register authorization details type') : 'Authorization details'}
    description={editorOpen ? 'Validate the schema and review the consent wording before saving.' : `Structured authorization request types accepted by ${session.workspace}.`}
    {...(editorOpen ? { back: { label: 'Back to authorization details', onClick: closeEditor } } : {})}
    actions={mayWrite && !editorOpen && <Button variant="primary" onClick={openCreate}><PlusIcon data-icon="inline-start" aria-hidden="true" /> Register type</Button>}
  >
    {notice !== null && !editorOpen && <Message tone="success">{notice}</Message>}
    {error !== null && !editorOpen && withdrawing === null && <Message tone="error">{error}</Message>}
    {withdrawing !== null && <ConfirmDialog title={`Withdraw ${withdrawing}?`}
      body={<><p>This removes the registration from {session.workspace}. Applications depending on it may no longer obtain the expected access. Already issued tokens retain their existing validity.</p>{error && <Message tone="error">{error}</Message>}</>}
      confirmLabel="Withdraw registration" busy={busy} onCancel={() => { setWithdrawing(null); setError(null); }} onConfirm={() => void withdraw(withdrawing)} />}
    {!editorOpen && <Panel title="Registered types">
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading the authorization details types." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && <DataTable
        caption="Registered authorization details types"
        rows={load.items}
        rowKey={item => item.type}
        search={{ of: item => `${item.type} ${item.consent_template ?? ''}`, label: 'Filter loaded authorization details types' }}
        empty={<EmptyState title="No registered types" body="Register a type to accept structured authorization requests." action={mayWrite ? <Button onClick={openCreate}>Register type</Button> : undefined} />}
        columns={[
          { key: 'type', header: 'Type', sortBy: item => item.type, cell: item => <code>{item.type}</code> },
          { key: 'consent', header: 'Consent', cell: item => item.consent_template ?? 'Undescribed' },
          { key: 'schema', header: 'Schema', cell: item => <Button small onClick={() => setInspecting(item)} aria-label={`View schema for ${item.type}`}>View schema</Button> },
          ...(mayWrite ? [{ key: 'actions', header: 'Actions', actions: true, cell: (item: RegisteredType) => <Actions><Button small disabled={busy} aria-label={`Edit ${item.type}`} onClick={() => edit(item)}><PencilIcon data-icon="inline-start" aria-hidden="true" />Edit</Button><Button small variant="danger" disabled={busy} onClick={() => setWithdrawing(item.type)}>Withdraw</Button></Actions> }] : []),
        ]}
      />}
    </Panel>}
    <DetailSheet open={inspecting !== null} onOpenChange={open => { if (!open) setInspecting(null); }} title={inspecting ? `Schema for ${inspecting.type}` : 'Registered schema'} description="Saved schema and consent wording. This view does not change the registration.">
      {inspecting && <><p>{inspecting.consent_template ?? 'No consent wording is registered.'}</p><JsonView value={inspecting.schema} label="Registered JSON schema" /></>}
    </DetailSheet>
    {mayWrite && editorOpen && <div className="schema-editor document-workspace">
      {error !== null && <Message tone="error">{error}</Message>}
      <Panel title="Registration details" description="Name the request type and the wording people see when they consent.">
        <FieldGroup className="registration-fields">
          <Field label="Type name" hint="A stable identifier used by applications. It cannot be renamed after registration.">{props => <input {...props} value={name} disabled={editing || busy} onChange={event => setName(event.target.value)} placeholder="payment_initiation" />}</Field>
          <Field label="Consent template" hint="A user-facing sentence, up to 512 characters. Leave blank to mark the type undescribed.">{props => <input {...props} value={template} maxLength={512} disabled={busy} onChange={event => setTemplate(event.target.value)} placeholder="Initiate the described payment" />}</Field>
        </FieldGroup>
      </Panel>
      <div className="schema-workbench">
        <Panel title="Schema definition" description="Define the shape of an authorization request. Syntax feedback does not replace the server’s schema checks.">
          <Field label="JSON Schema" hint="Supported: type, required, properties, additionalProperties, enum, maxLength, items, maxItems, title, description.">{props => <JsonDraftEditor {...props} rows={18} value={schema} disabled={checking || busy} onValueChange={value => { setSchema(value); setSampleResult(null); }} />}</Field>
        </Panel>
        <div className="schema-workbench-preview">
          <Panel title="Test a sample" description="Validate an example against this draft. This saves no schema and grants no access.">
            <Field label="Sample JSON">{props => <JsonDraftEditor {...props} rows={6} value={sample} disabled={checking || busy} onValueChange={value => { setSample(value); setSampleResult(null); }} />}</Field>
            <Button disabled={checking || busy} onClick={() => void validateSample()}>{checking ? 'Checking sample…' : 'Validate sample'}</Button>
            {sampleResult && <Message tone={sampleResult.valid ? 'success' : 'error'}>{sampleResult.valid ? 'The sample matches the schema.' : sampleResult.message ?? 'The sample does not match the schema.'}</Message>}
          </Panel>
          <Panel title="Consent wording preview" description="Actual requests can also show their actions, data and locations.">
            <p>{template.trim() || 'Perform an action this server has no description for'}</p><code>{name || 'Type name'}</code>
          </Panel>
        </div>
      </div>
      <Actions><Button disabled={busy || checking} onClick={closeEditor}>Cancel</Button><Button variant="primary" disabled={busy || checking} onClick={() => void save()}>{busy ? 'Validating…' : editing ? 'Save changes' : 'Validate and register'}</Button></Actions>
    </div>}

  </Screen>;
}
