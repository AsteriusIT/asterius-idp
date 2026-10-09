import { useEffect, useId, useRef, useState, type JSX } from 'react';
import { read, type Session } from './api';
import { Actions, Badge, Button, ConfirmDialog, Field, Message, Panel } from './ui';
import { Field as ChoiceField, FieldLabel, FieldGroup, FieldSet, FieldLegend } from './components/ui/field';
import { FormSelect } from './components/ui/select';
import { Checkbox } from './components/ui/checkbox';
import { Combobox, ComboboxContent, ComboboxInput, ComboboxItem, ComboboxList } from './components/ui/combobox';
import { JsonSourceView } from './components/json-view';
import { DurationInput } from './form-controls';
import { ENFORCEMENT_ACTIONS } from './conditional-policy-model';
import { addScope, builderDocument, CONDITION_LABELS, conditionKind, newCondition, object, patchScope, removeScope, scopeObjects, stringList, uniqueID, type ConditionKind, type JsonObject } from './conditional-policy-builder-model';
const BOUNDARIES: Record<string, string> = { authorize: 'Browser authorization', authorization_code: 'Code redemption', refresh_token: 'Token refresh', device_code: 'Device authorization', ciba: 'Backchannel authentication', token_exchange: 'Token exchange', client_credentials: 'Application credentials', jwt_bearer: 'JWT bearer redemption', access_evaluation: 'Online access evaluation' };
const FACTS: Record<string, string> = { assurance: 'Authentication assurance', authentication_age: 'Authentication freshness', application_sensitivity: 'Application sensitivity', network_zone: 'Network zone', device_compliance: 'Device compliance', groups: 'Groups', roles: 'Roles', grants: 'Grants' };
const commaList = (text: string) => text.split(',').map(item => item.trim()).filter(Boolean);
function Opaque({ value, onJSON }: { value: unknown; onJSON: () => void }) {
  return <div className="stack"><Message tone="info">This expression is preserved. Use the JSON editor to change it.</Message><JsonSourceView source={JSON.stringify(value, null, 2) ?? 'null'} label="Preserved expression" /><Button onClick={onJSON}>Open JSON editor</Button></div>;
}
function TextField({ label, value, onChange, disabled, hint }: { label: string; value: unknown; onChange: (value: string) => void; disabled: boolean; hint?: string }) {
  if (value !== undefined && typeof value !== 'string') return <p>{label}: preserved in JSON.</p>;
  return <Field label={label} hint={hint}>{props => <input {...props} value={value ?? ''} disabled={disabled} maxLength={1024} onChange={event => onChange(event.target.value)} />}</Field>;
}
function ListField({ label, value, disabled, onChange, hint }: { label: string; value: string[]; disabled: boolean; onChange: (value: string[]) => void; hint: string }) {
  const serialised = value.join(', ');
  const [text, setText] = useState(serialised);
  const last = useRef(serialised);
  useEffect(() => { if (serialised !== last.current) { setText(serialised); last.current = serialised; } }, [serialised]);
  return <TextField label={label} disabled={disabled} value={text} hint={hint} onChange={next => { setText(next); const values = commaList(next); last.current = values.join(', '); onChange(values); }} />;
}

function StringChoices({ label, value, options, disabled, onChange }: { label: string; value: unknown; options: readonly { value: string; label: string; description?: string }[]; disabled: boolean; onChange: (value: string[]) => void }) {
  const choiceID = useId();
  if (value !== undefined && !stringList(value)) return <p>{label}: preserved in JSON.</p>;
  const selected = stringList(value) ? value : [];
  const choices: { value: string; label: string; description?: string }[] = [...options, ...selected.filter(id => !options.some(option => option.value === id)).map(id => ({ value: id, label: `${id} (unresolved)` }))];
  return <FieldSet className="conditional-choice-set"><FieldLegend>{label}</FieldLegend><FieldGroup className="conditional-choices">{choices.map((option, i) => <ChoiceField key={option.value} orientation="horizontal" className="conditional-choice" data-selected={selected.includes(option.value)} data-disabled={disabled}>
    <Checkbox id={`${choiceID}-${i}`} aria-label={option.description ? `${option.label} (${option.value})` : option.label} disabled={disabled} checked={selected.includes(option.value)} onCheckedChange={checked => onChange(checked ? [...selected, option.value] : selected.filter(id => id !== option.value))} />
    <FieldLabel htmlFor={`${choiceID}-${i}`}><span><strong>{option.label}</strong>{option.description && <small>{option.description}</small>}</span></FieldLabel>
  </ChoiceField>)}</FieldGroup></FieldSet>;
}
interface ClientOption { client_id: string; client_name?: string }
function ApplicationTargets({ value, disabled, canRead, onChange }: { value: unknown; disabled: boolean; canRead: boolean; onChange: (value: string[]) => void }) {
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState<string>();
  const [options, setOptions] = useState<ClientOption[]>([]);
  const [labels, setLabels] = useState<Record<string, string>>({});
  const [next, setNext] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    if (!canRead || !open) return;
    let active = true;
    setLoading(true); setError(null);
    const timer = window.setTimeout(() => {
      const params = new URLSearchParams({ limit: '100' });
      if (query.trim()) params.set('q', query.trim());
      if (cursor) params.set('cursor', cursor);
      void read(`clients?${params}`).then(result => {
        if (!active) return;
        const page = result as { items: ClientOption[]; next_cursor: string | null };
        setOptions(previous => cursor ? [...new Map([...previous, ...page.items].map(item => [item.client_id, item])).values()] : page.items);
        setLabels(previous => ({ ...previous, ...Object.fromEntries(page.items.map(item => [item.client_id, item.client_name || item.client_id])) }));
        setNext(page.next_cursor); setLoading(false);
      }, reason => { if (active) { setError(reason instanceof Error ? reason.message : 'Applications could not be read.'); setLoading(false); } });
    }, query ? 220 : 0);
    return () => { active = false; window.clearTimeout(timer); };
  }, [query, cursor, open, canRead, retry]);
  if (!stringList(value) && value !== undefined) return <p>Application targets are preserved in JSON.</p>;
  const selected = stringList(value) ? value : [];
  return <div className="conditional-applications"><FieldGroup>

    {selected.length ? <ul className="conditional-selected">{selected.map((id, index) => <li key={`${id}-${index}`}><div><strong>{labels[id] ?? 'Unresolved application'}</strong><code>{id}</code></div><Button small disabled={disabled} onClick={() => onChange(selected.filter((_, i) => i !== index))} aria-label={`Remove application ${id}`}>Remove</Button></li>)}</ul> : <p className="conditional-empty">Search below to select the applications this scope protects.</p>}
    {!canRead ? <Message tone="info">Application read access is required to search. Existing targets are preserved.</Message> : <Field label="Find applications">{props => <Combobox modal={false} filter={null} items={options} value={null} inputValue={query} open={open} onOpenChange={setOpen} disabled={disabled}
      itemToStringLabel={(item: ClientOption) => item.client_name || item.client_id} itemToStringValue={(item: ClientOption) => item.client_id}
      onInputValueChange={(text, details) => { if (details.reason === 'input-change') { setQuery(text); setCursor(undefined); setOptions([]); setNext(null); } }}
      onValueChange={item => { if (item && !selected.includes(item.client_id)) onChange([...selected, item.client_id]); setOpen(false); }}>
      <ComboboxInput {...props} placeholder="Search name or client ID" aria-busy={loading} />
      <ComboboxContent><ComboboxList>{(item: ClientOption) => <ComboboxItem key={item.client_id} value={item} disabled={selected.includes(item.client_id)}><span className="entity-option-copy"><strong>{item.client_name || item.client_id}</strong><small>{item.client_id}</small></span></ComboboxItem>}</ComboboxList>
        {loading && <p role="status" className="entity-picker-status">Searching applications…</p>}
        {error && <div className="entity-picker-status" role="alert"><p>{error}</p><Button small onClick={() => setRetry(n => n + 1)}>Retry applications</Button></div>}
        {!loading && !error && !options.length && <p className="entity-picker-status">No matching applications.</p>}
        {!loading && !error && next && <Button small onClick={() => setCursor(next)}>Load more applications</Button>}
      </ComboboxContent></Combobox>}</Field>}
  </FieldGroup></div>;
}
function AssuranceSelect({ label, value, levels, disabled, onChange, optional = false }: { label: string; value: unknown; levels: string[]; disabled: boolean; onChange: (value: string) => void; optional?: boolean }) {
  if (value !== undefined && value !== null && typeof value !== 'string') return <p>{label}: preserved in JSON.</p>;
  const current = typeof value === 'string' ? value : '';
  const unresolved = current !== '' && !levels.includes(current);
  return <Field label={label} hint={unresolved ? 'The current value is unresolved and preserved. Choose a tenant level only after review.' : 'Values come from this tenant’s authentication assurance ladder.'}>{props => <FormSelect {...props} disabled={disabled || !levels.length} value={current} onValueChange={onChange} options={[{ value: '', label: optional ? 'No assurance remedy' : 'Choose assurance level' }, ...levels.map(level => ({ value: level, label: level })), ...(unresolved ? [{ value: current, label: `${current} (unresolved)` }] : [])]} />}</Field>;
}
function ConditionEditor({ value, onChange, onJSON, disabled, levels, zones, path = 'Condition' }: { value: unknown; onChange: (value: unknown) => void; onJSON: () => void; disabled: boolean; levels: string[]; zones: string[]; path?: string }): JSX.Element {
  const kind = conditionKind(value);
  const [pending, setPending] = useState<ConditionKind | null>(null);
  if (!kind || !object(value) || path.split('.').length > 9) return <Opaque value={value} onJSON={onJSON} />;
  const raw = value[kind], group = kind === 'all' || kind === 'any';
  const children = group && Array.isArray(raw) ? raw : kind === 'not' ? [raw] : [];
  const current = typeof raw === 'string' ? raw : '';
  const options = kind === 'application_sensitivity' ? ['standard', 'sensitive', 'critical'] : kind === 'device_compliance' ? ['compliant', 'non_compliant', 'unknown'] : zones;
  return <FieldSet className="conditional-condition" data-leaf={!group && kind !== 'not'}><FieldLegend>{group || kind === 'not' ? CONDITION_LABELS[kind] : 'Condition'}</FieldLegend><FieldGroup>
    <Field label={group || kind === 'not' ? "Match" : "Check"}>{props => <FormSelect {...props} aria-label={`${path} type`} disabled={disabled} value={kind} options={Object.entries(CONDITION_LABELS).map(([value, label]) => ({ value, label }))} onValueChange={next => { if (next !== kind) setPending(next as ConditionKind); }} />}</Field>
    {(group || kind === 'not') ? <>
      <p className="muted">{kind === 'all' ? 'Match every condition below. An empty group matches every request.' : kind === 'any' ? 'Match at least one condition below. An empty group matches no requests.' : 'Match when the condition below is false. Missing required evidence still denies access.'}</p>
      {children.map((child, index) => <div className="conditional-child" key={index}><ConditionEditor value={child} path={`${path}.${index + 1}`} disabled={disabled} levels={levels} zones={zones} onJSON={onJSON} onChange={next => onChange(kind === 'not' ? { not: next } : { [kind]: children.map((item, i) => i === index ? next : item) })} />{group && <Button small disabled={disabled} aria-label={`Remove ${path}.${index + 1}`} onClick={() => onChange({ [kind]: children.filter((_, i) => i !== index) })}>Remove condition</Button>}</div>)}
      {group && <Actions><Button small disabled={disabled} aria-label={`Add condition to ${path}`} onClick={() => onChange({ [kind]: [...children, newCondition('application_sensitivity')] })}>Add condition</Button><Button small disabled={disabled} aria-label={`Add group to ${path}`} onClick={() => onChange({ [kind]: [...children, newCondition('all')] })}>Add group</Button></Actions>}
    </> : kind === 'acr_at_least' ? <AssuranceSelect label={`${path} assurance level`} value={raw} levels={levels} disabled={disabled} onChange={next => onChange({ [kind]: next })} />
    : kind === 'authentication_age_at_most' ? <Field label={`${path} maximum age in seconds`} hint="The policy accepts 60–86400 seconds, measured from the original authentication proof.">{props => <DurationInput {...props} disabled={disabled} min={60} max={86400} step={1} value={raw as number | ''} onChange={event => onChange({ [kind]: event.target.value === '' ? '' : Number(event.target.value) })} />}</Field>
    : <Field label="Value">{props => <FormSelect {...props} aria-label={`${path} value`} disabled={disabled || (kind === 'network_zone' && !zones.length)} value={current} onValueChange={next => onChange({ [kind]: next })} options={[{ value: '', label: 'Choose value' }, ...[...new Set([...options, ...(current ? [current] : [])])].map(item => ({ value: item, label: options.includes(item) ? item : `${item} (unresolved)` }))]} />}</Field>}
    {kind === 'device_compliance' && <Message tone="info">Device evidence requires the enrolled-device adapter. An unavailable source denies an active scope that requires it. Simulation examples are hypothetical.</Message>}
    {pending && <ConfirmDialog title="Replace this condition?" body="Replacing the condition type removes this expression and its children from the draft. Publication remains separate." confirmLabel="Replace condition" onCancel={() => setPending(null)} onConfirm={() => { onChange(newCondition(pending)); setPending(null); }} />}
  </FieldGroup></FieldSet>;
}
function NetworkZones({ value, disabled, onChange, onJSON }: { value: unknown; disabled: boolean; onChange: (value: JsonObject) => void; onJSON: () => void }) {
  const [name, setName] = useState('');
  if (value !== undefined && !object(value)) return <Opaque value={value} onJSON={onJSON} />;
  const zones = object(value) ? value : {};
  return <FieldSet><FieldLegend>Network zones</FieldLegend><FieldGroup><p className="muted">Zones belong to this scope. Enter comma-separated CIDRs; the server validates them. Removing a zone retains its rule references for review.</p>
    {Object.entries(zones).map(([zone, networks]) => <div key={zone} className="conditional-zone">{stringList(networks) ? <ListField label={`CIDRs for ${zone}`} disabled={disabled} value={networks} hint="Comma-separated CIDRs" onChange={values => onChange({ ...zones, [zone]: values })} /> : <Opaque value={networks} onJSON={onJSON} />}<Button small disabled={disabled} onClick={() => onChange(Object.fromEntries(Object.entries(zones).filter(([key]) => key !== zone)))}>Remove zone {zone}</Button></div>)}
    <Field label="New network zone name">{props => <input {...props} disabled={disabled} value={name} maxLength={128} onChange={event => setName(event.target.value)} />}</Field>
    <Actions><Button disabled={disabled || !name.trim() || Object.hasOwn(zones, name.trim())} onClick={() => { onChange({ ...zones, [name.trim()]: [] }); setName(''); }}>Add network zone</Button></Actions>
  </FieldGroup></FieldSet>;
}
function RuleEditor({ rule, index, disabled, levels, zones, onChange, onDelete, onJSON }: { rule: unknown; index: number; disabled: boolean; levels: string[]; zones: string[]; onChange: (rule: unknown) => void; onDelete: () => void; onJSON: () => void }) {
  const [removeCondition, setRemoveCondition] = useState(false);
  if (!object(rule)) return <Opaque value={rule} onJSON={onJSON} />;
  const patch = (next: JsonObject) => onChange({ ...rule, ...next });
  const selector = (key: string, text: string) => { const next = { ...rule }; if (text) next[key] = text; else delete next[key]; onChange(next); };
  return <FieldSet className="conditional-rule"><FieldLegend>Rule {index + 1}</FieldLegend><FieldGroup>
    <div className="conditional-rule-header"><Badge tone={rule['effect'] === 'deny' ? 'bad' : 'neutral'}>{typeof rule['effect'] === 'string' ? rule['effect'] : 'Unknown effect'}</Badge><Button small disabled={disabled} onClick={onDelete}>Remove rule {index + 1}</Button></div>
    {rule['effect'] === 'permit' || rule['effect'] === 'deny' ? <Field label={`Rule ${index + 1} effect`}>{props => <FormSelect {...props} disabled={disabled} value={String(rule['effect'])} options={[{ value: 'permit', label: 'Permit, subject to base authorization' }, { value: 'deny', label: 'Deny' }]} onValueChange={effect => patch({ effect })} />}</Field> : <p>Effect is preserved in JSON.</p>}
    {Object.hasOwn(rule, 'when') ? <><ConditionEditor value={rule['when']} disabled={disabled} levels={levels} zones={zones} path={`Rule ${index + 1} condition`} onJSON={onJSON} onChange={when => patch({ when })} /><Actions><Button small disabled={disabled} onClick={() => setRemoveCondition(true)}>Remove rule condition</Button></Actions></> : <><Message tone="info">This rule has no condition. It matches whenever its selectors apply.</Message><Actions><Button disabled={disabled} onClick={() => patch({ when: newCondition('all') })}>Add rule condition</Button></Actions></>}
    <details className="conditional-advanced"><summary>Rule details <span className="muted">{['subject_type', 'resource_type', 'actions', 'reason_admin', 'reason_user'].filter(key => rule[key] !== undefined && rule[key] !== '' && (!Array.isArray(rule[key]) || (rule[key] as unknown[]).length > 0)).length} configured</span></summary><div className="stack">
    <TextField label={`Rule ${index + 1} identifier`} disabled={disabled} value={rule['id']} onChange={id => patch({ id })} />
    <TextField label={`Rule ${index + 1} subject type`} value={rule['subject_type']} disabled={disabled} hint="Blank matches any subject type." onChange={text => selector('subject_type', text)} />
    <TextField label={`Rule ${index + 1} resource type`} value={rule['resource_type']} disabled={disabled} hint="Blank matches any resource type." onChange={text => selector('resource_type', text)} />
    {rule['actions'] === undefined || stringList(rule['actions']) ? <ListField label={`Rule ${index + 1} resource actions`} disabled={disabled} value={stringList(rule['actions']) ? rule['actions'] : []} hint="Comma-separated operations, such as read; separate from scope boundaries. Blank matches any operation." onChange={actions => patch({ actions })} /> : <p>Rule actions are preserved in JSON.</p>}
    <TextField label={`Rule ${index + 1} operator reason`} disabled={disabled} value={rule['reason_admin']} onChange={text => selector('reason_admin', text)} />
    <TextField label={`Rule ${index + 1} user reason`} disabled={disabled} value={rule['reason_user']} onChange={text => selector('reason_user', text)} />
    </div></details>
    {removeCondition && <ConfirmDialog title="Remove this rule’s condition?" body="The rule would become unconditional for matching selectors. This changes only the draft." confirmLabel="Remove condition" onCancel={() => setRemoveCondition(false)} onConfirm={() => { const next = { ...rule }; delete next['when']; onChange(next); setRemoveCondition(false); }} />}
    {Object.keys(rule).some(key => !['id', 'effect', 'subject_type', 'resource_type', 'actions', 'when', 'reason_admin', 'reason_user'].includes(key)) && <details><summary>Additional preserved rule fields</summary><JsonSourceView source={JSON.stringify(rule, null, 2)} label="Complete rule" /><Button onClick={onJSON}>Open JSON editor</Button></details>}
  </FieldGroup></FieldSet>;
}
export function ConditionalPolicyBuilder({ draft, session, disabled, onChange, onJSON }: { draft: string; session: Session; disabled: boolean; onChange: (text: string) => void; onJSON: () => void }) {
  const doc = builderDocument(draft), scopes = doc ? scopeObjects(doc) : [];
  const [selected, setSelected] = useState(0);
  const [levels, setLevels] = useState<string[]>([]);
  const [ladderMessage, setLadderMessage] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  useEffect(() => {
    let active = true;
    void read(`tenants/${encodeURIComponent(session.workspace)}/settings`).then(value => {
      if (!active) return;
      const settings = value as { acr_policy?: { levels?: { value: string }[] } };
      const values = settings.acr_policy?.levels?.map(level => level.value) ?? [];
      setLevels(values); if (!values.length) setLadderMessage('No assurance levels were returned. Existing values are preserved in JSON.');
    }, () => { if (active) setLadderMessage('The tenant assurance ladder could not be read. Existing ACR values are preserved; use JSON for changes until catalogue access is available.'); });
    return () => { active = false; };
  }, [session.workspace]);
  const index = Math.min(selected, Math.max(0, scopes.length - 1)), scope = scopes[index];
  const patch = (next: JsonObject) => onChange(patchScope(draft, index, next));
  const rules = object(scope) && Array.isArray(scope['rules']) ? scope['rules'] : null;
  const zones = object(scope) && object(scope['network_zones']) ? Object.keys(scope['network_zones']) : [];
  return <Panel title="Conditional access builder" description="Choose applications, set conditions, then test your draft before publishing.">
    <div className="conditional-builder">
    {!doc ? <><Message tone="info">The draft cannot be edited structurally. Your exact JSON text is retained.</Message><Button onClick={onJSON}>Open JSON editor</Button></> : <>
      <div className="conditional-toolbar"><Actions>{scopes.length > 0 && <Field label="Scope to edit">{props => <FormSelect {...props} value={String(index)} onValueChange={value => setSelected(Number(value))} options={scopes.map((item, i) => ({ value: String(i), label: object(item) && typeof item['id'] === 'string' ? item['id'] : `Scope ${i + 1}` }))} />}</Field>}<Button disabled={disabled} onClick={() => { onChange(addScope(draft)); setSelected(scopes.length); }}>Add conditional scope</Button></Actions></div>
      {!scopes.length && <div className="conditional-empty"><strong>Start with a conditional scope</strong><p>Group applications that share the same access conditions. New scopes start in report-only mode so you can test before enforcing.</p></div>}
      {scopes.length > 0 && (!object(scope) ? <Opaque value={scope} onJSON={onJSON} /> : <>
        <section className="conditional-step" aria-labelledby="conditional-target-heading">
          <div className="conditional-step-heading"><span className="conditional-step-number" aria-hidden="true">1</span><div><h3 id="conditional-target-heading">Choose what to protect</h3><p>Target applications and the access flows to check.</p></div></div>
          <div className="stack conditional-step-body">
          <TextField label="Scope identifier" value={scope['id']} disabled={disabled} onChange={id => patch({ id })} />
          <ApplicationTargets key={index} value={scope['clients']} disabled={disabled} canRead={session.scopes.includes('admin.clients:read')} onChange={clients => patch({ clients })} />
          {(scope['actions'] === undefined || stringList(scope['actions'])) && <Actions><Button small disabled={disabled} onClick={() => patch({ actions: [...new Set([...(stringList(scope['actions']) ? scope['actions'] : []), 'authorize', 'authorization_code'])] })}>Select browser sign-in flows</Button></Actions>}
          <StringChoices label="Enforcement boundaries" value={scope['actions']} disabled={disabled} onChange={actions => patch({ actions })} options={ENFORCEMENT_ACTIONS.map(value => ({ value, label: BOUNDARIES[value] ?? value, description: value }))} />
          <p className="muted conditional-help">For a browser sign-in, select both Browser authorization and Code redemption. Each application and flow can belong to only one scope.</p>
          </div>
        </section>
        <section className="conditional-step" aria-labelledby="conditional-rules-heading">
          <div className="conditional-step-heading"><span className="conditional-step-number" aria-hidden="true">2</span><div><h3 id="conditional-rules-heading">Define access conditions</h3><p>A denial wins. At least one rule must permit the request.</p></div></div>
          <div className="stack conditional-step-body">
          {rules === null ? <Opaque value={scope['rules']} onJSON={onJSON} /> : <>{!rules.length && <p className="conditional-empty">No rules yet. Add a rule to define when access is permitted or denied.</p>}{rules.map((rule, i) => <RuleEditor key={`${index}-${i}`} rule={rule} index={i} disabled={disabled} levels={levels} zones={zones} onJSON={onJSON} onDelete={() => patch({ rules: rules.filter((_, n) => n !== i) })} onChange={next => patch({ rules: rules.map((item, n) => n === i ? next : item) })} />)}<Actions><Button disabled={disabled} onClick={() => patch({ rules: [...rules, { id: uniqueID('rule', rules), effect: 'permit', subject_type: 'user', when: { all: [newCondition('application_sensitivity')] } }] })}>Add conditional rule</Button></Actions></>}
          <details className="conditional-advanced" key={`advanced-${index}`}><summary>Advanced settings <span className="muted">{stringList(scope['required_facts']) ? scope['required_facts'].length : 0} required facts · {zones.length} network zones{scope['assurance_remedy'] ? ' · Assurance remedy set' : ''}</span></summary><div className="stack">
            <p className="muted">Conditions request the evidence they need. Add explicit requirements only when evidence must always be present.</p>
            <StringChoices label="Explicit required facts" value={scope['required_facts']} disabled={disabled} onChange={required_facts => patch({ required_facts })} options={Object.entries(FACTS).map(([value, label]) => ({ value, label }))} />
            <p className="muted">Application sensitivity is set in Applications → Policy. Changing this scope does not change an application’s classification.</p>
            {ladderMessage && <Message tone="info">{ladderMessage}</Message>}
            <AssuranceSelect label="Optional assurance remedy" value={scope['assurance_remedy']} optional levels={levels} disabled={disabled} onChange={value => patch({ assurance_remedy: value || null })} />
            <p className="muted">A remedy can request fresh authentication. Simulate to check whether it can satisfy the whole scope.</p>
            <NetworkZones key={index} value={scope['network_zones']} disabled={disabled} onChange={network_zones => patch({ network_zones })} onJSON={onJSON} />
          </div></details>
          </div>
        </section>
        <section className="conditional-step" aria-labelledby="conditional-rollout-heading">
          <div className="conditional-step-heading"><span className="conditional-step-number" aria-hidden="true">3</span><div><h3 id="conditional-rollout-heading">Choose your rollout</h3><p>Start by observing outcomes, then enforce after testing.</p></div><Badge tone={scope['mode'] === 'active' ? 'bad' : 'neutral'}>{scope['mode'] === 'active' ? 'Active draft' : scope['mode'] === 'report_only' ? 'Report-only draft' : 'Unknown mode'}</Badge></div>
          <div className="stack conditional-step-body">
            <Field label="Draft enforcement mode">{props => ['active', 'report_only'].includes(String(scope['mode'])) ? <FormSelect {...props} disabled={disabled} value={String(scope['mode'])} onValueChange={mode => patch({ mode })} options={[{ value: 'report_only', label: 'Report-only — record outcomes' }, { value: 'active', label: 'Active — enforce restrictions' }]} /> : <span>Unknown mode preserved. Use JSON to edit.</span>}</Field>
            <Message tone="info">{scope['mode'] === 'active' ? 'Active mode denies access when required evidence is missing, including inside Any or Not groups.' : 'Report-only records outcomes without overriding a denial. Publish active mode when you are ready to enforce.'}</Message>
            <p className="muted conditional-help">Next, simulate this draft below and review the changes before saving. Base authorization must also permit access.</p>
          </div>
        </section>
        <div className="conditional-scope-footer"><span className="muted">Changes stay in your draft until you publish.</span><Button variant="danger" small disabled={disabled} onClick={() => setRemoving(true)}>Remove conditional scope</Button></div>
        {removing && <ConfirmDialog title="Remove this conditional scope?" body="Removing a scope can relax restrictions after publication. Base authorization rules are retained." confirmLabel="Remove scope from draft" onCancel={() => setRemoving(false)} onConfirm={() => { onChange(removeScope(draft, index)); setSelected(0); setRemoving(false); }} />}
      </>)}
    </>}
    </div>
  </Panel>;
}
