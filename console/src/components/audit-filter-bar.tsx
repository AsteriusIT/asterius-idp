import { FilterValueEditor } from './filter-value-editor';
import { useState } from 'react';
import { PlusIcon, XIcon } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from './ui/popover';
import { Input } from './ui/input';
import { FieldGroup } from './ui/field';
import { Actions, Button, Field } from '../ui';
import type { Filters } from '../audit';

const FIELDS: { name: keyof Filters; label: string; placeholder: string }[] = [
  { name: 'type', label: 'Event type', placeholder: 'token.exchanged, session.revoked' },
  { name: 'user', label: 'User', placeholder: 'Subject ID' },
  { name: 'from', label: 'From', placeholder: '2026-01-01T00:00:00Z' },
  { name: 'until', label: 'Until', placeholder: '2026-12-31T00:00:00Z' },
  { name: 'agent', label: 'Agent', placeholder: 'Client ID' },
  { name: 'owner', label: 'Owner', placeholder: 'Subject the agent acts for' },
  { name: 'grant', label: 'Grant ID', placeholder: 'Paste a grant ID' },
  { name: 'task', label: 'Task ID', placeholder: 'Paste an immutable task ID' },
  { name: 'request_id', label: 'Support reference', placeholder: '32 lowercase hexadecimal characters' },
  { name: 'session', label: 'Session reference', placeholder: '64 lowercase hexadecimal characters' },
];
const DEFAULT_FIELDS = ['type', 'user', 'from', 'until'];

/** Flat server parameters presented as draft fields and independently applied chips. */
export function AuditFilterBar({ draft, applied, onDraft, onApply, empty }: {
  draft: Filters; applied: Filters; onDraft: (value: Filters) => void; onApply: (value: Filters) => void; empty: Filters;
}) {
  const [extra, setExtra] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const visible = FIELDS.filter(field => DEFAULT_FIELDS.includes(field.name) || extra.includes(field.name) || draft[field.name]?.trim());
  const available = FIELDS.filter(field => !visible.includes(field));
  const active = FIELDS.filter(field => applied[field.name]?.trim());
  const dirty = FIELDS.some(field => (draft[field.name] ?? '').trim() !== (applied[field.name] ?? '').trim());
  return <div className="audit-filter-bar">
    <form role="search" aria-label="Audit filters" onSubmit={event => { event.preventDefault(); onApply(draft); }}>
      <FieldGroup className="audit-filter-fields">{visible.map(({ name, label, placeholder }) => <Field key={name} label={label}>
        {props => <Input {...props} name={name} value={draft[name] ?? ''} placeholder={placeholder} maxLength={256}
          onChange={event => onDraft({ ...draft, [name]: event.target.value })} />}
      </Field>)}</FieldGroup>
      <Actions>
        {available.length > 0 && <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger render={<Button small />}><PlusIcon aria-hidden="true" />Add filter</PopoverTrigger>
          <PopoverContent align="start" aria-label="Additional audit filters"><div className="audit-filter-menu">
            {available.map(({ name, label }) => <Button key={name} variant="ghost" onClick={() => { setExtra(previous => [...previous, name]); setOpen(false); }}>{label}</Button>)}
          </div></PopoverContent>
        </Popover>}
        <Button variant="ghost" onClick={() => { onDraft(empty); onApply(empty); setExtra([]); }}>Clear</Button>
        <Button type="submit" variant="primary">Apply filters</Button>
        {dirty && <span className="muted" role="status">Filters have unapplied changes.</span>}
      </Actions>
    </form>
    {active.length > 0 && <div className="audit-applied-filters" aria-label="Applied audit filters">
      <span className="muted">Applied</span>{active.map(({ name, label }) => <div className="editable-filter-chip" key={name}>
        <FilterValueEditor label={label} value={applied[name] ?? ''} onApply={value => { onApply({ ...applied, [name]: value }); onDraft({ ...draft, [name]: value }); }} />
        <Button small variant="ghost" aria-label={`Remove ${label} filter`} onClick={() => { onApply({ ...applied, [name]: '' }); onDraft({ ...draft, [name]: '' }); }}><XIcon aria-hidden="true" /></Button>
      </div>)}
    </div>}
  </div>;
}
