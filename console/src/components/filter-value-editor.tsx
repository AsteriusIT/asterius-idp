import { useState } from 'react';
import { Popover, PopoverContent, PopoverTitle, PopoverDescription, PopoverTrigger } from './ui/popover';
import { Actions, Button, Field } from '../ui';
import { Input } from './ui/input';

/** Bounded edit of one existing server filter, applied explicitly. */
export function FilterValueEditor({ label, value, onApply }: { label: string; value: string; onApply: (value: string) => void }) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(value);
  return <Popover open={open} onOpenChange={next => { if (next) setDraft(value); setOpen(next); }}>
    <PopoverTrigger render={<Button small variant="ghost" aria-label={`Edit ${label} filter`} />}><span className="audit-filter-chip-copy">{label}: {value}</span></PopoverTrigger>
    <PopoverContent align="start" className="filter-value-popover">
      <PopoverTitle>Edit {label.toLowerCase()} filter</PopoverTitle>
      <PopoverDescription>Apply this value without changing your other filters.</PopoverDescription>
      <form onSubmit={event => { event.preventDefault(); onApply(draft); setOpen(false); }}>
        <Field label={`New ${label} value`}>{props => <Input {...props} value={draft} maxLength={256} onChange={event => setDraft(event.target.value)} />}</Field>
        <Actions><Button onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" variant="primary">Apply this filter</Button></Actions>
      </form>
    </PopoverContent>
  </Popover>;
}
