import { CheckIcon, ListFilterIcon, SearchIcon } from 'lucide-react';
import { DropdownMenu } from 'radix-ui';
import { Button, Field } from './ui';

export function DirectorySearch({ label, value, placeholder, onChange, onSubmit, actionLabel = 'Search' }: Readonly<{
  label: string; value: string; placeholder: string; actionLabel?: string; onChange: (value: string) => void; onSubmit: () => void;
}>) {
  return <form className="directory-search" role="search" onSubmit={event => { event.preventDefault(); onSubmit(); }}>
    <Field label={label}>{props => <input {...props} type="search" value={value} placeholder={placeholder} onChange={event => onChange(event.target.value)} />}</Field>
    <Button className="directory-icon-action" type="submit" title={actionLabel} aria-label={actionLabel}><SearchIcon aria-hidden="true" /><span className="visually-hidden">{actionLabel}</span></Button>
  </form>;
}

export function DirectoryStatusFilter({ value, options, onChange }: Readonly<{
  value: string;
  options: readonly { value: string; label: string }[];
  onChange: (value: string) => void;
}>) {
  const selected = options.find(option => option.value === value)?.label ?? 'All statuses';
  return <DropdownMenu.Root><DropdownMenu.Trigger asChild><Button className="directory-filter-action" aria-label={`Filter by status: ${selected}`} title="Filter by status">
    <ListFilterIcon aria-hidden="true" /><span className="directory-filter-label">{value ? selected : 'Filters'}</span>
    {value && <span className="directory-filter-active" aria-hidden="true" />}
  </Button></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content align="end" sideOffset={6} className="account-menu directory-filter-menu">
    <DropdownMenu.Label className="directory-filter-heading">Status</DropdownMenu.Label>
    <DropdownMenu.RadioGroup value={value} onValueChange={onChange}>{options.map(option => <DropdownMenu.RadioItem key={option.value} value={option.value} className="account-menu-item directory-filter-option">
      <span>{option.label}</span><DropdownMenu.ItemIndicator><CheckIcon aria-hidden="true" /></DropdownMenu.ItemIndicator>
    </DropdownMenu.RadioItem>)}</DropdownMenu.RadioGroup>
  </DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>;
}
