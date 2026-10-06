import { CheckIcon, ListFilterIcon, SearchIcon, XIcon } from 'lucide-react';
import { DropdownMenu } from '@/components/ui/dropdown-menu';
import { Badge, Button, Field } from './ui';

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
  return <DropdownMenu.Root><DropdownMenu.Trigger render={<Button className="directory-filter-action" aria-label={`Filter by status: ${selected}`} title="Filter by status">
    <ListFilterIcon aria-hidden="true" /><span className="directory-filter-label">{value ? selected : 'Filters'}</span>
    {value && <span className="directory-filter-active" aria-hidden="true" />}
  </Button>} /><DropdownMenu.Portal><DropdownMenu.Content align="end" sideOffset={6} className="account-menu directory-filter-menu">
    <DropdownMenu.Group><DropdownMenu.GroupLabel className="directory-filter-heading">Status</DropdownMenu.GroupLabel>
    <DropdownMenu.RadioGroup value={value} onValueChange={onChange}>{options.map(option => <DropdownMenu.RadioItem closeOnClick key={option.value} value={option.value} className="account-menu-item directory-filter-option">
      <span>{option.label}</span><DropdownMenu.RadioItemIndicator><CheckIcon aria-hidden="true" /></DropdownMenu.RadioItemIndicator>
    </DropdownMenu.RadioItem>)}</DropdownMenu.RadioGroup></DropdownMenu.Group>
  </DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>;
}

/** Only applied filters appear here; clearing status preserves the search draft. */
export function DirectoryFilterSummary({ query, status, onClearQuery, onClearStatus, onClearAll }: Readonly<{
  query: string; status: string; onClearQuery: () => void; onClearStatus: () => void; onClearAll: () => void;
}>) {
  if (!query && !status) return null;
  return <div className="directory-filter-summary" aria-label="Applied directory filters">
    {query && <Badge><span className="directory-filter-text">Search: {query}</span><Button small variant="ghost" aria-label="Remove search filter" onClick={onClearQuery}><XIcon aria-hidden="true" /></Button></Badge>}
    {status && <Badge><span className="directory-filter-text">Status: {status}</span><Button small variant="ghost" aria-label="Remove status filter" onClick={onClearStatus}><XIcon aria-hidden="true" /></Button></Badge>}
    <Button small variant="ghost" onClick={onClearAll}>Clear directory filters</Button>
  </div>;
}
