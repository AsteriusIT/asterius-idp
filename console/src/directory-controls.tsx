import { useState } from 'react';
import { ArrowDownUpIcon, SearchIcon } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from './components/ui/popover';
import { Button, Field } from './ui';

export function DirectoryOrder({ value, options, onChange }: Readonly<{
  value: string;
  options: readonly { value: string; label: string }[];
  onChange: (value: string) => void;
}>) {
  const [open, setOpen] = useState(false);
  return <Popover open={open} onOpenChange={setOpen}><PopoverTrigger asChild><Button className="directory-icon-action" aria-label={`Order: ${options.find(option => option.value === value)?.label ?? value}`} title="Order"><ArrowDownUpIcon aria-hidden="true" /><span>Order</span></Button></PopoverTrigger>
    <PopoverContent align="end" className="directory-order-menu"><p className="directory-order-title">Order</p>
      <div role="menu" aria-label="Order options">{options.map(option => <button type="button" key={option.value} role="menuitemradio" aria-checked={value === option.value} className="directory-order-option" onClick={() => { onChange(option.value); setOpen(false); }}>{option.label}</button>)}</div>
    </PopoverContent></Popover>;
}

export function DirectorySearch({ label, value, placeholder, onChange, onSubmit }: Readonly<{
  label: string; value: string; placeholder: string; onChange: (value: string) => void; onSubmit: () => void;
}>) {
  return <form className="directory-search" role="search" onSubmit={event => { event.preventDefault(); onSubmit(); }}>
    <Field label={label}>{props => <input {...props} type="search" value={value} placeholder={placeholder} onChange={event => onChange(event.target.value)} />}</Field>
    <Button className="directory-icon-action" type="submit" title="Search" aria-label="Search"><SearchIcon aria-hidden="true" /><span className="visually-hidden">Search</span></Button>
  </form>;
}
