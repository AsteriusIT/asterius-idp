import { Button } from '../ui';

/** Count selected records, not an inferred total; clearing never sends a write. */
export function SelectionBar({ count, disabled, onClear }: Readonly<{ count: number; disabled: boolean; onClear: () => void }>) {
  return <div className="selection-bar" role="group" aria-label="Selected ownership records"><span aria-live="polite">{count} {count === 1 ? 'record' : 'records'} selected</span><Button small variant="ghost" disabled={disabled || count === 0} onClick={onClear}>Clear selection</Button></div>;
}
