import { useId, type ComponentProps } from 'react';
import { InputGroup, InputGroupAddon, InputGroupTextarea, InputGroupText } from './ui/input-group';

/** Uses the browser's existing maxLength contract; raw text stays in the caller's draft. */
export function CharacterCountTextarea({ value, maxLength, 'aria-describedby': described, ...props }: Omit<ComponentProps<typeof InputGroupTextarea>, 'value' | 'maxLength'> & { value: string; maxLength: number }) {
  const countId = useId();
  return <InputGroup className="character-count-textarea">
    <InputGroupTextarea {...props} value={value} maxLength={maxLength} aria-describedby={[described, countId].filter(Boolean).join(' ')} />
    <InputGroupAddon align="block-end"><InputGroupText id={countId}>{value.length} / {maxLength} characters</InputGroupText><span className="visually-hidden" aria-live="polite">{value.length >= maxLength ? 'Character limit reached.' : ''}</span></InputGroupAddon>
  </InputGroup>;
}
