import { useId, useMemo, type ComponentProps } from 'react';
import { BracesIcon } from 'lucide-react';
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupText, InputGroupTextarea } from './ui/input-group';

/** Plain JSON editing; syntax feedback is distinct from server schema validation. */
export function JsonDraftEditor({ value, onValueChange, ...props }: Omit<ComponentProps<typeof InputGroupTextarea>, 'value' | 'onChange'> & {
  value: string; onValueChange: (value: string) => void;
}) {
  const statusId = useId();
  const syntax = useMemo(() => {
    try { return { valid: true, formatted: JSON.stringify(JSON.parse(value), null, 2) }; }
    catch { return { valid: false, formatted: null }; }
  }, [value]);
  const describedBy = [props['aria-describedby'], statusId].filter(Boolean).join(' ');
  return <InputGroup className="json-draft-editor">
    <InputGroupAddon align="block-start">
      <InputGroupText><BracesIcon aria-hidden="true" />JSON</InputGroupText>
      <InputGroupButton disabled={props.disabled || props.readOnly || !syntax.valid || syntax.formatted === value}
        onClick={() => { if (syntax.formatted !== null) onValueChange(syntax.formatted); }}>Format JSON</InputGroupButton>
    </InputGroupAddon>
    <InputGroupTextarea {...props} value={value} aria-describedby={describedBy} aria-invalid={props['aria-invalid'] || !syntax.valid}
      spellCheck={false} autoCapitalize="off" autoCorrect="off" onChange={event => onValueChange(event.target.value)} />
    <InputGroupAddon align="block-end">
      <InputGroupText id={statusId}>{syntax.valid ? 'Valid JSON syntax' : 'Incomplete or invalid JSON'} · Server validation required</InputGroupText>
      <InputGroupText>{value.split('\n').length} lines</InputGroupText>
    </InputGroupAddon>
  </InputGroup>;
}
