import type { JSX } from 'react';
import { Button, Field } from './ui';

export interface AssuranceLevel {
  readonly value: string;
  readonly amr: readonly string[];
}
export interface AssurancePolicy {
  readonly amr_in_id_token: boolean;
  readonly levels: readonly AssuranceLevel[];
}

/** The ordered, server-validated contexts a tenant advertises to applications. */
export function AssuranceEditor({ policy, onChange, disabled }: Readonly<{
  policy: AssurancePolicy;
  onChange: (value: AssurancePolicy) => void;
  disabled: boolean;
}>): JSX.Element {
  const changeLevel = (index: number, level: AssuranceLevel): void =>
    onChange({ ...policy, levels: policy.levels.map((old, i) => i === index ? level : old) });
  return <fieldset className="settings-section" disabled={disabled}>
    <legend>Authentication assurance</legend>
    <p className="muted">Define the authentication contexts applications can request, weakest first. Changes apply to new requests within 30 seconds across servers. Existing sessions must prove every method a requested context now requires. Administrator passkey verification remains required.</p>
    <label><input type="checkbox" checked={policy.amr_in_id_token}
      onChange={(event) => onChange({ ...policy, amr_in_id_token: event.target.checked })} /> Include authentication methods in ID tokens</label>
    {policy.levels.map((level, index) => <fieldset key={index} className="settings-section">
      <legend>Context {index + 1}</legend>
      <Field label={`Context ${index + 1} value`} hint="An ASCII name without spaces; maximum 255 characters.">
        {(props) => <input {...props} value={level.value} maxLength={255}
          onChange={(event) => changeLevel(index, { ...level, value: event.target.value })} />}
      </Field>
      {([['pwd', 'Password'], ['swk', 'Passkey'], ['user', 'User verification']] as const).map(([method, label]) =>
        <label key={method}><input type="checkbox" aria-label={`Context ${index + 1}: ${label}`}
          checked={level.amr.includes(method)} onChange={(event) => changeLevel(index, {
            ...level, amr: event.target.checked ? [...level.amr, method] : level.amr.filter((old) => old !== method),
          })} /> {label}</label>)}
      <Button onClick={() => onChange({ ...policy, levels: policy.levels.filter((_, i) => i !== index) })}>Remove context {index + 1}</Button>
      {index > 0 && <Button onClick={() => {
        const levels = [...policy.levels];
        const previous = levels[index - 1];
        if (previous === undefined) return;
        levels[index - 1] = level;
        levels[index] = previous;
        onChange({ ...policy, levels });
      }}>Move context {index + 1} earlier</Button>}
    </fieldset>)}
    <Button disabled={policy.levels.length >= 32} onClick={() => onChange({
      ...policy, levels: [...policy.levels, { value: '', amr: ['swk', 'user'] }],
    })}>Add authentication context</Button>
  </fieldset>;
}
