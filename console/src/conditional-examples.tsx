import type { JSX } from 'react';
import { EXAMPLE_FACTS, type Availability, type ExampleFactName, type FactExample } from './conditional-policy-model';
import { Field, Message } from './ui';
import { FormSelect } from './components/ui/select';
const LABELS: Record<ExampleFactName, string> = {
  assurance: 'Authentication assurance', authentication_age: 'Authentication age in seconds',
  application_sensitivity: 'Application sensitivity', network_zone: 'Network zones (comma separated)', device_compliance: 'Device compliance',
};
export function ConditionalExamples({ enabled, examples, onEnable, onChange }: Readonly<{
  enabled: boolean; examples: Readonly<Partial<Record<ExampleFactName, FactExample>>>;
  onEnable: (value: boolean) => void; onChange: (name: ExampleFactName, value: FactExample | undefined) => void;
}>): JSX.Element {
  return <fieldset><legend>Trusted-context examples for this simulation</legend>
    <label><input type="checkbox" checked={enabled} onChange={event => onEnable(event.target.checked)} /> Supply hypothetical evidence examples</label>
    <p className="muted">Examples never become production evidence. Without an example, a selected account has no bound authentication transaction, verified request peer or verified device. Groups, roles, grants and the stored application classification are read by the server.</p>
    {enabled && <><Message tone="info">Every overridden source is labelled hypothetical operator example. A missing, stale or invalid required fact still denies the simulated active scope.</Message>
      {EXAMPLE_FACTS.map(name => {
        const example = examples[name];
        return <div key={name} className="form-row"><Field label={`${LABELS[name]} availability`}>{props => <FormSelect {...props}
          value={example?.availability ?? 'server'} onValueChange={value => onChange(name,value === 'server' ? undefined : { availability:value as Availability,value:example?.value ?? '' })}
          options={[{ value: 'server', label: 'Use current server source' }, { value: 'known', label: 'Known example' }, { value: 'absent', label: 'Absent' }, { value: 'stale', label: 'Stale' }, { value: 'unavailable', label: 'Unavailable' }, { value: 'invalid', label: 'Invalid' }]} />}</Field>
        {example?.availability === 'known' && <Field label={`${LABELS[name]} example value`}>{props => name === 'application_sensitivity' || name === 'device_compliance' ? <FormSelect {...props} required value={example.value} onValueChange={value => onChange(name,{...example,value})}
          options={[{ value: '', label: 'Choose an example' }, ...(name === 'application_sensitivity' ? ['standard','sensitive','critical'] : ['compliant','non_compliant','unknown']).map(value => ({ value, label: value }))]} /> : <input {...props} required type={name === 'authentication_age' ? 'number' : 'text'} min={name === 'authentication_age' ? 0 : undefined} max={name === 'authentication_age' ? 604800 : undefined} maxLength={name === 'network_zone' ? 8192 : 256} value={example.value} onChange={event => onChange(name,{...example,value:event.target.value})} />}</Field>}
        </div>;
      })}</>}
  </fieldset>;
}
