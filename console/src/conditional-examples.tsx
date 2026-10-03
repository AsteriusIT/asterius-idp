import type { JSX } from 'react';
import { EXAMPLE_FACTS, type Availability, type ExampleFactName, type FactExample } from './conditional-policy-model';
import { Field, Message } from './ui';
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
        return <div key={name} className="form-row"><Field label={`${LABELS[name]} availability`}>{props => <select {...props}
          value={example?.availability ?? 'server'} onChange={event => onChange(name,event.target.value === 'server' ? undefined : { availability:event.target.value as Availability,value:example?.value ?? '' })}>
          <option value="server">Use current server source</option><option value="known">Known example</option><option value="absent">Absent</option><option value="stale">Stale</option><option value="unavailable">Unavailable</option><option value="invalid">Invalid</option>
        </select>}</Field>
        {example?.availability === 'known' && <Field label={`${LABELS[name]} example value`}>{props => name === 'application_sensitivity' || name === 'device_compliance' ? <select {...props} required value={example.value} onChange={event => onChange(name,{...example,value:event.target.value})}>
          <option value="">Choose an example</option>{(name === 'application_sensitivity' ? ['standard','sensitive','critical'] : ['compliant','non_compliant','unknown']).map(value => <option key={value} value={value}>{value}</option>)}
        </select> : <input {...props} required type={name === 'authentication_age' ? 'number' : 'text'} min={name === 'authentication_age' ? 0 : undefined} max={name === 'authentication_age' ? 604800 : undefined} maxLength={name === 'network_zone' ? 8192 : 256} value={example.value} onChange={event => onChange(name,{...example,value:event.target.value})} />}</Field>}
        </div>;
      })}</>}
  </fieldset>;
}
