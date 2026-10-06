import type { JSX } from 'react';
import { Field } from './ui';
import { FieldGroup } from './components/ui/field';
import { OptionalNumberInput } from './components/optional-number-input';
import { rateError, type RateBounds, type RateDraft } from './rate-limit-model';

const GROUPS: Record<string, string> = {
  login: 'Sign-in failures', registration: 'Client registration', client_configuration: 'Client configuration',
  par: 'Pushed authorization', token: 'Token requests', device_authorization: 'Device authorization',
  userinfo: 'UserInfo', introspection: 'Token introspection', revocation: 'Token revocation',
  ssf_subjects: 'Shared signal subjects', backchannel: 'Backchannel authentication', access_evaluation: 'Authorization decisions',
};
const SCOPES: Record<string, string> = { per_address: 'per address', per_account: 'per account', per_client: 'per authenticated client', per_subject: 'per person' };

export function RateLimitFields({ bounds, effective, draft, refusal, onChange }: Readonly<{
  bounds: RateBounds; effective: RateBounds; draft: RateDraft; refusal: string | null; onChange: (draft: RateDraft) => void;
}>): JSX.Element {
  return <>
    <legend>Rate limits</legend>
    <p>Lower the maximum requests or failed sign-ins in each deployment window. Leave a value empty to inherit.
      Windows and counters are shared by all replicas and cannot be reset by editing settings.</p>
    {Object.entries(bounds).map(([group, scopes]) => <FieldGroup key={group} className="rate-limit-group">
      <h3>{GROUPS[group] ?? group}</h3>
      {Object.entries(scopes).map(([scope, limit]) => {
        const value = draft[group]?.[scope] ?? '';
        const field = `rate_limits.${group}.${scope}`;
        const label = `${GROUPS[group] ?? group} ${SCOPES[scope] ?? scope}`;
        return <Field key={scope} label={label}
          hint={`Deployment maximum: ${limit.max} per ${limit.window_seconds} seconds. Effective saved maximum: ${effective[group]?.[scope]?.max ?? limit.max}.`}
          error={refusal?.includes(`${field}:`) ? refusal : rateError(value, limit.max)}>
          {(props) => <OptionalNumberInput {...props} name={field} maximum={limit.max} label={label}
            placeholder={`Inherit (${limit.max})`} value={value}
            onValueChange={value => onChange({ ...draft, [group]: { ...draft[group], [scope]: value } })} />}
        </Field>;
      })}
    </FieldGroup>)}
  </>;
}
