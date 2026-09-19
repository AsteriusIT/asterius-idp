import type { JSX } from 'react';
import type { Draft } from './settings-model';
import { Field } from './ui';

export function SessionPolicyFields({ draft, onChange, busy, refusal }: Readonly<{
  draft: Draft; onChange: (draft: Draft) => void; busy: boolean; refusal: string | null;
}>): JSX.Element {
  return <fieldset className="settings-section lifetime-settings" disabled={busy}>
    <legend>Session lifetimes</legend>
    <p className="muted">Apply to sign-in and console sessions in this tenant. Shorter limits also restrict existing sessions; renewal and step-up never extend their original absolute deadline. Token lifetimes are separate.</p>
    <Field label="Session idle timeout (seconds)" hint="At least 60 seconds and no longer than the absolute lifetime." error={refusal?.includes('session_policy.idle_seconds') ? refusal : null}>
      {(props) => <input {...props} name="session_idle_seconds" type="number" min={60} max={43200} value={draft.sessionIdle} onChange={(event) => onChange({ ...draft, sessionIdle: event.target.value })} />}
    </Field>
    <Field label="Session absolute lifetime (seconds)" hint="Between 60 seconds and 12 hours (43200 seconds)." error={refusal?.includes('session_policy.absolute_seconds') ? refusal : null}>
      {(props) => <input {...props} name="session_absolute_seconds" type="number" min={60} max={43200} value={draft.sessionAbsolute} onChange={(event) => onChange({ ...draft, sessionAbsolute: event.target.value })} />}
    </Field>
  </fieldset>;
}
