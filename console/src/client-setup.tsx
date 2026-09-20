import type { JSX } from 'react';
import { Field } from './ui';
import { FormSelect } from './components/ui/select';
import {
  TLS_SUBJECT_FIELDS,
  clientAuthenticationMethods,
  changeClientAuthentication,
  changeComplianceProfile,
  changeSenderConstraint,
  type Draft,
  type TlsSubjectField,
} from './client-draft';
import { clientFieldError, type ClientDiscovery } from './client-onboarding';

interface SetupProps {
  readonly draft: Draft;
  readonly discovery: ClientDiscovery | null;
  readonly refusal: string | null;
  readonly busy: boolean;
  readonly onChange: (draft: Draft) => void;
}

export function ClientSecurity({ draft, discovery, refusal, busy, onChange }: SetupProps): JSX.Element {
  const methods = clientAuthenticationMethods(
    draft,
    discovery?.token_endpoint_auth_methods_supported,
  );
  return <>
    <Field label="Security profile" error={clientFieldError(refusal, 'compliance_profile')}
      hint="FAPI is the default hardened profile. Compatibility exceptions must first be enabled for this tenant and do not receive the FAPI badge.">
      {(props) => <FormSelect {...props} disabled={busy} value={draft.compliance_profile}
        options={[
          { value: 'fapi', label: 'FAPI 2.0 Security Profile' },
          { value: 'oidc', label: 'Non-FAPI compatibility exception' },
        ]}
        onValueChange={(value) => onChange(changeComplianceProfile(
          draft,
          value as Draft['compliance_profile'],
        ))} />}
    </Field>
    <Field label="Client authentication" error={clientFieldError(refusal, 'token_endpoint_auth_method')}
      hint={draft.token_endpoint_auth_method === 'client_secret_basic'
        ? 'The server creates a secret and shows it once. Store it in your backend secret manager.'
        : 'Use private_key_jwt for a backend that signs assertions. Mutual TLS methods require this deployment’s certificate endpoints.'}>
      {(props) => <FormSelect {...props} disabled={busy} value={draft.token_endpoint_auth_method}
        options={methods.map((value) => ({ value, label: value }))}
        onValueChange={(value) => onChange(changeClientAuthentication(draft, value))} />}
    </Field>
    {draft.token_endpoint_auth_method === 'tls_client_auth' && <>
      <Field label="Certificate identity field">
        {(props) => <FormSelect {...props} disabled={busy} value={draft.tls_subject_field}
          options={TLS_SUBJECT_FIELDS.map((value) => ({ value, label: value }))}
          onValueChange={(value) => onChange({ ...draft, tls_subject_field: value as TlsSubjectField })} />}
      </Field>
      <Field label="Certificate identity" required error={clientFieldError(refusal, draft.tls_subject_field)}
        hint="Register exactly one subject DN or SAN matching the certificate the application presents.">
        {(props) => <input {...props} value={draft.tls_subject_value}
          onChange={(event) => onChange({ ...draft, tls_subject_value: event.target.value })} />}
      </Field>
    </>}
    <Field label="Sender constraint"
      error={clientFieldError(refusal, 'dpop_bound_access_tokens') ?? clientFieldError(refusal, 'tls_client_certificate_bound_access_tokens')}
      hint="DPoP requires proof keys; certificate binding requires mutual TLS. Bearer maximizes client-library compatibility but tokens are usable by anyone who obtains them.">
      {(props) => <FormSelect {...props} disabled={busy}
        value={draft.tls_client_certificate_bound_access_tokens === true
          ? 'mtls'
          : draft.dpop_bound_access_tokens === false ? 'bearer' : 'dpop'}
        options={[
          { value: 'dpop', label: 'DPoP-bound tokens' },
          ...((discovery?.mtls_endpoint_aliases || draft.tls_client_certificate_bound_access_tokens === true)
            ? [{ value: 'mtls', label: 'Certificate-bound tokens (mTLS)' }] : []),
          ...(draft.compliance_profile === 'oidc'
            ? [{ value: 'bearer', label: 'Bearer tokens (maximum compatibility)' }] : []),
        ]}
        onValueChange={(value) => onChange(changeSenderConstraint(
          draft,
          value as 'dpop' | 'mtls' | 'bearer',
        ))} />}
    </Field>
  </>;
}
