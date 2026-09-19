import type { JSX } from 'react';
import { Field } from './ui';
import { FormSelect } from './components/ui/select';
import { TLS_SUBJECT_FIELDS, type Draft, type TlsSubjectField } from './client-draft';
import { clientFieldError, publicKeyError, type ClientDiscovery } from './client-onboarding';
import { redirectUris } from './validation';

interface SetupProps {
  readonly draft: Draft;
  readonly discovery: ClientDiscovery | null;
  readonly refusal: string | null;
  readonly busy: boolean;
  readonly onChange: (draft: Draft) => void;
}

export function ClientSecurity({ draft, discovery, refusal, busy, onChange }: SetupProps): JSX.Element {
  const methods = [
    ...(draft.compliance_profile === 'oidc' ? ['client_secret_basic'] : []),
    'private_key_jwt', 'tls_client_auth', 'self_signed_tls_client_auth',
  ]
    .filter((method) => method === draft.token_endpoint_auth_method
      || (discovery?.token_endpoint_auth_methods_supported ?? ['private_key_jwt']).includes(method));
  return <>
    <Field label="Security profile" error={clientFieldError(refusal, 'compliance_profile')}
      hint="FAPI is the default hardened profile. Standard OIDC must first be enabled for this tenant and does not receive the FAPI badge.">
      {(props) => <FormSelect {...props} disabled={busy} value={draft.compliance_profile}
        options={[
          { value: 'fapi', label: 'FAPI 2.0 Security Profile' },
          { value: 'oidc', label: 'Standard OIDC (non-FAPI)' },
        ]}
        onValueChange={(value) => onChange({
          ...draft,
          compliance_profile: value as Draft['compliance_profile'],
          token_endpoint_auth_method: value === 'oidc' ? 'client_secret_basic' : 'private_key_jwt',
          jwks: value === 'oidc' ? '' : draft.jwks,
          jwks_uri: value === 'oidc' ? '' : draft.jwks_uri,
        })} />}
    </Field>
    <Field label="Client authentication" error={clientFieldError(refusal, 'token_endpoint_auth_method')}
      hint={draft.token_endpoint_auth_method === 'client_secret_basic'
        ? 'The server creates a secret and shows it once. Store it in your backend secret manager.'
        : 'Use private_key_jwt for a backend that signs assertions. Mutual TLS methods require this deployment’s certificate endpoints.'}>
      {(props) => <FormSelect {...props} disabled={busy} value={draft.token_endpoint_auth_method}
        options={methods.map((value) => ({ value, label: value }))}
        onValueChange={(value) => onChange({ ...draft, token_endpoint_auth_method: value,
          tls_subject_value: value === 'tls_client_auth' ? draft.tls_subject_value : '',
          use_mtls_endpoint_aliases: value !== 'private_key_jwt' || draft.tls_client_certificate_bound_access_tokens === true })} />}
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
      hint="DPoP requires a separate proof key and a fresh proof for token and resource requests. Certificate binding requires mutual TLS.">
      {(props) => <FormSelect {...props} disabled={busy}
        value={draft.tls_client_certificate_bound_access_tokens === true ? 'mtls' : 'dpop'}
        options={[
          { value: 'dpop', label: 'DPoP-bound tokens' },
          ...((discovery?.mtls_endpoint_aliases || draft.tls_client_certificate_bound_access_tokens === true)
            ? [{ value: 'mtls', label: 'Certificate-bound tokens (mTLS)' }] : []),
        ]}
        onValueChange={(value) => onChange({ ...draft, dpop_bound_access_tokens: value === 'dpop',
          tls_client_certificate_bound_access_tokens: value === 'mtls',
          use_mtls_endpoint_aliases: value === 'mtls' || draft.token_endpoint_auth_method !== 'private_key_jwt' })} />}
    </Field>
  </>;
}

export function ClientSetup(props: SetupProps): JSX.Element {
  const { draft, refusal, onChange } = props;
  return <>
    <legend>Confidential application setup</legend>
    <p>Connect a server-side application or backend for frontend. FAPI clients use PAR and asymmetric client authentication.
      Standard OIDC clients may use a shared secret and direct authorization requests. Both use PKCE S256 and sender-constrained tokens.</p>
    <h3>1. Name and callbacks</h3>
    <Field label="Client name" required error={clientFieldError(refusal, 'client_name')}>
      {(field) => <input {...field} value={draft.client_name}
        onChange={(event) => onChange({ ...draft, client_name: event.target.value })} />}
    </Field>
    <Field label="Redirect URIs (one per line)" required
      hint="Enter exact HTTPS callback URLs handled by your backend, for example https://app.example/callback."
      error={clientFieldError(refusal, 'redirect_uris') ?? redirectUris(draft.redirect_uris, draft.application_type)}>
      {(field) => <textarea {...field} rows={3} value={draft.redirect_uris}
        onChange={(event) => onChange({ ...draft, redirect_uris: event.target.value })} />}
    </Field>
    <Field label="Post-logout redirect URIs (one per line)"
      hint="Optional exact HTTPS destinations after RP-initiated logout."
      error={clientFieldError(refusal, 'post_logout_redirect_uris') ?? redirectUris(draft.post_logout_redirect_uris, draft.application_type)}>
      {(field) => <textarea {...field} rows={2} value={draft.post_logout_redirect_uris}
        onChange={(event) => onChange({ ...draft, post_logout_redirect_uris: event.target.value })} />}
    </Field>
    <h3>2. Public keys and security</h3>
    <ClientSecurity {...props} />
    {draft.token_endpoint_auth_method !== 'client_secret_basic' && <><Field label="Inline JWK Set" error={clientFieldError(refusal, 'jwks') ?? publicKeyError(draft)}
      hint="Generate an EdDSA, ES256 or PS256 key in your application. Paste its public keys array, with a kid for rotation. Never paste a private key.">
      {(field) => <textarea {...field} rows={5} value={draft.jwks}
        onChange={(event) => onChange({ ...draft, jwks: event.target.value })} />}
    </Field>
    <Field label="JWK Set URL" error={clientFieldError(refusal, 'jwks_uri')}
      hint="Alternatively publish your public keys at a public HTTPS URL. Private addresses and localhost cannot be fetched; use inline keys for local development.">
      {(field) => <input {...field} type="url" value={draft.jwks_uri}
        onChange={(event) => onChange({ ...draft, jwks_uri: event.target.value })} />}
    </Field></>}
    <h3>3. Access and configuration</h3>
    <Field label="Scope" error={clientFieldError(refusal, 'scope')}
      hint="Space-separated scopes, starting with openid. Request only what the application needs.">
      {(field) => <input {...field} value={draft.scope}
        onChange={(event) => onChange({ ...draft, scope: event.target.value })} />}
    </Field>
    <p>Use the advanced tabs for grant types, signing algorithms and token claims. Register to obtain your client ID and copy the saved connection configuration.</p>
  </>;
}
