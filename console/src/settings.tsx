/**
 * The tenant settings screen (`ast-bfn`).
 *
 * What one tenant's administrators can change about it: which optional
 * features are switched on, and how long an authorization code and an access
 * token live. Those are the settings the admin API serves
 * (`GET`/`PUT /tenants/{tenant_id}/settings`, `ast-f7m.4`), and this screen is
 * deliberately no wider than that — a form whose `PUT` goes nowhere is worse
 * than an absent one, because it tells an operator a change was saved.
 *
 * Assurance, session and rate-limit policies share the scoped settings API.
 * Runtime branding controls remain tracked separately.
 *
 * # The ceilings are the server's
 *
 * `max_input` below is a courtesy to whoever is typing, not a limit. FAPI
 * 2.0 Security Profile §5.3.1.1 caps an authorization code at sixty seconds,
 * and that cap is applied in `asterius_domain::TenantSettings::validated`,
 * below the API, where a `curl` with a session cookie meets it too. The
 * numbers this form uses come from the `limits` member of the document the
 * server just sent, so a console pinned to an older release shows the server's
 * ceilings rather than its own — and when a value is refused anyway, what is
 * displayed is the server's sentence, which names the clause.
 *
 * # No third-party anything
 *
 * The console runs under a strict nonce CSP with `connect-src 'self'`
 * (ADR-0009). Every control here is an ordinary form element, every handler is
 * attached by React rather than written into markup, and nothing is fetched
 * from anywhere but this origin.
 */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { ShieldCheck, KeyRound, Smartphone, ArrowRightLeft, Radio, Fingerprint, Users, Settings2 } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
import { toast } from './components/ui/toast';
import { Actions, Button, Field, LoadFailure, Message, Panel, Screen, Skeleton } from './ui';
import { SessionPolicyFields } from './session-policy';

import { AssuranceEditor } from './assurance-policy';
import { draftOf, isDirty, type Draft, type Settings } from './settings-model';
import { RateLimitFields } from './rate-limit-fields';
import { rateDocument } from './rate-limit-model';

/**
 * The optional features this console draws a switch for, mirroring
 * `asterius_domain::Feature::ALL`.
 *
 * A list here rather than one fetched, because the API's settings document
 * reports only what is *disabled* — it has no "everything this build knows"
 * member — and a screen with no list would show an operator nothing to switch
 * on. It is therefore a display list and nothing else: a name this build has
 * forgotten still arrives in `disabled_features` and is still rendered (see
 * {@link featureRows}), so a flag the console does not know about cannot be
 * silently switched on by saving the form.
 *
 * The label says what the feature does for the deployment, not which
 * document defines it (`ast-k7az.4`): an administrator deciding whether to
 * switch `device_flow` on is served by "a device with no keyboard" and not
 * by "RFC 8628". In order: RFC 8705, Grant Management for OAuth 2.0,
 * CIBA, RFC 8628, RFC 8693, SSF 1.0, AuthZEN 1.0, RFC 9449 §8.
 */
const KNOWN_FEATURES: readonly (readonly [string, string])[] = [
  [
    'mtls',
    'Clients prove themselves with a TLS certificate, and their tokens work only from it',
  ],
  ['grant_management', 'Grant Management for OAuth 2.0'],
  ['ciba', 'CIBA backchannel authentication'],
  ['device_flow', 'Sign-in on a device with no keyboard, by entering a code on another screen'],
  ['token_exchange', 'A service swaps one token for another to act on someone’s behalf'],
  ['ssf', 'Shared Signals Framework transmitter'],
  ['authzen', 'AuthZEN Authorization API'],
  [
    'dpop_nonce',
    'Clients sign a challenge this server hands out, so a captured proof cannot be reused',
  ],
];

const FEATURE_PRESENTATION = {
  mtls: { label: 'Certificate-bound access', icon: ShieldCheck, description: 'Authenticate applications with mutual TLS and bind tokens to their certificate.' },
  grant_management: { label: 'Consent management', icon: Users, description: 'Let applications manage the access their users have granted.' },
  ciba: { label: 'Decoupled authentication', icon: Smartphone, description: 'Approve a sign-in on a separate, trusted device.' },
  device_flow: { label: 'Device sign-in', icon: KeyRound, description: 'Sign in on TVs and other devices using a code on another screen.' },
  token_exchange: { label: 'Token exchange', icon: ArrowRightLeft, description: 'Allow services to exchange tokens to act on a user’s behalf.' },
  ssf: { label: 'Security event sharing', icon: Radio, description: 'Share security events with connected services using SSF.' },
  authzen: { label: 'Authorization decisions', icon: Settings2, description: 'Let applications request access decisions through AuthZEN.' },
  dpop_nonce: { label: 'Proof replay protection', icon: Fingerprint, description: 'Require a fresh challenge for DPoP proofs to prevent reuse.' },
};

/** What the screen is doing. */
type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly settings: Settings }
  | { readonly kind: 'failed'; readonly message: string };

/** The path of one tenant's settings, relative to the API base. */
export function settingsPath(tenant: string): string {
  return `tenants/${encodeURIComponent(tenant)}/settings`;
}

/**
 * Every switch to draw: the flags this build knows, plus any the server
 * reports disabled that it does not.
 *
 * The second half is what keeps a `PUT` from dropping somebody else's flag: a
 * console that rendered only its own list would send back a
 * `disabled_features` missing the unknown name, and the whole-document replace
 * would switch that feature on.
 */
export function featureRows(
  disabled: readonly string[],
): readonly (readonly [string, string])[] {
  const known = new Set(KNOWN_FEATURES.map(([key]) => key));
  const unknown = disabled.filter((name) => !known.has(name));
  return [
    ...KNOWN_FEATURES,
    ...unknown.map((name) => [name, 'A flag this console does not know about.'] as const),
  ];
}

/**
 * One tenant's settings: the session's own, or the one the Tenants screen named
 * (`ast-l5bl`).
 *
 * `tenant` is a fragment parameter and is trusted for nothing: it becomes the
 * `{tenant_id}` of a path the server re-authorises, and a caller who may not
 * read that tenant gets the 403 drawn as a failed load. What it buys is the
 * link `ast-l5bl` asks for — a deployment administrator reading a row in the
 * tenant list can open that tenant's settings — without a second screen that
 * would drift from this one.
 */
export function TenantSettings({
  session,
  tenant,
}: Readonly<{
  session: Session;
  /** The tenant to configure. The active workspace when absent. */
  tenant?: string | null;
}>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const subject = tenant ?? session.workspace;
  const elsewhere = subject !== session.workspace;
  const path = settingsPath(subject);

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read(path).then(
      (document) => {
        const settings = document as Settings;
        setLoad({ kind: 'ready', settings });
        setDraft(draftOf(settings));
      },
      (error: unknown) =>
        setLoad({
          kind: 'failed',
          message: error instanceof Error ? error.message : 'the settings could not be read',
        }),
    );
  }, [path]);

  useEffect(refresh, [refresh]);

  const save = useCallback(
    (current: Draft) => {
      setBusy(true);
      setNotice(null);
      setRefusal(null);
      mutate(path, 'PUT', session, {
        acr_policy: current.acrPolicy,
        disabled_features: current.disabled,
        // `Number` and not `parseInt`: an entry of `60abc` must be refused
        // rather than quietly become 60. `NaN` fails the server's parse, which
        // is the refusal an operator should see.
        authorization_code_lifetime_seconds: Number(current.code),
        access_token_lifetime_seconds: Number(current.token),
        always_ask_consent: current.alwaysAskConsent,
        session_policy: { idle_seconds: Number(current.sessionIdle), absolute_seconds: Number(current.sessionAbsolute) },

        ...(load.kind === 'ready' && load.settings.rate_limit_bounds !== undefined ? { rate_limits: rateDocument(current.rateLimits) } : {}),
      }).then(
        (document) => {
          // Re-read from the answer rather than from the form: the server's
          // document is the one that is in force.
          const settings = document as Settings;
          setLoad({ kind: 'ready', settings });
          setDraft(draftOf(settings));
          setNotice('Saved.');
          toast.success('The tenant settings were saved');
          setBusy(false);
        },
        (error: unknown) => {
          setRefusal(error instanceof Error ? error.message : 'the change was refused');
          setBusy(false);
        },
      );
    },
    [load, path, session],
  );

  if (load.kind === 'loading') {
    return (
      <Screen title="Tenant settings">
        <Panel title="Reading">
          <Skeleton rows={5} label="Reading the settings." />
        </Panel>
      </Screen>
    );
  }
  if (load.kind === 'failed') {
    return (
      <Screen title="Tenant settings">
        <Panel title="The settings could not be read">
          <LoadFailure message={load.message} onRetry={refresh} />
        </Panel>
      </Screen>
    );
  }

  if (draft === null) return <Skeleton rows={5} label="Reading the settings." />;
  const settings = load.settings;
  const refused = refusedField(refusal);
  const toggle = (name: string, enabled: boolean): void =>
    setDraft({
      ...draft,
      disabled: enabled
        ? draft.disabled.filter((each) => each !== name)
        : [...draft.disabled, name],
    });

  return (
    <Screen
      title="Tenant settings"
      description={
        <>
          Manage sign-in capabilities and token security for <strong>{settings.tenant_id}</strong>.
        </>
      }
    >
      {elsewhere && (
        <Message tone="info">
          These are the settings of <strong>{settings.tenant_id}</strong>, opened from the tenant
          list. You are signed in to <strong>{session.tenant}</strong>.
        </Message>
      )}
      {notice !== null && <Message tone="success">{notice}</Message>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}

      {/*
        `noValidate`, so that an out-of-range value reaches the server.

        The `max` attributes below are what tell an operator where the ceiling
        is, and the number in them is the server's own. But the browser's
        constraint validation would *block* the submission of a value above it
        and show a tooltip that names no clause — leaving the one message worth
        reading, "exceeds the maximum of 60 s required by FAPI 2.0 Security
        Profile §5.3.2.1 item 11", unreachable from this screen. The ceiling is
        applied in `asterius_domain::TenantSettings::validated` either way, so
        nothing is lost by letting the request be made and everything is gained
        by showing what came back.
      */}
      <div className="tenant-configuration">
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          save(draft);
        }}
      >
        <Tabs defaultValue="features"><TabsList aria-label="Tenant configuration"><TabsTrigger value="features">Capabilities</TabsTrigger><TabsTrigger value="tokens">Token lifetimes</TabsTrigger><TabsTrigger value="consent">Consent</TabsTrigger><TabsTrigger value="sessions">Sessions</TabsTrigger>{draft.acrPolicy && <TabsTrigger value="assurance">Authentication</TabsTrigger>}{settings.rate_limit_bounds !== undefined && <TabsTrigger value="rate-limits">Rate limits</TabsTrigger>}</TabsList>
        <TabsContent value="features"><fieldset className="settings-section" disabled={busy}>
          <legend>Sign-in and access capabilities</legend>
          <p className="muted">
            Choose which capabilities applications can use in this workspace. Changes take effect when you save.
          </p>
          <div className="capability-list">
            {featureRows(draft.disabled).map(([name, description]) => {
              const feature = FEATURE_PRESENTATION[name as keyof typeof FEATURE_PRESENTATION];
              const Icon = feature?.icon ?? Settings2;
              const enabled = !draft.disabled.includes(name);
              return <label className="capability-row" key={name}>
                <span className="capability-icon"><Icon aria-hidden="true" /></span>
                <span className="capability-copy"><strong>{feature?.label ?? name}</strong><span>{feature?.description ?? description}</span></span>
                <span className="capability-state" aria-hidden="true">{enabled ? 'Enabled' : 'Disabled'}</span>
                <input className="capability-switch" type="checkbox" role="switch" name={name}
                  aria-label={feature?.label ?? name} checked={enabled}
                  onChange={(event) => toggle(name, event.target.checked)} />
              </label>;
            })}
          </div>
        </fieldset></TabsContent>

        <TabsContent value="tokens"><fieldset className="settings-section lifetime-settings" disabled={busy}>
          <legend>Token lifetimes</legend>
          <p className="muted">Control how long codes and access tokens remain valid. Shorter lifetimes reduce the window for misuse.</p>
          <Field
            label="Authorization code lifetime (seconds)"
            hint={`Time to exchange a sign-in code for tokens. Maximum ${settings.limits.max_authorization_code_lifetime_seconds} seconds.`}
            error={refused === 'code' ? 'This is the value the server refused above.' : null}
          >
            {(props) => (
              <input
                {...props}
                name="authorization_code_lifetime_seconds"
                type="number"
                min={1}
                max={settings.limits.max_authorization_code_lifetime_seconds}
                value={draft.code}
                onChange={(event) => setDraft({ ...draft, code: event.target.value })}
              />
            )}
          </Field>
          <Field
            label="Access token lifetime (seconds)"
            hint={`Time an access token can be used before renewal. Maximum ${settings.limits.max_access_token_lifetime_seconds} seconds.`}
            error={refused === 'token' ? 'This is the value the server refused above.' : null}
          >
            {(props) => (
              <input
                {...props}
                name="access_token_lifetime_seconds"
                type="number"
                min={1}
                max={settings.limits.max_access_token_lifetime_seconds}
                value={draft.token}
                onChange={(event) => setDraft({ ...draft, token: event.target.value })}
              />
            )}
          </Field>
        </fieldset></TabsContent>

        <TabsContent value="sessions"><SessionPolicyFields draft={draft} onChange={setDraft} busy={busy} refusal={refusal} /></TabsContent>
        <TabsContent value="consent"><fieldset className="settings-section" disabled={busy}>
          <legend>Consent decisions</legend>
          <p className="muted">
            Decide whether a previous approval can take returning users directly back to an application.
          </p>
          <div className="capability-list">
            <label className="capability-row">
              <span className="capability-icon"><Users aria-hidden="true" /></span>
              <span className="capability-copy">
                <strong>Always show consent</strong>
                <span>Ask on every interactive authorization, even when the same access was approved before. Users can review or deny each request; silent requests return consent_required.</span>
              </span>
              <span className="capability-state" aria-hidden="true">{draft.alwaysAskConsent ? 'Enabled' : 'Disabled'}</span>
              <input
                className="capability-switch"
                type="checkbox"
                role="switch"
                name="always_ask_consent"
                aria-label="Always show consent"
                checked={draft.alwaysAskConsent}
                onChange={(event) => setDraft({ ...draft, alwaysAskConsent: event.target.checked })}
              />
            </label>
          </div>
        </fieldset></TabsContent>
        {draft.acrPolicy && <TabsContent value="assurance"><AssuranceEditor
          policy={draft.acrPolicy} disabled={busy}
          onChange={(acrPolicy) => setDraft({ ...draft, acrPolicy })} /></TabsContent>}

        {settings.rate_limit_bounds !== undefined && <TabsContent value="rate-limits"><fieldset className="settings-section" disabled={busy}>
          <RateLimitFields bounds={settings.rate_limit_bounds} effective={settings.effective_rate_limits ?? settings.rate_limit_bounds}
            draft={draft.rateLimits} refusal={refusal} onChange={(rateLimits) => setDraft({ ...draft, rateLimits })} />
        </fieldset></TabsContent>}
        </Tabs>

        <Actions>
          <Button
            disabled={busy || !isDirty(settings, draft)}
            onClick={() => setDraft(draftOf(settings))}
          >
            Discard changes
          </Button>
          <Button type="submit" variant="primary" disabled={busy}>
            Save settings
          </Button>
        </Actions>
      </form>
      </div>
    </Screen>
  );
}

/**
 * Which field the server's refusal is about, when it is about one.
 *
 * The admin API answers `{"error": {"code", "message"}}` and nothing in that
 * envelope is a JSON pointer, so there is no *path* to read: what there is, is
 * a sentence the server wrote about a named lifetime. Matching on the name is
 * therefore the whole of what this console may claim to know, and it claims it
 * quietly — the sentence itself stays at the top of the form, in the alert,
 * exactly as the server wrote it. The field only gets a mark saying "this one",
 * which is the thing an operator was looking for when they read the sentence.
 *
 * `null` when the message names neither, which is the ordinary case for a
 * refusal about something else: a guess would point at the wrong field.
 */
export function refusedField(message: string | null): 'code' | 'token' | null {
  if (message === null) {
    return null;
  }
  const said = message.toLowerCase();
  if (said.includes('authorization code')) {
    return 'code';
  }
  if (said.includes('access token')) {
    return 'token';
  }
  return null;
}
