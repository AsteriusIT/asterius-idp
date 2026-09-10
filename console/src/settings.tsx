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
 * Theming tokens, the ACR policy editor, rate limits and session lifetimes are
 * named by `ast-bfn` and are *not* here: none of them exists below the API
 * yet, so each needs a domain type, a route and a migration before a control
 * for it can mean anything.
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
 */
const KNOWN_FEATURES: readonly (readonly [string, string])[] = [
  ['mtls', 'mTLS client authentication and certificate-bound tokens (RFC 8705)'],
  ['grant_management', 'Grant Management for OAuth 2.0'],
  ['ciba', 'CIBA backchannel authentication'],
  ['device_flow', 'Device Authorization Grant (RFC 8628)'],
  ['token_exchange', 'Token Exchange (RFC 8693)'],
  ['ssf', 'Shared Signals Framework transmitter'],
  ['authzen', 'AuthZEN Authorization API'],
  ['dpop_nonce', 'Server-issued DPoP nonces (RFC 9449 §8)'],
];

/** The ceilings the server sends with the document. */
export interface Limits {
  readonly max_authorization_code_lifetime_seconds: number;
  readonly max_access_token_lifetime_seconds: number;
}

/** One tenant's settings, as `GET /tenants/{tenant_id}/settings` describes it. */
export interface Settings {
  readonly tenant_id: string;
  readonly disabled_features: readonly string[];
  readonly authorization_code_lifetime_seconds: number;
  readonly access_token_lifetime_seconds: number;
  readonly limits: Limits;
}

/** What the form holds while it is being edited. */
interface Draft {
  readonly disabled: readonly string[];
  readonly code: string;
  readonly token: string;
}

/** What the screen is doing. */
type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly settings: Settings }
  | { readonly kind: 'failed'; readonly message: string };

/** The path of one tenant's settings, relative to the API base. */
export function settingsPath(tenant: string): string {
  return `tenants/${encodeURIComponent(tenant)}/settings`;
}

/** The draft a freshly read document starts as. */
export function draftOf(settings: Settings): Draft {
  return {
    disabled: [...settings.disabled_features],
    code: String(settings.authorization_code_lifetime_seconds),
    token: String(settings.access_token_lifetime_seconds),
  };
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
  const known = KNOWN_FEATURES.map(([key]) => key);
  const unknown = disabled.filter((name) => !known.includes(name));
  return [
    ...KNOWN_FEATURES,
    ...unknown.map((name) => [name, 'A flag this console does not know about.'] as const),
  ];
}

/** Whether the draft differs from what the server last sent. */
export function isDirty(settings: Settings, draft: Draft): boolean {
  const same =
    draft.disabled.length === settings.disabled_features.length &&
    draft.disabled.every((name) => settings.disabled_features.includes(name));
  return (
    !same ||
    draft.code !== String(settings.authorization_code_lifetime_seconds) ||
    draft.token !== String(settings.access_token_lifetime_seconds)
  );
}

export function TenantSettings({ session }: { session: Session }): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const path = settingsPath(session.tenant);

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
        disabled_features: current.disabled,
        // `Number` and not `parseInt`: an entry of `60abc` must be refused
        // rather than quietly become 60. `NaN` fails the server's parse, which
        // is the refusal an operator should see.
        authorization_code_lifetime_seconds: Number(current.code),
        access_token_lifetime_seconds: Number(current.token),
      }).then(
        (document) => {
          // Re-read from the answer rather than from the form: the server's
          // document is the one that is in force.
          const settings = document as Settings;
          setLoad({ kind: 'ready', settings });
          setDraft(draftOf(settings));
          setNotice('Saved.');
          setBusy(false);
        },
        (error: unknown) => {
          setRefusal(error instanceof Error ? error.message : 'the change was refused');
          setBusy(false);
        },
      );
    },
    [path, session],
  );

  if (load.kind === 'loading') {
    return (
      <>
        <h2>Tenant settings</h2>
        <p>Reading the settings.</p>
      </>
    );
  }
  if (load.kind === 'failed') {
    return (
      <>
        <h2>Tenant settings</h2>
        <p>{load.message}</p>
        <button type="button" onClick={refresh}>
          Try again
        </button>
      </>
    );
  }
  if (draft === null) {
    return (
      <>
        <h2>Tenant settings</h2>
        <p>Reading the settings.</p>
      </>
    );
  }

  const settings = load.settings;
  const toggle = (name: string, enabled: boolean): void =>
    setDraft({
      ...draft,
      disabled: enabled
        ? draft.disabled.filter((each) => each !== name)
        : [...draft.disabled, name],
    });

  return (
    <>
      <h2>Tenant settings</h2>
      <p className="muted">
        What <strong>{settings.tenant_id}</strong> is configured to do. Every value below is
        checked again by the server when it is saved.
      </p>

      {notice !== null && (
        <p role="status" aria-live="polite">
          {notice}
        </p>
      )}
      {refusal !== null && (
        <p role="alert" className="refusal">
          {refusal}
        </p>
      )}

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
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          save(draft);
        }}
      >
        <fieldset disabled={busy}>
          <legend>Features</legend>
          <p className="muted">
            A feature that is off is absent from this tenant&rsquo;s discovery document as well
            as refused at its endpoints.
          </p>
          <ul className="switches">
            {featureRows(draft.disabled).map(([name, description]) => (
              <li key={name}>
                <label>
                  <input
                    type="checkbox"
                    name={name}
                    checked={!draft.disabled.includes(name)}
                    onChange={(event) => toggle(name, event.target.checked)}
                  />{' '}
                  <code>{name}</code>
                </label>
                <p className="muted">{description}</p>
              </li>
            ))}
          </ul>
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Lifetimes</legend>
          <p>
            <label htmlFor="code-lifetime">Authorization code lifetime (seconds)</label>
            <input
              id="code-lifetime"
              name="authorization_code_lifetime_seconds"
              type="number"
              min={1}
              max={settings.limits.max_authorization_code_lifetime_seconds}
              value={draft.code}
              onChange={(event) => setDraft({ ...draft, code: event.target.value })}
            />
          </p>
          <p className="muted">
            This deployment refuses anything above{' '}
            {settings.limits.max_authorization_code_lifetime_seconds} seconds.
          </p>
          <p>
            <label htmlFor="token-lifetime">Access token lifetime (seconds)</label>
            <input
              id="token-lifetime"
              name="access_token_lifetime_seconds"
              type="number"
              min={1}
              max={settings.limits.max_access_token_lifetime_seconds}
              value={draft.token}
              onChange={(event) => setDraft({ ...draft, token: event.target.value })}
            />
          </p>
          <p className="muted">
            This deployment refuses anything above{' '}
            {settings.limits.max_access_token_lifetime_seconds} seconds.
          </p>
        </fieldset>

        <p>
          <button type="submit" disabled={busy}>
            Save settings
          </button>{' '}
          <button
            type="button"
            disabled={busy || !isDirty(settings, draft)}
            onClick={() => setDraft(draftOf(settings))}
          >
            Discard changes
          </button>
        </p>
      </form>

      <section aria-labelledby="not-here">
        <h3 id="not-here">Not configurable yet</h3>
        <p className="muted">
          Theme tokens, the ACR policy, rate limits and session lifetimes are not served by this
          release&rsquo;s admin API, so this screen does not offer them. A control that saved
          nowhere would be worse than none.
        </p>
      </section>
    </>
  );
}
