/**
 * The Policy screen (`ast-f7m.9`): the tenant's AuthZEN rule document, and a
 * bench for asking what it decides.
 *
 * Three parts. The editor, which is the document `GET /policies` returns, put
 * back whole by `PUT /policies` — the API takes no partial write, because deny
 * precedence is a property of the rule *set* (ADR-0011). A structured reading
 * of the rules beside it, so that "what does this catalogue actually say" does
 * not require reading JSON. And the test bench, which sends Authorization API
 * 1.0 §6.1's request to `POST /policies/try` and shows §6.2's Decision.
 *
 * # The validation is the server's
 *
 * Nothing here decides whether a document is valid. The draft is sent as
 * typed, the server parses it with the fuzzed parser the evaluator reads
 * through (`crates/domain/src/policy/document.rs`), and its refusal is what
 * this screen shows — with the path it names, `rules[3].when.attribute.of`,
 * and the line when the message carries one. A validator written here would be
 * a second opinion about the rule language, and it is the one that would be
 * wrong: a document this console called valid and the server refused is a
 * confusing screen, and one this console called invalid and the server would
 * have taken is a rule an administrator never wrote.
 *
 * The only parsing done here is `JSON.parse`, for the preview and to tell the
 * administrator where their braces went, and its failure never stops a save.
 *
 * # The bench is not a way to invent facts
 *
 * The form sends the entity types, ids and `properties` of §5, and nothing
 * else. Group membership, application roles, active grants and `acr` are
 * resolved below the API from this tenant's own store; a field for them here
 * would be a field that lies.
 */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, probe, read, type Session } from './api';
import { toast } from './components/ui/toast';
import {
  Actions,
  Badge,
  Button,
  ConfirmDialog,
  DataTable,
  EmptyState,
  Field,
  LoadFailure,
  Message,
  Panel,
  Screen,
  Skeleton,
} from './ui';
import { jsonDocument, jsonObject } from './validation';

/** One rule, as the document carries it (`asterius_domain::policy::Rule`). */
export interface RuleDocument {
  readonly id: string;
  readonly effect: 'permit' | 'deny';
  readonly subject_type?: string;
  readonly resource_type?: string;
  readonly actions?: readonly string[];
  readonly when?: unknown;
  readonly reason_admin?: string;
  readonly reason_user?: string;
  readonly acr_values?: readonly string[];
}

/** The policy, as `GET /policies` renders it. */
export interface PolicyDocument {
  readonly document: { readonly version: number; readonly rules?: readonly RuleDocument[] };
  readonly rule_count: number;
  readonly updated_at: string | null;
}

/**
 * §5.5.1's reason: an object keyed by language tag, not a string.
 *
 * Rendered rather than re-tagged: the console shows what an enforcement point
 * receives, and a sentence an administrator wrote in one language is what is
 * there to show.
 */
export type Reason = Readonly<Record<string, string>>;

/** §5.5's Decision, as the bench receives it. */
export interface DecisionDocument {
  readonly decision: boolean;
  readonly context?: {
    /** The rule that decided, absent on a default deny. */
    readonly id?: string;
    readonly reason_admin?: Reason;
    readonly reason_user?: Reason;
    readonly acr_values?: readonly string[];
    readonly error?: unknown;
  };
}

/**
 * A reason as one line: the English text when there is one, and otherwise the
 * first translation the server sent — a reason in a language this console did
 * not expect is still the administrator's own sentence, and dropping it would
 * leave a deny with no explanation at all.
 */
export function readReason(reason: Reason | undefined): string | undefined {
  if (reason === undefined) {
    return undefined;
  }
  return reason['en'] ?? Object.values(reason)[0];
}

/** What the bench asks about: §6.1's request, as a person fills it in. */
export interface Question {
  readonly subjectType: string;
  readonly subjectId: string;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: string;
  readonly context: string;
}

export const EMPTY_QUESTION: Question = {
  subjectType: 'user',
  subjectId: '',
  action: '',
  resourceType: '',
  resourceId: '',
  context: '',
};

/**
 * Where a refusal points, as the server's message carries it.
 *
 * The parser names a path — `rules[3].when.attribute.of` — and `JSON.parse`
 * names a position, `at line 7 column 12`. Both are read out of the message
 * rather than reconstructed: this console does not know the document's
 * grammar, and a path it computed itself would send an administrator to the
 * wrong rule.
 */
export interface Location {
  readonly path?: string;
  readonly line?: number;
}

/** The path and the line a refusal names, if it names either. */
export function locationOf(message: string): Location {
  const path = /rules\[\d+\](?:[.[][\w.[\]"-]*)?/.exec(message)?.[0];
  const line = /line (\d+)/.exec(message)?.[1];
  return {
    ...(path === undefined ? {} : { path }),
    ...(line === undefined ? {} : { line: Number(line) }),
  };
}

/**
 * The 1-based line `path` sits on in `text`, or `undefined`.
 *
 * A refusal from the rule parser names a path and no position, because it
 * reads a `Value` and not the bytes. The editor still has the bytes, so the
 * rule is found by counting the rule objects that open before it: the *n*th
 * `rules[n]` is the *n*th element of the array, and the array is in document
 * order. Best-effort by construction — it is a scroll hint, not a diagnosis —
 * so anything that does not parse gives nothing rather than a wrong number.
 */
export function lineOfRule(text: string, path: string): number | undefined {
  const index = /rules\[(\d+)\]/.exec(path)?.[1];
  if (index === undefined) {
    return undefined;
  }
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return undefined;
  }
  const rules = (document as { rules?: unknown }).rules;
  if (!Array.isArray(rules)) {
    return undefined;
  }
  const rule = rules[Number(index)] as { id?: unknown } | undefined;
  if (rule === undefined || typeof rule.id !== 'string') {
    return undefined;
  }
  const lines = text.split('\n');
  const needle = JSON.stringify(rule.id);
  const found = lines.findIndex((line) => line.includes(needle));
  return found === -1 ? undefined : found + 1;
}

/** The rules of a draft, for the preview, or `null` if it is not JSON yet. */
export function rulesOf(text: string): readonly RuleDocument[] | null {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return null;
  }
  const rules = (document as { rules?: unknown }).rules;
  return Array.isArray(rules) ? (rules as readonly RuleDocument[]) : null;
}

/**
 * §6.1's request, built from the form.
 *
 * A blank field is left out rather than sent as an empty string: the server
 * refuses an empty `id`, and "" would be a 400 that says nothing about what
 * the administrator left out. `context` is sent only when it parses as an
 * object, and the caller has already been told when it does not.
 */
export function questionToRequest(question: Question): Record<string, unknown> {
  const request: Record<string, unknown> = {
    subject: { type: question.subjectType.trim(), id: question.subjectId.trim() },
    action: { name: question.action.trim() },
    resource: { type: question.resourceType.trim(), id: question.resourceId.trim() },
  };
  const properties = question.context.trim();
  if (properties !== '') {
    request['context'] = { properties: JSON.parse(properties) as unknown };
  }
  return request;
}

/** What a rule says, in one line, for the preview. */
export function describeRule(rule: RuleDocument): string {
  const subject = rule.subject_type ?? 'any subject';
  const resource = rule.resource_type ?? 'any resource';
  const actions =
    rule.actions === undefined || rule.actions.length === 0
      ? 'any action'
      : rule.actions.join(', ');
  return `${subject} → ${actions} → ${resource}`;
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly policy: PolicyDocument }
  | { readonly kind: 'failed'; readonly message: string };

export function Policy({ session }: { session: Session }): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [draft, setDraft] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // The question in front of the one irreversible act on this screen.
  const [removing, setRemoving] = useState(false);
  const mayWrite = session.scopes.includes('admin.policies:write');

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read('policies').then(
      (value) => {
        const policy = value as PolicyDocument;
        setLoad({ kind: 'ready', policy });
        setDraft(`${JSON.stringify(policy.document, null, 2)}\n`);
      },
      (error: unknown) =>
        setLoad({
          kind: 'failed',
          message: error instanceof Error ? error.message : 'the policy could not be read',
        }),
    );
  }, []);

  useEffect(refresh, [refresh]);

  /** Runs one edit, then re-reads the document the server now holds. */
  const run = (call: () => Promise<unknown>, success: string, announced: string): void => {
    setBusy(true);
    setNotice(null);
    setRefusal(null);
    call().then(
      () => {
        setBusy(false);
        setNotice(success);
        // The announcement; the sentence above is the record (`ast-f9j5` (3)).
        // A policy screen is long enough that "Save policy" and the line that
        // says it worked are not on screen together. The toast carries the
        // title alone and not a copy of that sentence: two elements saying the
        // same words are two things to read and — as the sweep found — two
        // things a test cannot tell apart.
        toast.success(announced);
        refresh();
      },
      (error: unknown) => {
        setBusy(false);
        const message = error instanceof Error ? error.message : 'the change was refused';
        setRefusal(message);
        // The toast says *that* it was refused; the panel above says why, with
        // the path and the line, which is the part an operator has to act on
        // and therefore the part that must not scroll away.
        toast.error('The policy was not changed');
      },
    );
  };

  const save = (): void => {
    let document: unknown;
    try {
      document = JSON.parse(draft);
    } catch (error: unknown) {
      // Not sent: a body that is not JSON has no path for the server to name,
      // and `JSON.parse` has already said which line the braces went wrong on.
      setNotice(null);
      const message = error instanceof Error ? error.message : 'the document is not JSON';
      setRefusal(message);
      toast.error('The policy was not sent');
      return;
    }
    run(
      () => mutate('policies', 'PUT', session, document),
      'The policy was replaced.',
      'Policy saved',
    );
  };

  if (load.kind === 'loading') {
    return (
      <Screen title="Policy">
        <Panel title="Reading">
          <Skeleton rows={5} label="Reading the policy." />
        </Panel>
      </Screen>
    );
  }
  if (load.kind === 'failed') {
    return (
      <Screen title="Policy">
        <Panel title="The policy could not be read">
          <LoadFailure message={load.message} onRetry={refresh} />
        </Panel>
      </Screen>
    );
  }

  const preview = rulesOf(draft);
  const location = refusal === null ? {} : locationOf(refusal);
  const line = location.line ?? (location.path === undefined ? undefined : lineOfRule(draft, location.path));

  return (
    <Screen
      title="Policy"
      description={
        <>
          The rules <strong>{session.tenant}</strong> is decided by. An enforcement point asks
          whether a subject may take an action on a resource, and this document answers; an
          explicit deny wins, and a request no rule matches is denied.{' '}
          {load.policy.rule_count === 0
            ? 'This tenant has no policy yet, so every evaluation is denied.'
            : `${load.policy.rule_count} rule${load.policy.rule_count === 1 ? '' : 's'}, last changed ${load.policy.updated_at ?? 'never'}.`}
        </>
      }
    >
      {notice !== null && <Message tone="success">{notice}</Message>}
      {/*
        Not a `Message`, because this refusal has a second line the component
        does not take: the JSON path the server named, and the line of the
        draft it falls on. Same treatment, same mark, one more sentence.
      */}
      {refusal !== null && (
        <div role="alert" className="message error">
          <span className="message-mark" aria-hidden="true">
            &#9888;
          </span>
          <span className="message-body">
            <p>{refusal}</p>
            {(location.path !== undefined || line !== undefined) && (
              <p>
                {location.path !== undefined && (
                  <>
                    At <code>{location.path}</code>
                  </>
                )}
                {line !== undefined && <> (line {line})</>}
              </p>
            )}
          </span>
        </div>
      )}

      <Panel title="Rules">
      {preview === null ? (
        <p className="muted">The draft below is not JSON yet, so there is nothing to summarise.</p>
      ) : (
        <DataTable
          rows={preview.map((rule, index) => ({ rule, index }))}
          rowKey={({ rule, index }) => `${index}-${rule.id}`}
          empty={<EmptyState title="No rule." body="Every evaluation is denied." />}
          // A catalogue is read to answer "what decides this" (`ast-f9j5` (1)).
          // The condition is searched with everything else, because an
          // administrator hunting a rule usually remembers the attribute it
          // reads and not the name somebody gave it.
          search={{
            of: ({ rule }) =>
              `${rule.id} ${rule.effect} ${describeRule(rule)} ${
                rule.when === undefined ? 'always' : JSON.stringify(rule.when)
              } ${rule.reason_admin ?? ''}`,
            placeholder: 'Filter by rule, effect or condition…',
            label: 'Filter these rules by rule, effect, what they match or their condition',
          }}
          columns={[
            {
              key: 'rule',
              header: 'Rule',
              sortBy: ({ rule }) => rule.id,
              cell: ({ rule }) => <code>{rule.id}</code>,
            },
            {
              key: 'effect',
              header: 'Effect',
              sortBy: ({ rule }) => rule.effect,
              cell: ({ rule }) => (
                <Badge tone={rule.effect === 'permit' ? 'ok' : 'bad'}>{rule.effect}</Badge>
              ),
            },
            { key: 'matches', header: 'Matches', cell: ({ rule }) => describeRule(rule) },
            {
              key: 'condition',
              header: 'Condition',
              cell: ({ rule }) => (
                <code>{rule.when === undefined ? 'always' : JSON.stringify(rule.when)}</code>
              ),
            },
            { key: 'reason', header: 'Reason', cell: ({ rule }) => rule.reason_admin ?? '' },
          ]}
        />
      )}
      </Panel>

      <Panel title="Document">
        <Field
          label="The rule document, as the evaluator reads it"
          // The one thing this screen is allowed to say about the draft before
          // the server sees it: whether the braces close. It is the same
          // `JSON.parse` `save` already runs — a few keystrokes earlier — and
          // it says nothing about the *rules*, which are the server's subject
          // and this module's opening paragraph.
          error={jsonDocument(draft, 'The document')}
        >
          {(props) => (
            <textarea
              {...props}
              name="document"
              rows={20}
              spellCheck={false}
              value={draft}
              readOnly={!mayWrite}
              onChange={(event) => setDraft(event.target.value)}
            />
          )}
        </Field>
        {mayWrite ? (
          <Actions>
            <Button variant="danger" disabled={busy} onClick={() => setRemoving(true)}>
              Remove policy
            </Button>
            <Button disabled={busy} onClick={refresh}>
              Discard changes
            </Button>
            <Button variant="primary" disabled={busy} onClick={save}>
              Save policy
            </Button>
          </Actions>
        ) : (
          <p className="muted">
            This session may read the policy and not change it (<code>admin.policies:write</code>{' '}
            is what a change needs).
          </p>
        )}
      </Panel>

      <TestBench session={session} />

      {removing && (
        <ConfirmDialog
          title="Remove the policy?"
          body="Every evaluation for this tenant is denied until a new document is saved."
          confirmLabel="Remove it"
          busy={busy}
          onCancel={() => setRemoving(false)}
          onConfirm={() => {
            setRemoving(false);
            run(
              () => mutate('policies', 'DELETE', session),
              'The policy was removed. Every evaluation is denied.',
              'Policy removed',
            );
          }}
        />
      )}
    </Screen>
  );
}

type Answer =
  | { readonly kind: 'idle' }
  | { readonly kind: 'asking' }
  | { readonly kind: 'answered'; readonly decision: DecisionDocument }
  | { readonly kind: 'failed'; readonly message: string };

/**
 * The bench: one evaluation, answered by the document the server holds.
 *
 * The answer is the decision an enforcement point would receive, and it is
 * shown as one — `permit` or `deny`, the rule that decided, the two reasons of
 * §5.5.1 and the `acr_values` a step-up would need. A refusal is kept apart
 * from a deny on purpose: "this request could not be read" and "your rules say
 * no" are different things to learn, and merging them would send an
 * administrator to edit a rule that was never consulted.
 */
function TestBench({ session }: { session: Session }): JSX.Element {
  const [question, setQuestion] = useState<Question>(EMPTY_QUESTION);
  const [answer, setAnswer] = useState<Answer>({ kind: 'idle' });

  const ask = (): void => {
    let request: Record<string, unknown>;
    try {
      request = questionToRequest(question);
    } catch (error: unknown) {
      setAnswer({
        kind: 'failed',
        message:
          error instanceof Error
            ? `the context properties are not JSON: ${error.message}`
            : 'the context properties are not JSON',
      });
      return;
    }
    setAnswer({ kind: 'asking' });
    probe('policies/try', session, request).then(
      (value) => setAnswer({ kind: 'answered', decision: value as DecisionDocument }),
      (error: unknown) =>
        setAnswer({
          kind: 'failed',
          message: error instanceof Error ? error.message : 'the request was refused',
        }),
    );
  };

  const field = (
    name: keyof Question,
    label: string,
    placeholder: string,
  ): JSX.Element => (
    <Field label={label}>
      {(props) => (
        <input
          {...props}
          name={name}
          type="text"
          value={question[name]}
          placeholder={placeholder}
          maxLength={256}
          onChange={(event) => setQuestion({ ...question, [name]: event.target.value })}
        />
      )}
    </Field>
  );

  return (
    <Panel
      title="Try a request"
      description="The question an enforcement point would ask. The subject's groups, application roles, active authorizations and authentication level are read from this tenant's own records, and cannot be filled in here: a rule that reads them is answered with what the server knows. Nothing asked here is enforced, and nothing is stored."
    >
      <form
        className="toolbar"
        onSubmit={(event) => {
          event.preventDefault();
          ask();
        }}
      >
        {field('subjectType', 'Subject type', 'user')}
        {field('subjectId', 'Subject', 'the sub this server issued')}
        {field('action', 'Action', 'read')}
        {field('resourceType', 'Resource type', 'document')}
        {field('resourceId', 'Resource', 'an identifier your application uses')}
        <Field
          label="Context properties (JSON)"
          error={jsonObject(question.context, 'The context properties')}
        >
          {(props) => (
            <input
              {...props}
              name="context"
              type="text"
              value={question.context}
              placeholder='{"ip": "198.51.100.7"}'
              maxLength={1024}
              onChange={(event) => setQuestion({ ...question, context: event.target.value })}
            />
          )}
        </Field>
        <Actions>
          <Button
            onClick={() => {
              setQuestion(EMPTY_QUESTION);
              setAnswer({ kind: 'idle' });
            }}
          >
            Clear
          </Button>
          <Button type="submit" variant="primary" disabled={answer.kind === 'asking'}>
            Ask the policy
          </Button>
        </Actions>
      </form>

      <Verdict answer={answer} />
    </Panel>
  );
}

function Verdict({ answer }: { answer: Answer }): JSX.Element {
  if (answer.kind === 'idle') {
    return <p className="muted">No request asked yet.</p>;
  }
  if (answer.kind === 'asking') {
    return <Skeleton rows={2} label="Asking the policy." />;
  }
  if (answer.kind === 'failed') {
    return <Message tone="error">{answer.message}</Message>;
  }

  const context = answer.decision.context ?? {};
  const admin = readReason(context.reason_admin);
  const user = readReason(context.reason_user);
  // A named region rather than a bare list: the answer is what the
  // administrator came for, and a screen reader moving by landmark should be
  // able to reach it — and the browser sweep can then assert on *the decision*
  // rather than on a word that also appears in the document above.
  return (
    <section aria-label="Decision">
    <dl className="detail">
      <div>
        <dt>Decision</dt>
        <dd>
          <strong>{answer.decision.decision ? 'permit' : 'deny'}</strong>
        </dd>
      </div>
      {context.id !== undefined && (
        <div>
          <dt>Rule</dt>
          <dd>
            <code>{context.id}</code>
          </dd>
        </div>
      )}
      {admin !== undefined && (
        <div>
          <dt>Reason (operator)</dt>
          <dd>{admin}</dd>
        </div>
      )}
      {user !== undefined && (
        <div>
          <dt>Reason (person)</dt>
          <dd>{user}</dd>
        </div>
      )}
      {context.acr_values !== undefined && context.acr_values.length > 0 && (
        <div>
          <dt>Step-up would need</dt>
          <dd>
            <code>{context.acr_values.join(' ')}</code>
          </dd>
        </div>
      )}
      {context.error !== undefined && (
        <div>
          <dt>Error</dt>
          <dd>
            <code>{JSON.stringify(context.error)}</code>
          </dd>
        </div>
      )}
      </dl>
    </section>
  );
}
