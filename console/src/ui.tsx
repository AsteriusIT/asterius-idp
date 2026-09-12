/**
 * The console's own components (`ast-fe39`).
 *
 * Nine screens were written one at a time, and each invented its own way of
 * saying the same six things: this is the screen you are on, this is a section
 * of it, this went wrong, this worked, this is a table, are you sure. The
 * result was a console that did not look like one product — and did not look
 * like the pages `7f428d2` redrew either.
 *
 * So the six things live here, in the visual language of those pages
 * (`tokens.css`, `styles.css`). Nothing in this file talks to the network, and
 * no screen's behaviour lives here: a component takes what to draw and gives
 * back what was pressed. That is what makes the migration of a screen a change
 * of markup and not a change of what it does — the admin API calls, their
 * scopes and their refusals are exactly where they were.
 *
 * # No component framework
 *
 * On purpose, and it is the kind of decision that should be written down
 * rather than discovered. A UI library is a dependency tree inside the most
 * privileged page this deployment serves, shipped to every browser that opens
 * it, and the console needs a table, a dialog and six wrappers. React and
 * `react-dom` remain the console's only runtime dependencies.
 */
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { JSX, ReactNode } from 'react';

/* ---- layout ------------------------------------------------------------ */

/**
 * One screen: its name, what it is for, and what can be done to all of it.
 *
 * The heading is an `<h2>` because the shell owns the `<h1>` — one document,
 * one first-level heading, and the screens are sections of it.
 */
export function Screen({
  title,
  description,
  actions,
  children,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}): JSX.Element {
  return (
    <div className="screen">
      <div className="screen-head">
        <div className="screen-title">
          <h2>{title}</h2>
          {description !== undefined && <p className="muted">{description}</p>}
        </div>
        {actions !== undefined && <div className="screen-actions">{actions}</div>}
      </div>
      {children}
    </div>
  );
}

/**
 * One section of a screen, drawn as a panel.
 *
 * `aria-labelledby` rather than `aria-label`: the heading is on screen, and a
 * region labelled by text nobody can see is a second name for the same thing.
 * The id is generated when the caller does not supply one, so two panels with
 * the same title on one screen do not collide.
 */
export function Panel({
  title,
  id,
  description,
  actions,
  children,
}: {
  title: string;
  id?: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}): JSX.Element {
  const generated = useId();
  const headingId = id ?? generated;
  return (
    <section className="panel" aria-labelledby={headingId}>
      <div className="panel-head">
        <div className="panel-title">
          <h3 id={headingId}>{title}</h3>
          {description !== undefined && <p className="muted">{description}</p>}
        </div>
        {actions !== undefined && <div className="actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

/** The centred card the user-facing pages are drawn as: one sentence, one act. */
export function CenteredCard({
  heading,
  children,
}: {
  heading: string;
  children?: ReactNode;
}): JSX.Element {
  return (
    <main id="content" tabIndex={-1} className="page">
      <div className="card">
        <span className="brand-mark" aria-hidden="true">
          A
        </span>
        <h1>{heading}</h1>
        {children}
      </div>
    </main>
  );
}

/* ---- controls ---------------------------------------------------------- */

/** Which of the three things a control does. */
export type Variant = 'primary' | 'secondary' | 'danger' | 'ghost';

/**
 * A button.
 *
 * `primary` is spent once per view — direction A's rule, and the reason the
 * default is `secondary`: a screen where everything is emphasised has emphasised
 * nothing. `danger` is not red-filled, because a destructive act is *confirmed*
 * rather than shouted at; the dialog is where the weight is.
 */
export function Button({
  variant = 'secondary',
  small = false,
  type = 'button',
  children,
  ...rest
}: {
  variant?: Variant;
  small?: boolean;
  // React 19 passes `ref` as an ordinary prop to a function component, so the
  // dialog can hold one without `forwardRef` in the tree.
} & React.ComponentProps<'button'>): JSX.Element {
  const classes = ['', variant === 'secondary' ? '' : variant, small ? 'small' : '']
    .filter((name) => name !== '')
    .join(' ');
  return (
    <button type={type} className={classes === '' ? undefined : classes} {...rest}>
      {children}
    </button>
  );
}

/** A row of controls, the decisive one last. */
export function Actions({
  end = false,
  children,
}: {
  end?: boolean;
  children: ReactNode;
}): JSX.Element {
  return <div className={end ? 'actions end' : 'actions'}>{children}</div>;
}

/**
 * One field: its label, its help and the refusal that belongs to it.
 *
 * `error` is the server's own sentence, shown at the field when the refusal
 * named a path this screen recognises — an operator who typed a bad redirect
 * URI should read about it beside the redirect URIs and not at the top of a
 * form. It is wired with `aria-describedby` and `aria-invalid` through the
 * render callback, so the control the caller draws carries them.
 */
export function Field({
  label,
  hint,
  error,
  required = false,
  children,
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  required?: boolean;
  children: (props: {
    id: string;
    'aria-describedby': string | undefined;
    'aria-invalid': boolean | undefined;
    required: boolean;
  }) => ReactNode;
}): JSX.Element {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const described = [hint !== undefined ? hintId : '', error ? errorId : '']
    .filter((name) => name !== '')
    .join(' ');
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children({
        id,
        'aria-describedby': described === '' ? undefined : described,
        'aria-invalid': error ? true : undefined,
        required,
      })}
      {hint !== undefined && (
        <p className="hint" id={hintId}>
          {hint}
        </p>
      )}
      {error ? (
        <p className="field-error" id={errorId}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

/* ---- messages ---------------------------------------------------------- */

/** What a message is about. */
export type Tone = 'success' | 'error' | 'info';

/**
 * A sentence about what just happened, beside the thing it happened to.
 *
 * A refusal is `role="alert"` and an outcome is `role="status"`, which is the
 * distinction the browser sweep already asserts: a screen that reported a
 * refusal in a polite live region would have an administrator reading "saved"
 * and "refused" in the same voice.
 *
 * The mark is decorative — the colour is not the message and neither is the
 * glyph, the sentence is — so it is hidden from the accessibility tree.
 */
export function Message({
  tone,
  children,
}: {
  tone: Tone;
  children: ReactNode;
}): JSX.Element {
  const mark = tone === 'success' ? '✓' : tone === 'error' ? '⚠' : 'ℹ';
  return (
    <p
      className={`message ${tone}`}
      role={tone === 'error' ? 'alert' : 'status'}
      {...(tone === 'error' ? {} : { 'aria-live': 'polite' as const })}
    >
      <span className="message-mark" aria-hidden="true">
        {mark}
      </span>
      <span className="message-body">{children}</span>
    </p>
  );
}

/** A state, as a word first and a colour second. */
export function Badge({
  tone = 'neutral',
  children,
}: {
  tone?: 'neutral' | 'ok' | 'warn' | 'bad' | 'accent';
  children: ReactNode;
}): JSX.Element {
  return <span className={tone === 'neutral' ? 'badge' : `badge ${tone}`}>{children}</span>;
}

/** Nothing to show, and — when there is one — what to do about it. */
export function EmptyState({
  title,
  body,
  action,
}: {
  title: string;
  body?: ReactNode;
  action?: ReactNode;
}): JSX.Element {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {body !== undefined && <p>{body}</p>}
      {action}
    </div>
  );
}

/**
 * The shape of what is arriving.
 *
 * The grey lines are `aria-hidden` and the sentence beside them is the live
 * region: an assistive technology should hear "Reading the directory" and not
 * a count of rectangles.
 *
 * `aria-live` without `role="status"`, deliberately. A polite live region is
 * what this needs; the *role* is a widget an automated reader can search for,
 * and the browser sweep asks "is there a status on this screen, and what does
 * it say" to tell a saved change from a refused one. A skeleton that answered
 * that question would be a second status beside the one the screen meant.
 */
export function Skeleton({ rows = 3, label }: { rows?: number; label: string }): JSX.Element {
  return (
    <div className="stack">
      <p className="muted" aria-live="polite">
        {label}
      </p>
      <div className="skeleton" aria-hidden="true">
        {Array.from({ length: rows }, (_, index) => (
          <div className="skeleton-line" key={index} />
        ))}
      </div>
    </div>
  );
}

/** A read that did not answer, and the way to ask again. */
export function LoadFailure({
  message,
  onRetry,
  retryLabel = 'Try again',
}: {
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
}): JSX.Element {
  return (
    <div className="stack">
      <Message tone="error">{message}</Message>
      {onRetry !== undefined && (
        <Actions>
          <Button onClick={onRetry}>{retryLabel}</Button>
        </Actions>
      )}
    </div>
  );
}

/* ---- tables ------------------------------------------------------------ */

/** One column of a {@link DataTable}. */
export interface Column<Row> {
  /** The column's own name, used as its sort key. */
  readonly key: string;
  /** What the header says. Empty for a column of controls. */
  readonly header: string;
  /** The cell. */
  readonly cell: (row: Row) => ReactNode;
  /** What this column sorts by, when it sorts at all. */
  readonly sortBy?: (row: Row) => string | number;
  /** A column of numbers is set right and tabular. */
  readonly numeric?: boolean;
  /** A column of controls: right-aligned, and its header is for readers only. */
  readonly actions?: boolean;
}

/** Which way a sorted column is sorted. */
type Direction = 'ascending' | 'descending';

/**
 * A table with one sort.
 *
 * The sort is *client-side and shallow*, and that is the whole of it: it
 * reorders the page the server already sent, and never re-reads. A console
 * that sorted by asking the server would be changing an API call, which this
 * migration does not do — and a directory of 20 rows an operator can see is
 * not a place where the difference matters. Where a screen paginates, the
 * caller says so in its own text.
 *
 * `aria-sort` on the header is what a screen reader announces; the arrow is
 * decorative and hidden.
 */
export function DataTable<Row>({
  caption,
  columns,
  rows,
  rowKey,
  empty,
}: {
  caption?: string;
  columns: readonly Column<Row>[];
  rows: readonly Row[];
  rowKey: (row: Row) => string;
  empty?: ReactNode;
}): JSX.Element {
  const [sort, setSort] = useState<{ key: string; direction: Direction } | null>(null);

  if (rows.length === 0 && empty !== undefined) {
    return <>{empty}</>;
  }

  const sorted = (() => {
    if (sort === null) {
      return rows;
    }
    const column = columns.find((candidate) => candidate.key === sort.key);
    const by = column?.sortBy;
    if (by === undefined) {
      return rows;
    }
    const factor = sort.direction === 'ascending' ? 1 : -1;
    return [...rows].sort((left, right) => {
      const a = by(left);
      const b = by(right);
      if (a === b) {
        return 0;
      }
      return (a < b ? -1 : 1) * factor;
    });
  })();

  return (
    <div className="table-wrap">
      <table>
        {caption !== undefined && <caption>{caption}</caption>}
        <thead>
          <tr>
            {columns.map((column) => {
              const sortable = column.sortBy !== undefined;
              const active = sort?.key === column.key ? sort.direction : undefined;
              return (
                <th
                  key={column.key}
                  scope="col"
                  className={column.numeric === true ? 'numeric' : undefined}
                  {...(active === undefined ? {} : { 'aria-sort': active })}
                >
                  {column.actions === true ? (
                    <span className="visually-hidden">
                      {column.header === '' ? 'Actions' : column.header}
                    </span>
                  ) : sortable ? (
                    <button
                      type="button"
                      className="sort"
                      onClick={() =>
                        setSort((current) =>
                          current?.key === column.key && current.direction === 'ascending'
                            ? { key: column.key, direction: 'descending' }
                            : { key: column.key, direction: 'ascending' },
                        )
                      }
                    >
                      {column.header}
                      <span className="arrow" aria-hidden="true">
                        {active === 'ascending' ? '▲' : active === 'descending' ? '▼' : '⇅'}
                      </span>
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => (
            <tr key={rowKey(row)}>
              {columns.map((column) => (
                <td
                  key={column.key}
                  className={
                    column.actions === true
                      ? 'actions-cell'
                      : column.numeric === true
                        ? 'numeric'
                        : undefined
                  }
                >
                  {column.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---- dialogs ----------------------------------------------------------- */

/**
 * The question asked before something irreversible.
 *
 * It replaces `window.confirm`, which the screens used because "a modal of our
 * own is a focus trap to get right for no benefit an administrator would
 * name". The benefit turned out to be nameable: a native confirm cannot say
 * *what* is about to happen in more than one unstyled line, cannot be read in
 * the console's own voice, and is drawn by the browser in a place the page
 * does not control. So the focus trap is got right, once, here:
 *
 *  - `role="dialog"` with `aria-modal="true"`, labelled by its heading and
 *    described by its sentence;
 *  - focus moves to the cancelling control when it opens — the safe one, so
 *    that a stray Return does nothing;
 *  - Tab and Shift+Tab cycle inside it and cannot leave;
 *  - Escape cancels;
 *  - focus returns to whatever opened it when it closes, which is what stops a
 *    keyboard user being dropped at the top of the document.
 *
 * A click on the scrim cancels too, and that is deliberate for a *confirmation*:
 * the accidental gesture lands on the harmless answer.
 */
export function ConfirmDialog({
  title,
  body,
  confirmLabel,
  cancelLabel = 'Cancel',
  busy = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}): JSX.Element {
  const surface = useRef<HTMLDivElement | null>(null);
  const cancel = useRef<HTMLButtonElement | null>(null);
  const headingId = useId();
  const bodyId = `${headingId}-body`;

  useEffect(() => {
    const opener = document.activeElement;
    cancel.current?.focus();
    return () => {
      if (opener instanceof HTMLElement && opener.isConnected) {
        opener.focus();
      }
    };
  }, []);

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onCancel();
        return;
      }
      if (event.key !== 'Tab') {
        return;
      }
      const focusable = surface.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (focusable === undefined || focusable.length === 0) {
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (first === undefined || last === undefined) {
        return;
      }
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [onCancel],
  );

  return (
    // The scrim is not a control and carries no role: the dialog inside it is
    // what an assistive technology sees. A pointer gesture on it cancels, and
    // a keyboard user reaches the same answer through the cancelling button,
    // which is where the focus already is.
    <div
      className="scrim"
      onKeyDown={onKeyDown}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onCancel();
        }
      }}
    >
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        aria-describedby={bodyId}
        ref={surface}
      >
        <h3 id={headingId}>{title}</h3>
        <p id={bodyId}>{body}</p>
        <Actions end>
          <Button ref={cancel} onClick={onCancel} disabled={busy}>
            {cancelLabel}
          </Button>
          <Button variant="danger" onClick={onConfirm} disabled={busy}>
            {confirmLabel}
          </Button>
        </Actions>
      </div>
    </div>
  );
}
