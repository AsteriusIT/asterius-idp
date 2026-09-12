/**
 * The console's components (`ast-fe39`, rebuilt on shadcn/ui by `ast-gore`).
 *
 * Nine screens were written one at a time, and each invented its own way of
 * saying the same six things: this is the screen you are on, this is a section
 * of it, this went wrong, this worked, this is a table, are you sure. So the
 * six things live here — and the screens that call them did not have to change
 * when what is underneath them did.
 *
 * # What changed, and why a framework is now the answer
 *
 * `ast-fe39` wrote these by hand and said why: "a UI library is a dependency
 * tree inside the most privileged page this deployment serves". That objection
 * is answered by *how* shadcn/ui ships rather than by ignoring it. It is not a
 * dependency: the components are **copied into this repository**
 * (`src/components/ui/`), reviewed like the rest of it and changed where this
 * deployment disagrees — the sidebar's cookie is gone, Sonner is gone. What
 * remains under them is Radix, which is behaviour and not paint: the focus
 * traps, the roving tab indexes, the `aria-*` wiring and the dismiss semantics
 * that `ConfirmDialog` had to get right by hand once and that every subsequent
 * dialog would have had to get right again.
 *
 * The paint is still ours. Every colour in `tailwind.css` is a `var(--token)`
 * from `tokens.css`, which is a checked copy of the user-facing pages'
 * `:root` — so the console still looks like the product and the Rust test
 * `the_console_declares_the_same_design_tokens` still fails if it stops.
 *
 * # What is still true
 *
 * Nothing in this file talks to the network; a component takes what to draw
 * and gives back what was pressed. The admin API calls, their scopes and their
 * refusals are exactly where they were.
 */
import { useCallback, useId, useMemo, useState } from 'react';
import type { JSX, ReactNode } from 'react';
import { ArrowDownIcon, ArrowUpIcon, ChevronsUpDownIcon, SearchIcon } from 'lucide-react';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Badge as ShadBadge } from '@/components/ui/badge';
import { Button as ShadButton } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardHeader } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton as ShadSkeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { cn } from '@/lib/utils';

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
 * One section of a screen, drawn as a shadcn `Card`.
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
    <Card asChild>
      <section aria-labelledby={headingId}>
        <CardHeader>
          <div className="panel-title">
            <h3 id={headingId}>{title}</h3>
            {description !== undefined && <p className="muted">{description}</p>}
          </div>
          {/* A row with a gap: a panel's actions are a *set* of controls, and
              `CardAction` is one grid cell, so two buttons dropped into it sat
              edge to edge (`ast-f9j5`). */}
          {actions !== undefined && (
            <CardAction className="flex flex-wrap items-center gap-2">{actions}</CardAction>
          )}
        </CardHeader>
        <CardContent className="flex flex-col gap-3">{children}</CardContent>
      </section>
    </Card>
  );
}

/** The pages' centred card, for the three views that are one sentence. */
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

/** Which of the four things a control does. */
export type Variant = 'primary' | 'secondary' | 'danger' | 'ghost';

/**
 * A button.
 *
 * `primary` is spent once per view — direction A's rule, and the reason the
 * default is `secondary`: a screen where everything is emphasised has
 * emphasised nothing. `danger` is deliberately *not* the filled destructive
 * button: a destructive act is confirmed rather than shouted at, and the
 * dialog is where the weight is. The one filled red control in this console is
 * the confirm inside `ConfirmDialog`.
 */
export function Button({
  variant = 'secondary',
  small = false,
  type = 'button',
  className,
  children,
  ...rest
}: {
  variant?: Variant;
  small?: boolean;
  // React 19 passes `ref` as an ordinary prop to a function component, so the
  // dialog can hold one without `forwardRef` in the tree.
} & React.ComponentProps<'button'>): JSX.Element {
  const mapped = variant === 'primary' ? 'default' : variant === 'ghost' ? 'ghost' : 'outline';
  return (
    <ShadButton
      type={type}
      variant={mapped}
      size={small ? 'sm' : 'default'}
      className={cn(
        variant === 'danger' &&
          'border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive',
        className,
      )}
      {...rest}
    >
      {children}
    </ShadButton>
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
 * It stays even though `ast-gore` added toasts, and the division is this: the
 * toast is the *announcement* and this is the *record*. An outcome that scrolls
 * away after six seconds is not where a refusal an operator has to act on
 * belongs.
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
  return (
    <ShadBadge
      variant="outline"
      className={cn(
        'font-medium',
        tone === 'ok' && 'border-success/40 bg-success/10 text-success',
        tone === 'warn' && 'border-warning/40 bg-warning/10 text-warning',
        tone === 'bad' && 'border-destructive/40 bg-destructive/10 text-destructive',
        tone === 'accent' && 'border-primary/40 bg-primary/10 text-primary',
      )}
    >
      {children}
    </ShadBadge>
  );
}

/**
 * A long single-token value that must not decide how wide its column is
 * (`ast-f9j5`).
 *
 * An issuer, a `client_id` or an address made of a UUID has no space to break
 * at, so one row of them widened the table past the card it sits in and the
 * columns after it — a status, a control — went off the edge. The value is
 * clipped with an ellipsis at a width given in characters, and the whole of it
 * stays available: in the `title`, which is also what a pointer shows, and by
 * selecting the cell, since the text is all there in the DOM.
 *
 * Not a substitute for the horizontal scroll `DataTable` still has. It is what
 * keeps the scroll from being needed for the common row.
 */
export function Truncate({
  text,
  // A Tailwind class and not a `style` attribute: this console writes no
  // inline style into its markup, and a Rust test asserts it of the built
  // bundle. `max-width` on the inner block is what bounds the *column* — a
  // table laid out automatically asks its cells how wide they want to be, and
  // this is the answer. The caller passes a literal so Tailwind can see it.
  className = 'max-w-[24ch]',
}: {
  text: string;
  className?: string;
}): JSX.Element {
  return (
    <span className={cn('block truncate', className)} title={text}>
      {text}
    </span>
  );
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
    <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed px-6 py-10 text-center">
      <strong className="text-sm font-semibold">{title}</strong>
      {body !== undefined && <p className="max-w-prose text-sm text-muted-foreground">{body}</p>}
      {action !== undefined && <div className="pt-1">{action}</div>}
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
      <div className="flex flex-col gap-2" aria-hidden="true">
        {Array.from({ length: rows }, (_, index) => (
          <ShadSkeleton className="h-4 w-full" key={index} />
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
 * How a caller lets a table be searched (`ast-gore` (5)).
 *
 * Client-side and over the page already on screen, exactly like the sort: it
 * filters what the server sent and never re-reads. A screen that paginates
 * still paginates, and the count beside the box says which of the two numbers
 * an operator is looking at — "3 of 20 shown" is the difference between
 * "nothing here" and "nothing here *matching*", which is the failure a filter
 * without a count causes.
 */
export interface Search<Row> {
  /** The text this row is searched by. */
  readonly of: (row: Row) => string;
  /** What the box says when it is empty. */
  readonly placeholder?: string;
  /** The label of the box, for a reader. */
  readonly label?: string;
}

/**
 * A table with one sort and, when the caller asks for one, one filter.
 *
 * The sort is *client-side and shallow*: it reorders the page the server
 * already sent, and never re-reads. A console that sorted by asking the server
 * would be changing an API call, which this work does not do.
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
  search,
}: {
  caption?: string;
  columns: readonly Column<Row>[];
  rows: readonly Row[];
  rowKey: (row: Row) => string;
  empty?: ReactNode;
  search?: Search<Row>;
}): JSX.Element {
  const [sort, setSort] = useState<{ key: string; direction: Direction } | null>(null);
  const [query, setQuery] = useState('');
  const searchId = useId();

  const matched = useMemo(() => {
    if (search === undefined || query.trim() === '') {
      return rows;
    }
    const needle = query.trim().toLowerCase();
    return rows.filter((row) => search.of(row).toLowerCase().includes(needle));
  }, [rows, query, search]);

  const sorted = useMemo(() => {
    if (sort === null) {
      return matched;
    }
    const column = columns.find((candidate) => candidate.key === sort.key);
    const by = column?.sortBy;
    if (by === undefined) {
      return matched;
    }
    const factor = sort.direction === 'ascending' ? 1 : -1;
    return [...matched].sort((left, right) => {
      const a = by(left);
      const b = by(right);
      if (a === b) {
        return 0;
      }
      return (a < b ? -1 : 1) * factor;
    });
  }, [matched, sort, columns]);

  // The empty state belongs to the *screen* — it says what to do about there
  // being nothing — so it replaces the table only when the server sent
  // nothing. A filter that matched nothing is a different sentence, below.
  if (rows.length === 0 && empty !== undefined) {
    return <>{empty}</>;
  }

  const box =
    search === undefined ? null : (
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <div className="relative max-w-xs flex-1">
          <SearchIcon
            className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            id={searchId}
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={search.placeholder ?? 'Filter…'}
            aria-label={search.label ?? 'Filter the rows below'}
            className="pl-8"
          />
        </div>
        {query.trim() !== '' && (
          <p className="text-sm text-muted-foreground" aria-live="polite">
            {matched.length} of {rows.length} shown
          </p>
        )}
      </div>
    );

  return (
    <div>
      {box}
      {sorted.length === 0 ? (
        <EmptyState
          title="No row matches that filter"
          body={`Nothing in these ${rows.length} rows contains “${query.trim()}”.`}
          action={
            <Button small onClick={() => setQuery('')}>
              Clear the filter
            </Button>
          }
        />
      ) : (
        <div className="table-wrap">
          <Table>
            {caption !== undefined && <TableCaption>{caption}</TableCaption>}
            <TableHeader>
              <TableRow>
                {columns.map((column) => {
                  const sortable = column.sortBy !== undefined;
                  const active = sort?.key === column.key ? sort.direction : undefined;
                  return (
                    <TableHead
                      key={column.key}
                      scope="col"
                      className={cn(
                        column.numeric === true && 'text-right tabular-nums',
                        column.actions === true && 'text-right',
                      )}
                      {...(active === undefined ? {} : { 'aria-sort': active })}
                    >
                      {column.actions === true ? (
                        <span className="sr-only">
                          {column.header === '' ? 'Actions' : column.header}
                        </span>
                      ) : sortable ? (
                        <button
                          type="button"
                          className="inline-flex items-center gap-1 rounded-sm font-medium hover:text-foreground"
                          onClick={() =>
                            setSort((current) =>
                              current?.key === column.key && current.direction === 'ascending'
                                ? { key: column.key, direction: 'descending' }
                                : { key: column.key, direction: 'ascending' },
                            )
                          }
                        >
                          {column.header}
                          <span aria-hidden="true">
                            {active === 'ascending' ? (
                              <ArrowUpIcon className="size-3.5" />
                            ) : active === 'descending' ? (
                              <ArrowDownIcon className="size-3.5" />
                            ) : (
                              <ChevronsUpDownIcon className="size-3.5 opacity-50" />
                            )}
                          </span>
                        </button>
                      ) : (
                        column.header
                      )}
                    </TableHead>
                  );
                })}
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted.map((row) => (
                <TableRow key={rowKey(row)}>
                  {columns.map((column) => (
                    <TableCell
                      key={column.key}
                      className={cn(
                        column.numeric === true && 'text-right tabular-nums',
                        column.actions === true && 'actions-cell text-right',
                      )}
                    >
                      {column.cell(row)}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}

/* ---- dialogs ----------------------------------------------------------- */

/**
 * The question asked before something irreversible.
 *
 * It replaced `window.confirm` in `ast-fe39` and was a hand-written focus trap
 * until `ast-gore`; it is now Radix's `AlertDialog`, which is the same
 * behaviour with one difference worth naming: `role="alertdialog"` rather than
 * `role="dialog"`. That is the correct role for a modal that interrupts to ask
 * a question, and an assistive technology announces its description
 * immediately rather than waiting to be asked.
 *
 * Everything the hand-written one guaranteed still holds, and Radix is what
 * guarantees it: focus moves into the dialog and to the *cancelling* control
 * when it opens, so a stray Return does nothing; Tab cycles inside; Escape
 * cancels; focus returns to whatever opened it. A click on the scrim cancels,
 * which is deliberate for a *confirmation* — the accidental gesture lands on
 * the harmless answer.
 *
 * The component is still mounted only while the question is being asked, so
 * every caller is unchanged.
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
  const dismiss = useCallback(
    (open: boolean) => {
      if (!open) {
        onCancel();
      }
    },
    [onCancel],
  );

  return (
    <AlertDialog open onOpenChange={dismiss}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{body}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>{cancelLabel}</AlertDialogCancel>
          {/* `asChild` so the confirm is an ordinary button this screen owns:
              the act runs on click and the dialog is unmounted by the caller
              when the call settles, rather than closing before it has. */}
          <AlertDialogAction asChild>
            <ShadButton variant="destructive" disabled={busy} onClick={onConfirm}>
              {confirmLabel}
            </ShadButton>
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
