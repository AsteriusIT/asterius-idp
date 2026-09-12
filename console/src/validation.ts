/**
 * What this console can say about a value *before* the server sees it
 * (`ast-f9j5` (2)).
 *
 * # The server is still the validator
 *
 * Every function here returns a sentence to show beside a field while it is
 * being typed, and nothing else. None of them stops a submission, none of them
 * disables a control, and none of them is consulted when a refusal arrives:
 * the server's own sentence is what `Field` shows then, because it is the one
 * that names the clause. This module exists for the round trip an operator
 * should not have to make to learn that a role name cannot carry a space —
 * not to have an opinion about what may be stored.
 *
 * That distinction is the whole reason `clients.tsx` says "this form has no
 * rules of its own", and it survives: these are not rules, they are *echoes*.
 * Each one mirrors a refusal this server already spells out, and every function
 * below names where it is written:
 *
 * | Here | Where the server decides |
 * | --- | --- |
 * | {@link roleName}, {@link roleDescription} | `asterius_domain::RoleName::parse`, `MAX_ROLE_DESCRIPTION_LEN` |
 * | {@link tenantId} | `asterius_domain::TenantId::parse` |
 * | {@link issuerUrl} | `asterius_domain::Issuer::parse` |
 * | {@link username}, {@link emailAddress} | `asterius_admin_api::users::accept_username` / `accept_email` |
 * | {@link redirectUris} | `asterius_domain::RedirectUri::parse` |
 * | {@link jsonDocument} | `JSON.parse`, which is what the screen already ran |
 *
 * A rule that drifts from its counterpart shows a sentence about a value the
 * server would have taken. That is a bad screen and not an unauthorised write,
 * which is why the trade is worth making at all — and why nothing here is
 * allowed to grow a rule the server does not have.
 *
 * # Why an empty field is never wrong here
 *
 * Every function answers `null` for the empty string. A form that turns red
 * before anything has been typed teaches an operator to ignore it, and
 * "required" is already carried by `Field`'s own mark and by the server's
 * refusal. What these catch is a value that *has* been typed and cannot work.
 */

/** A message to show at the field, or `null` when there is nothing to say. */
export type Complaint = string | null;

/** Whether `value` carries a character no console can render honestly. */
function hasControlCharacter(value: string): boolean {
  return /[\u0000-\u001f\u007f]/u.test(value);
}

/**
 * An application role name, as `RoleName::parse` admits one.
 *
 * ASCII lowercase, digits, `-`, `_`, `.` and `:`, starting with a letter or a
 * digit, at most 64 characters. Uppercase is refused rather than folded by the
 * server, so it is reported here rather than quietly accepted.
 */
export function roleName(value: string): Complaint {
  if (value === '') {
    return null;
  }
  if (value.length > 64) {
    return 'A role name is at most 64 characters.';
  }
  const bad = [...value].find((character) => !/[a-z0-9\-_.:]/.test(character));
  if (bad !== undefined) {
    return `A role name may only contain a-z, 0-9, “-”, “_”, “.” and “:” — found “${bad}”. Upper case is refused rather than lowercased.`;
  }
  if (!/^[a-z0-9]/.test(value)) {
    return 'A role name must start with a lowercase letter or a digit.';
  }
  return null;
}

/** A role's description: free text, bounded, and never a control character. */
export function roleDescription(value: string): Complaint {
  if (value === '') {
    return null;
  }
  if ([...value].length > 200) {
    return 'A description is at most 200 characters.';
  }
  if (hasControlCharacter(value)) {
    return 'A description must not carry control characters.';
  }
  return null;
}

/** A tenant id, as `TenantId::parse` admits one. */
export function tenantId(value: string): Complaint {
  if (value === '') {
    return null;
  }
  if (value.length > 64) {
    return 'A tenant id is at most 64 characters.';
  }
  const bad = [...value].find((character) => !/[a-z0-9\-_]/.test(character));
  if (bad !== undefined) {
    return `A tenant id may only contain a-z, 0-9, “-” and “_” — found “${bad}”.`;
  }
  if (!/^[a-z0-9]/.test(value)) {
    return 'A tenant id must start with a lowercase letter or a digit.';
  }
  return null;
}

/**
 * An issuer, as `Issuer::parse` admits one.
 *
 * `https`, a host, and no query, fragment or userinfo. The trailing slash the
 * server strips is not reported: it is normalised rather than refused, so a
 * complaint about it would be a rule this server does not have.
 */
export function issuerUrl(value: string): Complaint {
  if (value === '') {
    return null;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'This is not a URL.';
  }
  if (url.protocol !== 'https:') {
    return 'An issuer is an https URL.';
  }
  if (url.hostname === '') {
    return 'An issuer must name a host.';
  }
  if (url.search !== '') {
    return 'An issuer carries no query string (RFC 8414 §2).';
  }
  if (value.includes('#')) {
    return 'An issuer carries no fragment (RFC 8414 §2).';
  }
  if (url.username !== '' || url.password !== '') {
    return 'An issuer carries no user:password@ part.';
  }
  return null;
}

/** A username, as `accept_username` admits one. */
export function username(value: string): Complaint {
  const trimmed = value.trim();
  if (trimmed === '') {
    return null;
  }
  if ([...trimmed].length > 320) {
    return 'A username is at most 320 characters.';
  }
  if (hasControlCharacter(trimmed)) {
    return 'A username must not carry control characters.';
  }
  return null;
}

/**
 * An address, as `accept_email` admits one.
 *
 * Deliberately as shallow as the server's own check, and for the reason it
 * gives: an RFC 5322 address is not a thing to validate with a regular
 * expression, and the only proof an address belongs to somebody is a message
 * they answered.
 */
export function emailAddress(value: string): Complaint {
  const trimmed = value.trim();
  if (trimmed === '') {
    return null;
  }
  if (trimmed.length > 320) {
    return 'An address is at most 320 octets.';
  }
  if (/\s/.test(trimmed) || hasControlCharacter(trimmed)) {
    return 'An address carries no whitespace.';
  }
  const at = trimmed.lastIndexOf('@');
  if (at === -1) {
    return 'An address carries an @.';
  }
  const local = trimmed.slice(0, at);
  const domain = trimmed.slice(at + 1);
  if (local === '' || domain === '' || !domain.includes('.')) {
    return 'An address names a local part and a domain.';
  }
  return null;
}

/**
 * The redirect URIs box, one URI per line, as `RedirectUri::parse` admits one.
 *
 * The first line that cannot work is named by its number, because the server
 * does the same (`redirect_uris[2]: …`) and an operator with six callbacks
 * should not have to count them. The loopback exception follows
 * `application_type`, exactly as FAPI 2.0 SP §5.3.2.2 item 8 and RFC 8252 §7.3
 * make it: `http` only for a native client, and only on an IP literal.
 *
 * Byte-for-byte normalisation (RFC 3986 §6.2.2) is deliberately *not* checked
 * here. It is the one rule whose browser-side answer could differ from the
 * server's URL parser, and a console that told an operator their URI was
 * malformed when it was not is worse than one that says nothing.
 */
export function redirectUris(value: string, applicationType: string): Complaint {
  const lines = value.split('\n').map((line) => line.trim());
  for (const [index, line] of lines.entries()) {
    if (line === '') {
      continue;
    }
    const complaint = oneRedirectUri(line, applicationType);
    if (complaint !== null) {
      return `Line ${index + 1}: ${complaint}`;
    }
  }
  return null;
}

/** One entry of {@link redirectUris}. */
function oneRedirectUri(value: string, applicationType: string): Complaint {
  if (value.length > 2048) {
    return 'a redirect URI is at most 2048 bytes.';
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'this is not an absolute URI.';
  }
  if (value.includes('#')) {
    return 'a redirect URI carries no fragment (RFC 6749 §3.1.2).';
  }
  if (url.username !== '' || url.password !== '') {
    return 'a redirect URI carries no user:password@ part.';
  }
  if (url.protocol === 'https:') {
    return url.hostname === '' ? 'a redirect URI names a host.' : null;
  }
  if (url.protocol === 'http:') {
    if (applicationType !== 'native') {
      return 'http is admissible only for a loopback redirect on a native client (FAPI 2.0 SP §5.3.2.2 item 8).';
    }
    return url.hostname === '127.0.0.1' || url.hostname === '[::1]'
      ? null
      : 'http is admissible only on 127.0.0.1 or [::1]; localhost resolves through DNS (RFC 8252 §8.3).';
  }
  return 'the scheme must be https.';
}

/**
 * A box that has to hold JSON, and the position the parser names when it does
 * not.
 *
 * The same `JSON.parse` the screen was already going to run on submission —
 * this only runs it a few keystrokes earlier, and `what` is what the sentence
 * calls the box.
 */
export function jsonDocument(value: string, what: string): Complaint {
  if (value.trim() === '') {
    return null;
  }
  try {
    JSON.parse(value);
    return null;
  } catch (error: unknown) {
    return `${what} is not JSON yet: ${error instanceof Error ? error.message : 'it could not be parsed'}`;
  }
}

/** A JSON object — `{…}` and not a list or a number — for a box that needs one. */
export function jsonObject(value: string, what: string): Complaint {
  const complaint = jsonDocument(value, what);
  if (complaint !== null || value.trim() === '') {
    return complaint;
  }
  const parsed: unknown = JSON.parse(value);
  return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
    ? null
    : `${what} has to be a JSON object.`;
}
