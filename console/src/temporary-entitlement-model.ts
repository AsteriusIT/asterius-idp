/** Temporary privilege values use server deadlines and stable directory IDs. */
export function activationDuration(raw: string): number {
  if (!/^[1-9][0-9]?$/.test(raw) || Number(raw) > 60) {
    throw new Error('Choose a whole number of minutes from 1 to 60.');
  }
  return Number(raw) * 60;
}

export function boundedReason(raw: string): string {
  const reason = raw.trim();
  if (reason.length === 0 || new TextEncoder().encode(reason).length > 1024
      || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(reason)) {
    throw new Error('Enter a reason of at most 1,024 bytes without control characters.');
  }
  return reason;
}

export function approverUsernames(raw: string): readonly string[] {
  const usernames = raw.split('\n').map(value => value.trim()).filter(Boolean);
  if (usernames.length === 0 || usernames.length > 16 || new Set(usernames).size !== usernames.length) {
    throw new Error('Enter 1 to 16 different approver usernames, one per line.');
  }
  return usernames;
}

export function eligibilityInterval(start: string, end: string): { not_before: number; expires_at: number } {
  const from = Date.parse(start), until = Date.parse(end);
  if (!Number.isFinite(from) || !Number.isFinite(until) || until <= from) {
    throw new Error('Choose an eligibility end after its start.');
  }
  return { not_before: Math.floor(from / 1000), expires_at: Math.floor(until / 1000) };
}

export function entitlementDeadline(value: number): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value * 1000));
}
