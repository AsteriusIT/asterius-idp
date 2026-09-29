export interface AssuranceLevel {
  readonly value: string;
  readonly amr: readonly string[];
}

export interface AssurancePolicy {
  readonly amr_in_id_token: boolean;
  readonly levels: readonly AssuranceLevel[];
}

/** Move one rung of the assurance ladder without mutating the policy response. */
export function moveAssuranceLevel(
  levels: readonly AssuranceLevel[],
  from: number,
  to: number,
): readonly AssuranceLevel[] {
  if (from === to || from < 0 || to < 0 || from >= levels.length || to >= levels.length) {
    return levels;
  }
  const reordered = [...levels];
  const [moved] = reordered.splice(from, 1);
  if (moved === undefined) return levels;
  reordered.splice(to, 0, moved);
  return reordered;
}

/** Add a password + TOTP context without replacing a tenant's custom contexts. */
export function enableAuthenticator(policy: AssurancePolicy): AssurancePolicy {
  if (policy.levels.some(level => level.amr.includes('otp')) || policy.levels.length >= 32) return policy;
  const base = 'urn:asterius:acr:pwd-otp';
  let value = base;
  let suffix = 2;
  while (policy.levels.some(level => level.value === value)) value = `${base}-${suffix++}`;
  const levels = [...policy.levels];
  // Keep password + code below the tenant's passkey levels by default.
  const firstPasskey = levels.findIndex(level => level.amr.includes('swk'));
  levels.splice(firstPasskey < 0 ? levels.length : firstPasskey, 0, { value, amr: ['pwd', 'otp'] });
  return { ...policy, levels };
}
