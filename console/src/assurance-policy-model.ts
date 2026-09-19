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
