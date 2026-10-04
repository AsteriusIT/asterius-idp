function decodePart(part: string): unknown {
  const bytes = Uint8Array.from(atob(part.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
}

/** A local inspection only; signature trust comes from the issuer. */
export function decodeJwt(token: string): { header: unknown; claims: unknown } | null {
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts.some(part => part === '')) return null;
  try { return { header: decodePart(parts[0]!), claims: decodePart(parts[1]!) }; }
  catch { return null; }
}
