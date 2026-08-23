/**
 * The `?target=<url-encoded URL>` boot parameter: a link can open the
 * inspector pre-pointed at a server (the gateway's browser redirect
 * hands navigations here with exactly this shape).
 *
 * Read ONCE at module load and stripped from the address bar — a reload
 * must not re-add, matching how `?token=` cannot be resurrected. Only
 * the `target` key is consumed; unknown parameters are left alone.
 */
function readBootTarget(): string | null {
  try {
    const params = new URLSearchParams(window.location.search);
    const raw = params.get('target');
    if (raw === null) return null;
    params.delete('target');
    const query = params.toString();
    window.history.replaceState(
      null,
      '',
      window.location.pathname + (query ? `?${query}` : '') + window.location.hash,
    );
    const trimmed = raw.trim();
    return trimmed === '' ? null : trimmed;
  } catch {
    return null;
  }
}

export const bootTarget: string | null = readBootTarget();
