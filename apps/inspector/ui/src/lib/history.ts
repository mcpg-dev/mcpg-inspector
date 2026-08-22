/**
 * What you have already asked this server.
 *
 * The panes are built around one call at a time: fill the form, press the
 * button, read the answer, and the answer before it is gone. That is fine
 * for the first call and wrong for the fifth, which is usually the one that
 * matters — you are comparing, not calling.
 *
 * History lives above the panes for the same reason a subscription does:
 * switching tabs is navigation, not cancellation.
 */

export type HistoryKind = 'tools.call' | 'resources.read' | 'prompts.get';

export interface HistoryEntry {
  /** Monotonic within a session; also the React key. */
  seq: number;
  kind: HistoryKind;
  targetId: string;
  /** Tool name, resource URI, or prompt name. */
  subject: string;
  /** What was sent — enough to run it again. */
  args: unknown;
  at: number;
  /** Wall-clock milliseconds the round trip took. */
  tookMs: number;
  ok: boolean;
  /** The result, or the error message. */
  result?: unknown;
  error?: string;
}

/** Entries kept. Long enough to compare a session's worth, bounded so a
 *  left-open tab does not grow without limit. */
export const HISTORY_CAP = 200;

export function record(
  entries: HistoryEntry[],
  entry: Omit<HistoryEntry, 'seq'>,
): HistoryEntry[] {
  const seq = (entries[0]?.seq ?? 0) + 1;
  // Newest first: the thing you just did is the thing you are looking for.
  return [{ ...entry, seq }, ...entries].slice(0, HISTORY_CAP);
}

/** The verb a kind reads as, for the one-line summary. */
export function verbOf(kind: HistoryKind): string {
  switch (kind) {
    case 'tools.call':
      return 'called';
    case 'resources.read':
      return 'read';
    case 'prompts.get':
      return 'rendered';
  }
}

/** Which pane an entry belongs to, for "open this again". */
export function paneOf(kind: HistoryKind): 'tools' | 'resources' | 'prompts' {
  switch (kind) {
    case 'tools.call':
      return 'tools';
    case 'resources.read':
      return 'resources';
    case 'prompts.get':
      return 'prompts';
  }
}

/** A compact rendering of the arguments, for the list row. */
export function summarize(args: unknown): string {
  if (args === undefined || args === null) return '';
  if (typeof args === 'string') return args;
  const text = JSON.stringify(args);
  return text === '{}' ? '' : text.length > 120 ? `${text.slice(0, 120)}…` : text;
}
