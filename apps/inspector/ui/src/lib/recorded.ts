import { useMutation } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { HistoryEntry, HistoryKind } from '@/lib/history';

/** What every pane needs to take part in history and replay. */
export interface RecordedPaneProps {
  targetId: string;
  connected: boolean;
  onRecord: (entry: Omit<HistoryEntry, 'seq'>) => void;
  /** An entry the user asked to load back into this pane, or null. */
  replay: HistoryEntry | null;
  /** Called once the pane has taken it, so it is not applied twice. */
  onReplayed: () => void;
}

/**
 * An operation that records itself.
 *
 * Every pane was doing the same four things around a call — time it, keep the
 * result, keep the error, and forget both on the next call. Three copies of
 * that is three chances for the history to disagree with the pane it came
 * from, so the timing and the recording happen in one place and the pane
 * supplies only what it is asking for.
 */
export function useRecordedOp<T = unknown>({
  targetId,
  op,
  kind,
  onRecord,
}: {
  targetId: string;
  /** The engine op name, e.g. `tools.call`. */
  op: string;
  kind: HistoryKind;
  onRecord: RecordedPaneProps['onRecord'];
}) {
  return useMutation({
    mutationFn: async ({ subject, params }: { subject: string; params: unknown }) => {
      const started = Date.now();
      try {
        const body = await api.op<{ result: T }>(targetId, op, params);
        onRecord({
          kind,
          targetId,
          subject,
          args: params,
          at: started,
          tookMs: Date.now() - started,
          ok: true,
          result: body.result,
        });
        return body;
      } catch (e) {
        // A failure is the more interesting half of a history, so it is
        // recorded on the way past rather than only surfaced in the pane.
        onRecord({
          kind,
          targetId,
          subject,
          args: params,
          at: started,
          tookMs: Date.now() - started,
          ok: false,
          error: (e as Error).message,
        });
        throw e;
      }
    },
  });
}
