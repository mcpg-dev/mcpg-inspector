import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';

/**
 * A subscription that outlives the pane showing it.
 *
 * This used to live inside the subscriptions pane, which closed the stream
 * on unmount — and a pane unmounts when you click another tab. Watching what
 * a server pushes while doing something else is the entire use case, so the
 * old arrangement cancelled the feature every time you used it. The stream
 * belongs to the target, not to whichever pane is on screen.
 */

export interface Push {
  seq: number;
  at: number;
  method: string;
  /** The resource a `resources/updated` push names, when it names one. */
  uri?: string;
  body: unknown;
}

export interface Subscription {
  watching: boolean;
  /** When the stream opened, so "how long has this been quiet" is answerable. */
  since?: number;
  uris: string[];
  lists: boolean;
  pushes: Push[];
  error?: string;
  /** Pushes that arrived while the pane was not on screen. */
  unseen: number;
}

const EMPTY: Subscription = {
  watching: false,
  uris: [],
  lists: true,
  pushes: [],
  unseen: 0,
};

/** Pushes retained. A chatty server would otherwise grow this without bound. */
const PUSH_CAP = 500;

export function useSubscription(targetId: string | undefined) {
  const [state, setState] = useState<Subscription>(EMPTY);
  const source = useRef<EventSource | null>(null);
  const seq = useRef(0);

  const stop = useCallback(() => {
    source.current?.close();
    source.current = null;
    setState((prev) => ({ ...prev, watching: false }));
  }, []);

  // Only a different TARGET ends a subscription — switching panes must not,
  // and the effect is keyed accordingly.
  useEffect(() => {
    return () => {
      source.current?.close();
      source.current = null;
    };
  }, [targetId]);

  useEffect(() => {
    setState(EMPTY);
    seq.current = 0;
  }, [targetId]);

  const start = useCallback(
    (uris: string, lists: boolean) => {
      if (!targetId) return;
      source.current?.close();
      seq.current = 0;
      const list = uris
        .split(',')
        .map((u) => u.trim())
        .filter(Boolean);
      const es = api.subscribe(targetId, uris, lists);
      es.onmessage = (event) => {
        try {
          const body = JSON.parse(event.data) as Record<string, unknown>;
          seq.current += 1;
          const method = typeof body.method === 'string' ? body.method : 'push';
          const params = (body.params ?? {}) as Record<string, unknown>;
          const uri = typeof params.uri === 'string' ? params.uri : undefined;
          setState((prev) => ({
            ...prev,
            pushes: [{ seq: seq.current, at: Date.now(), method, uri, body }, ...prev.pushes].slice(
              0,
              PUSH_CAP,
            ),
            unseen: prev.unseen + 1,
          }));
        } catch {
          /* a frame that is not JSON is not ours to render */
        }
      };
      es.onerror = () => {
        // EventSource reports a connect failure and a server close the same
        // way, so this says what it can rather than guessing which.
        setState((prev) => ({
          ...prev,
          watching: false,
          error: 'the subscription stream closed — the server may not support it',
        }));
        es.close();
        source.current = null;
      };
      source.current = es;
      setState({
        watching: true,
        since: Date.now(),
        uris: list,
        lists,
        pushes: [],
        unseen: 0,
        error: undefined,
      });
    },
    [targetId],
  );

  const clearPushes = useCallback(
    () => setState((prev) => ({ ...prev, pushes: [], unseen: 0 })),
    [],
  );
  const markSeen = useCallback(() => setState((prev) => ({ ...prev, unseen: 0 })), []);

  return { state, start, stop, clearPushes, markSeen };
}
