import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';

/**
 * An `events/stream` that outlives the pane showing it, as a subscription
 * does: the stream belongs to the target, not to the tab on screen.
 */

export interface StreamFrame {
  seq: number;
  at: number;
  /** `notifications/events/active`, `…/event`, `…/heartbeat`, `…/terminated`. */
  method: string;
  body: unknown;
}

export interface EventStream {
  open: boolean;
  name?: string;
  arguments?: unknown;
  since?: number;
  /** Newest first. */
  frames: StreamFrame[];
  error?: string;
  /** Frames that arrived while the pane was not on screen. */
  unseen: number;
}

const EMPTY: EventStream = { open: false, frames: [], unseen: 0 };

/** Frames retained. A busy event type would otherwise grow this without bound. */
const FRAME_CAP = 500;

export function useEventStream(targetId: string | undefined) {
  const [state, setState] = useState<EventStream>(EMPTY);
  const source = useRef<EventSource | null>(null);
  const seq = useRef(0);

  const stop = useCallback(() => {
    source.current?.close();
    source.current = null;
    setState((prev) => ({ ...prev, open: false }));
  }, []);

  useEffect(() => {
    setState(EMPTY);
    seq.current = 0;
    return () => {
      source.current?.close();
      source.current = null;
    };
  }, [targetId]);

  const start = useCallback(
    (name: string, args: unknown) => {
      if (!targetId) return;
      source.current?.close();
      seq.current = 0;
      const es = api.eventStream(targetId, name, args);
      es.onmessage = (event) => {
        try {
          const body = JSON.parse(event.data) as Record<string, unknown>;
          seq.current += 1;
          const method =
            typeof body.method === 'string' ? body.method : 'result' in body ? 'result' : 'frame';
          setState((prev) => ({
            ...prev,
            frames: [{ seq: seq.current, at: Date.now(), method, body }, ...prev.frames].slice(
              0,
              FRAME_CAP,
            ),
            unseen: prev.unseen + 1,
          }));
        } catch {
          /* a frame that is not JSON is not ours to render */
        }
      };
      es.onerror = () => {
        // A refused open and a stream the server ended look the same to an
        // EventSource; the frames above say which it was.
        setState((prev) => ({
          ...prev,
          open: false,
          error: prev.frames.length
            ? 'the stream closed'
            : 'the stream did not open: the server may not offer push for this type',
        }));
        es.close();
        source.current = null;
      };
      source.current = es;
      setState({
        open: true,
        name,
        arguments: args,
        since: Date.now(),
        frames: [],
        unseen: 0,
      });
    },
    [targetId],
  );

  const clear = useCallback(() => setState((prev) => ({ ...prev, frames: [], unseen: 0 })), []);
  const markSeen = useCallback(() => setState((prev) => ({ ...prev, unseen: 0 })), []);

  return { state, start, stop, clear, markSeen };
}
