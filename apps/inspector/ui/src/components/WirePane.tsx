import { useEffect, useRef, useState } from 'react';
import { api, type WireEvent } from '@/lib/api';

/**
 * The wire timeline: every frame the client sent or received, raw or
 * decoded. This is the pane the tool exists for, so it stays live —
 * frames stream in as they happen and the view follows unless the
 * operator scrolls away.
 */
export function WirePane({ targetId }: { targetId: string }) {
  const [events, setEvents] = useState<WireEvent[]>([]);
  const [decoded, setDecoded] = useState(true);
  const [filter, setFilter] = useState('');
  const [follow, setFollow] = useState(true);
  const bottom = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setEvents([]);
    const source = api.events(targetId, 0);
    source.onmessage = (message) => {
      const event = JSON.parse(message.data) as WireEvent;
      setEvents((prev) => [...prev.slice(-2000), event]);
    };
    // No hand-rolled retry. Every event carries its sequence number as the
    // SSE id, so a dropped EventSource reconnects on its own and sends
    // `Last-Event-ID`; the server resumes from exactly there. Reconnecting
    // by hand recovered the FIRST drop only — the replacement stream was
    // left with no error handler of its own.
    return () => source.close();
  }, [targetId]);

  useEffect(() => {
    if (follow) bottom.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events, follow]);

  const shown = filter
    ? events.filter((e) => e.body.toLowerCase().includes(filter.toLowerCase()))
    : events;

  return (
    <section className="flex min-h-0 flex-1 flex-col" data-testid="wire-pane">
      <header className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-2">
        <h2 className="text-sm font-semibold">Wire</h2>
        <input
          className="h-7 flex-1 rounded border border-input bg-background px-2 text-xs"
          placeholder="filter frames…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          data-testid="wire-filter"
        />
        <label className="flex items-center gap-1 text-xs">
          <input type="checkbox" checked={decoded} onChange={() => setDecoded(!decoded)} />
          decoded
        </label>
        <label className="flex items-center gap-1 text-xs">
          <input type="checkbox" checked={follow} onChange={() => setFollow(!follow)} />
          follow
        </label>
        <a
          className="text-xs underline"
          href={api.exportUrl(targetId)}
          data-testid="wire-export"
        >
          export
        </a>
        <span className="text-xs text-muted-foreground" data-testid="wire-count">
          {shown.length} frames
        </span>
      </header>
      <div className="min-h-0 flex-1 overflow-auto p-2 font-mono text-xs">
        {shown.map((event) => (
          <Frame key={event.seq} event={event} decoded={decoded} />
        ))}
        <div ref={bottom} />
      </div>
    </section>
  );
}

function Frame({ event, decoded }: { event: WireEvent; decoded: boolean }) {
  const sent = event.direction === 'sent';
  return (
    <div className="border-b border-border/50 py-1" data-testid="wire-frame">
      <div className="flex items-center gap-2">
        <span className={sent ? 'text-blue-600' : 'text-emerald-600'}>{sent ? '→' : '←'}</span>
        <span className="text-muted-foreground">{event.channel}</span>
        <span className="text-muted-foreground">
          {new Date(event.ts_ms).toISOString().slice(11, 23)}
        </span>
        <span className="text-muted-foreground">#{event.seq}</span>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all">
        {decoded ? summarize(event.body) : event.body}
      </pre>
    </div>
  );
}

/**
 * Decoded view: pretty-print JSON-RPC, and label what a frame is. An
 * SSE block is shown with its field lines intact — the point is to see
 * what the server actually framed, not a cleaned-up version.
 */
function summarize(body: string): string {
  const trimmed = body.trim();
  const payload = trimmed.startsWith('data:')
    ? trimmed
        .split('\n')
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trim())
        .join('')
    : trimmed;
  try {
    const parsed = JSON.parse(payload);
    const label =
      parsed.method && parsed.id !== undefined
        ? `request ${parsed.method} (id ${parsed.id})`
        : parsed.method
          ? `notification ${parsed.method}`
          : parsed.error
            ? `error ${parsed.error.code}`
            : `result (id ${parsed.id})`;
    return `${label}\n${JSON.stringify(parsed, null, 2)}`;
  } catch {
    return body;
  }
}
