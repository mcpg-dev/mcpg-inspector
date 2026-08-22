import { useState } from 'react';
import { Empty } from '@/components/EntityPane';
import { ResultView } from '@/components/ResultView';
import { type HistoryEntry, paneOf, summarize, verbOf } from '@/lib/history';

/**
 * Everything asked of this server, and what came back.
 *
 * The value is comparison: two calls that differ in one argument, and the
 * question of which of them returned the thing you wanted. So the list keeps
 * both, the detail shows one, and "run it again" puts the old arguments back
 * in the pane that sent them rather than re-sending behind your back —
 * re-running silently is how you lose the difference you were chasing.
 */
export function HistoryPane({
  entries,
  onReplay,
  onClear,
}: {
  entries: HistoryEntry[];
  onReplay: (entry: HistoryEntry) => void;
  onClear: () => void;
}) {
  const [selected, setSelected] = useState<number | null>(null);
  const entry = entries.find((e) => e.seq === selected) ?? entries[0];

  if (entries.length === 0) {
    return (
      <Empty>
        Nothing called yet. Every tool call, resource read and prompt render lands here —
        with what was sent, what came back, and how long it took.
      </Empty>
    );
  }

  return (
    <section className="flex min-h-0 flex-1 flex-col" data-testid="history-pane">
      <header className="flex items-center gap-3 border-b border-border px-4 py-2">
        <h2 className="text-sm font-semibold">
          History <span className="text-muted-foreground">({entries.length})</span>
        </h2>
        <button
          className="ml-auto rounded border border-input px-2 py-0.5 text-xs"
          onClick={onClear}
          data-testid="history-clear"
        >
          clear
        </button>
      </header>
      <div className="flex min-h-0 flex-1">
        <ul
          className="w-2/5 min-w-64 overflow-auto border-r border-border"
          data-testid="history-list"
        >
          {entries.map((item) => (
            <li key={item.seq}>
              <button
                className={`w-full px-3 py-2 text-left text-xs hover:bg-accent ${
                  item.seq === entry?.seq ? 'bg-accent' : ''
                }`}
                onClick={() => setSelected(item.seq)}
                data-testid="history-item"
                data-ok={item.ok}
              >
                <div className="flex items-baseline gap-1.5">
                  <span
                    className={`size-1.5 shrink-0 rounded-full ${
                      item.ok ? 'bg-emerald-500' : 'bg-destructive'
                    }`}
                    title={item.ok ? 'ok' : 'failed'}
                  />
                  <span className="font-medium">{verbOf(item.kind)}</span>
                  <span className="min-w-0 flex-1 truncate font-mono">{item.subject}</span>
                  <span className="text-muted-foreground">{item.tookMs}ms</span>
                </div>
                {summarize(item.args) && (
                  <div className="truncate pl-3 font-mono text-muted-foreground">
                    {summarize(item.args)}
                  </div>
                )}
                <div className="pl-3 text-muted-foreground">
                  {new Date(item.at).toLocaleTimeString()}
                </div>
              </button>
            </li>
          ))}
        </ul>
        <div className="min-h-0 min-w-0 flex-1 overflow-auto p-3 text-xs">
          {entry && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-medium">{verbOf(entry.kind)}</span>
                <span className="font-mono">{entry.subject}</span>
                <span className="text-muted-foreground">
                  {new Date(entry.at).toLocaleString()} · {entry.tookMs}ms
                </span>
                <button
                  className="ml-auto rounded bg-primary px-2 py-0.5 text-primary-foreground"
                  onClick={() => onReplay(entry)}
                  data-testid="history-replay"
                >
                  load into {paneOf(entry.kind)}
                </button>
              </div>
              <div>
                <p className="mb-1 text-muted-foreground">sent</p>
                <pre className="max-w-full overflow-x-auto rounded bg-muted p-2">
                  {JSON.stringify(entry.args ?? {}, null, 2)}
                </pre>
              </div>
              {entry.ok ? (
                <ResultView result={entry.result} testid="history-result" />
              ) : (
                <div>
                  <p className="mb-1 text-muted-foreground">failed</p>
                  <p className="text-destructive" data-testid="history-error">
                    {entry.error}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
