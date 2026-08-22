import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type Tool } from '@/lib/api';
import { SchemaForm } from '@/components/SchemaForm';
import { ResultView } from '@/components/ResultView';
import { AppPreview } from '@/components/AppPreview';
import type { Schema } from '@/lib/schema';
import { type RecordedPaneProps, useRecordedOp } from '@/lib/recorded';

/**
 * Tools: what the server advertises, and a call form built from the schema
 * it advertised them with.
 *
 * Arguments are held as a typed value model rather than as text — the form
 * never re-escapes a string on every keystroke, which is the failure mode
 * behind the official inspector's largest open bug cluster — and the
 * declared type is what decides how each value is serialized, so an integer
 * field sends 3 and not "3".
 */
export function ToolsPane({
  targetId,
  connected,
  onRecord,
  replay,
  onReplayed,
}: RecordedPaneProps) {
  const [selected, setSelected] = useState<string | null>(null);
  const [args, setArgs] = useState<Record<string, unknown>>({});

  // "Load into tools" from the history pane: the old call's tool and its
  // arguments, put back where they were sent from — not re-sent, because
  // re-running silently is how you lose the difference you were chasing.
  useEffect(() => {
    if (replay?.kind !== 'tools.call') return;
    const params = (replay.args ?? {}) as { name?: string; arguments?: unknown };
    if (typeof params.name === 'string') setSelected(params.name);
    setArgs((params.arguments ?? {}) as Record<string, unknown>);
    onReplayed();
  }, [replay, onReplayed]);

  const tools = useQuery({
    queryKey: ['tools', targetId],
    enabled: connected,
    queryFn: () => api.op<{ tools: Tool[] }>(targetId, 'tools.list'),
  });

  const call = useRecordedOp({
    targetId,
    op: 'tools.call',
    kind: 'tools.call',
    onRecord,
  });

  if (!connected) {
    return <Empty>Connect the target to list its tools.</Empty>;
  }
  if (tools.isLoading) return <Empty>Loading tools…</Empty>;
  if (tools.error) return <Empty>{(tools.error as Error).message}</Empty>;

  const list = tools.data?.tools ?? [];
  const tool = list.find((t) => t.name === selected);

  return (
    <section className="flex min-h-0 flex-1 flex-col" data-testid="tools-pane">
      <header className="border-b border-border px-4 py-2">
        <h2 className="text-sm font-semibold">
          Tools <span className="text-muted-foreground">({list.length})</span>
        </h2>
      </header>
      <div className="flex min-h-0 flex-1">
        <ul className="w-1/3 min-w-48 overflow-auto border-r border-border" data-testid="tool-list">
          {list.map((t) => (
            <li key={t.name}>
              <button
                className={`w-full px-3 py-2 text-left text-xs hover:bg-accent ${
                  t.name === selected ? 'bg-accent' : ''
                }`}
                onClick={() => {
                  // Choosing another tool clears the arguments; the form
                  // itself no longer does, so that a replay can seed it.
                  if (t.name !== selected) setArgs({});
                  setSelected(t.name);
                  call.reset();
                }}
                data-testid="tool-item"
              >
                <div className="font-medium">{t.title ?? t.name}</div>
                {t.description && (
                  <div className="line-clamp-2 text-muted-foreground">{t.description}</div>
                )}
              </button>
            </li>
          ))}
          {list.length === 0 && (
            <li className="px-3 py-2 text-xs text-muted-foreground">
              No tools visible to this identity.
            </li>
          )}
        </ul>
        <div className="min-h-0 min-w-0 flex-1 overflow-auto p-3 text-xs">
          {!tool && <p className="text-muted-foreground">Select a tool.</p>}
          {tool && (
            <div className="space-y-3">
              {/* The action sits with the name, not after the fields. A form
                  built from a schema can be a screen and a half long, and a
                  primary action below the fold is one you go looking for. */}
              <div className="sticky top-0 z-10 flex items-start gap-3 bg-background pb-2">
                <div className="min-w-0 flex-1">
                  <div className="font-mono font-medium">{tool.name}</div>
                  {tool.description && (
                    <p className="text-muted-foreground">{tool.description}</p>
                  )}
                </div>
                <button
                  className="rounded bg-primary px-3 py-1 text-primary-foreground disabled:opacity-50"
                  disabled={call.isPending}
                  onClick={() =>
                    call.mutate({
                      subject: tool.name,
                      params: { name: tool.name, arguments: args },
                    })
                  }
                  data-testid="tool-call"
                >
                  {call.isPending ? 'calling…' : 'Call'}
                </button>
              </div>

              {/* A tool that ships an app: shown before the form, because it
                  is often the point of the tool rather than a footnote. */}
              <AppPreview targetId={targetId} tool={tool} />

              <SchemaForm
                schema={tool.inputSchema as Schema | undefined}
                value={args}
                onChange={setArgs}
                idPrefix={`${targetId}:${tool.name}`}
              />

              {/* The schemas stay reachable: a form is a reading of them, and
                  checking that reading is part of what this tool is for. */}
              <div className="flex gap-3">
                {tool.inputSchema != null && (
                  <details className="min-w-0 flex-1">
                    <summary className="cursor-pointer text-muted-foreground">
                      input schema
                    </summary>
                    <pre className="max-w-full overflow-x-auto rounded bg-muted p-2">
                      {JSON.stringify(tool.inputSchema, null, 2)}
                    </pre>
                  </details>
                )}
                {tool.outputSchema != null && (
                  <details className="min-w-0 flex-1">
                    <summary className="cursor-pointer text-muted-foreground">
                      output schema
                    </summary>
                    <pre
                      className="max-w-full overflow-x-auto rounded bg-muted p-2"
                      data-testid="tool-output-schema"
                    >
                      {JSON.stringify(tool.outputSchema, null, 2)}
                    </pre>
                  </details>
                )}
              </div>


              {call.error && <p className="text-destructive">{(call.error as Error).message}</p>}
              {call.data != null && (
                <ResultView
                  result={call.data.result}
                  outputSchema={tool.outputSchema as Schema | undefined}
                  testid="tool-result"
                />
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <section className="flex flex-1 items-center justify-center p-6 text-xs text-muted-foreground">
      {children}
    </section>
  );
}
