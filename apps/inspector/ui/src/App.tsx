import { useCallback, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { ToolsPane } from '@/components/ToolsPane';
import { ResourcesPane } from '@/components/ResourcesPane';
import { PromptsPane } from '@/components/PromptsPane';
import { SubscriptionsPane } from '@/components/SubscriptionsPane';
import { HistoryPane } from '@/components/HistoryPane';
import { DiagnosePane } from '@/components/DiagnosePane';
import { WirePane } from '@/components/WirePane';
import { PendingRequests } from '@/components/PendingRequests';
import { TargetPicker } from '@/components/TargetPicker';
import { type HistoryEntry, paneOf, record } from '@/lib/history';
import { useSubscription } from '@/lib/subscriptions';

type Pane =
  | 'tools'
  | 'resources'
  | 'prompts'
  | 'subscriptions'
  | 'history'
  | 'diagnose'
  | 'wire';

const PANES: Pane[] = [
  'tools',
  'resources',
  'prompts',
  'subscriptions',
  'history',
  'diagnose',
  'wire',
];

export function App() {
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [pane, setPane] = useState<Pane>('tools');

  const meta = useQuery({ queryKey: ['meta'], queryFn: api.meta });
  const targets = useQuery({ queryKey: ['targets'], queryFn: api.targets });

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['targets'] });
    queryClient.invalidateQueries({ queryKey: ['tools'] });
  };

  const connect = useMutation({ mutationFn: api.connect, onSuccess: refresh });
  const disconnect = useMutation({ mutationFn: api.disconnect, onSuccess: refresh });
  const addTarget = useMutation({
    mutationFn: (url: string) => api.addTarget({ url }),
    onSuccess: refresh,
  });

  const list = targets.data?.targets ?? [];
  const selected = list.find((t) => t.id === selectedId) ?? list[0];

  // Both of these live here rather than in a pane, because a pane unmounts
  // when you click another tab, and neither a held-open stream nor a record
  // of what you have done should end because you looked at something else.
  const subscription = useSubscription(selected?.id);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [replay, setReplay] = useState<HistoryEntry | null>(null);

  const remember = useCallback((entry: Omit<HistoryEntry, 'seq'>) => {
    setHistory((prev) => record(prev, entry));
  }, []);

  const openAgain = (entry: HistoryEntry) => {
    setReplay(entry);
    setPane(paneOf(entry.kind));
  };

  const paneProps = {
    targetId: selected?.id ?? '',
    connected: selected?.session.state === 'ready',
    onRecord: remember,
    replay,
    onReplayed: () => setReplay(null),
  };

  return (
    <div className="flex h-screen flex-col bg-background text-foreground">
      <header className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-2">
        <h1 className="text-sm font-semibold">MCPG Inspector</h1>

        <TargetPicker
          targets={list}
          selected={selected}
          onSelect={setSelectedId}
          onAdd={(url) => addTarget.mutate(url)}
          addError={addTarget.error ? (addTarget.error as Error).message : undefined}
          busy={addTarget.isPending}
        />

        {selected &&
          (selected.session.state === 'ready' ? (
            <button
              className="rounded border border-input px-2 py-0.5 text-xs"
              onClick={() => disconnect.mutate(selected.id)}
              data-testid="disconnect"
            >
              disconnect
            </button>
          ) : (
            <button
              className="rounded bg-primary px-2 py-0.5 text-xs text-primary-foreground"
              onClick={() => connect.mutate(selected.id)}
              disabled={connect.isPending}
              data-testid="connect"
            >
              {connect.isPending ? 'connecting…' : 'connect'}
            </button>
          ))}
        {selected?.session.state === 'ready' && (
          <span
            className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] text-emerald-700"
            data-testid="state-badge"
          >
            {selected.session.negotiated_version}
          </span>
        )}
        {selected?.session.state === 'failed' && (
          <span
            className="rounded bg-destructive/15 px-1.5 py-0.5 text-[10px] text-destructive"
            title={selected.session.message}
            data-testid="state-badge"
          >
            failed
          </span>
        )}

        {meta.data && (
          <span className="ml-auto text-xs text-muted-foreground" data-testid="meta">
            v{meta.data.version} · {meta.data.mode} · auth {meta.data.authMode}
          </span>
        )}
        {meta.error && (
          <span className="ml-auto text-xs text-destructive" data-testid="meta-error">
            {(meta.error as Error).message}
          </span>
        )}

        <nav className="flex w-full gap-1">
          {PANES.map((p) => (
            <button
              key={p}
              className={`rounded px-2 py-0.5 text-xs ${pane === p ? 'bg-accent' : ''}`}
              onClick={() => setPane(p)}
              data-testid={`pane-${p}`}
            >
              {p}
              {/* A count on the tab is how something that happened while you
                  were elsewhere gets noticed at all. */}
              {p === 'history' && history.length > 0 && (
                <span className="ml-1 text-muted-foreground">{history.length}</span>
              )}
              {p === 'subscriptions' && subscription.state.unseen > 0 && (
                <span
                  className="ml-1 rounded bg-emerald-500/20 px-1 text-emerald-700"
                  data-testid="subscribe-unseen"
                >
                  {subscription.state.unseen}
                </span>
              )}
            </button>
          ))}
        </nav>
      </header>

      {connect.error && (
        <p className="border-b border-border px-4 py-1 text-xs text-destructive">
          {(connect.error as Error).message}
        </p>
      )}

      <main className="flex min-h-0 flex-1 flex-col">
        {!selected ? (
          <div className="flex flex-1 items-center justify-center text-xs text-muted-foreground">
            Add a target to begin — the picker above.
          </div>
        ) : (
          <>
            {/* Above the pane: the request it shows is holding a call open no
                matter which pane is on screen. */}
            <PendingRequests
              targetId={selected.id}
              connected={selected.session.state === 'ready'}
            />
            {pane === 'tools' && <ToolsPane {...paneProps} />}
            {pane === 'resources' && <ResourcesPane {...paneProps} />}
            {pane === 'prompts' && <PromptsPane {...paneProps} />}
            {pane === 'subscriptions' && (
              <SubscriptionsPane
                connected={paneProps.connected}
                subscription={subscription.state}
                onStart={subscription.start}
                onStop={subscription.stop}
                onClear={subscription.clearPushes}
                onSeen={subscription.markSeen}
              />
            )}
            {pane === 'history' && (
              <HistoryPane
                entries={history}
                onReplay={openAgain}
                onClear={() => setHistory([])}
              />
            )}
            {pane === 'diagnose' && (
              <DiagnosePane targetId={selected.id} connected={paneProps.connected} />
            )}
            {pane === 'wire' && <WirePane targetId={selected.id} />}
          </>
        )}
      </main>
    </div>
  );
}
