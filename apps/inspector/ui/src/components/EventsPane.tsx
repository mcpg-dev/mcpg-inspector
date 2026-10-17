import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type CheckResult, type EventHook, type EventType } from '@/lib/api';
import { Empty, Json, ListDetail, type EntityRow } from '@/components/EntityPane';
import { CheckList } from '@/components/DiagnosePane';
import { SchemaForm } from '@/components/SchemaForm';
import type { Schema } from '@/lib/schema';
import type { EventStream } from '@/lib/event-stream';
import { type RecordedPaneProps, useRecordedOp } from '@/lib/recorded';

type Tab = 'stream' | 'webhooks';

/**
 * MCP Events: the event types a server offers, read the three ways it can
 * deliver them.
 *
 * A poll is one request and its answer. A stream is held open above this
 * pane, like a subscription, so that looking at another tab does not end
 * it. A webhook subscription points the server at a callback this inspector
 * made for it; each delivery is checked against its signature and kept, so
 * what the server actually sent is on screen next to what it should have.
 */
export function EventsPane({
  targetId,
  connected,
  onRecord,
  replay,
  onReplayed,
  stream,
  onStreamStart,
  onStreamStop,
  onStreamClear,
  onSeen,
}: RecordedPaneProps & {
  stream: EventStream;
  onStreamStart: (name: string, args: unknown) => void;
  onStreamStop: () => void;
  onStreamClear: () => void;
  onSeen: () => void;
}) {
  const queryClient = useQueryClient();
  // An open stream outlives the pane; coming back shows it.
  const [selected, setSelected] = useState<string | null>(stream.name ?? null);
  const [args, setArgs] = useState<Record<string, unknown>>({});
  const [tab, setTab] = useState<Tab>('stream');
  const [callbackBase, setCallbackBase] = useState('');

  useEffect(() => onSeen(), [stream.frames.length, onSeen]);

  useEffect(() => {
    if (replay?.kind !== 'events.poll') return;
    const params = (replay.args ?? {}) as { name?: string; arguments?: unknown };
    if (typeof params.name === 'string') setSelected(params.name);
    setArgs((params.arguments ?? {}) as Record<string, unknown>);
    onReplayed();
  }, [replay, onReplayed]);

  const types = useQuery({
    queryKey: ['events', targetId],
    enabled: connected,
    queryFn: () => api.op<{ events: EventType[]; advertised?: unknown }>(targetId, 'events.list'),
  });

  const checks = useQuery({
    queryKey: ['event-checks', targetId],
    enabled: connected,
    queryFn: () => api.eventChecks(targetId),
    // Deliveries arrive on the server's schedule, not on a click.
    refetchInterval: 2_000,
  });

  const poll = useRecordedOp({ targetId, op: 'events.poll', kind: 'events.poll', onRecord });

  const subscribe = useMutation({
    mutationFn: (params: { name: string; arguments: unknown; callbackBase?: string }) =>
      api.op<{ result: unknown; hook: { sid: string; url: string } }>(
        targetId,
        'events.subscribe',
        params,
      ),
    onSuccess: () => {
      setTab('webhooks');
      queryClient.invalidateQueries({ queryKey: ['event-checks', targetId] });
    },
  });

  const unsubscribe = useMutation({
    mutationFn: (sid: string) => api.op<unknown>(targetId, 'events.unsubscribe', { sid }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['event-checks', targetId] }),
  });

  if (!connected) return <Empty>Connect the target to list its event types.</Empty>;
  if (types.isLoading) return <Empty>Loading event types…</Empty>;
  if (types.error) {
    return (
      <Empty>
        {(types.error as Error).message}. A server without the MCP Events extension lists none.
      </Empty>
    );
  }

  const list = types.data?.events ?? [];
  const type = list.find((t) => t.name === selected);
  const modes = new Set(type?.delivery ?? []);
  const rows: EntityRow[] = list.map((t) => ({
    key: t.name,
    primary: t.name,
    secondary: [t.delivery?.join(' · '), t.description].filter(Boolean).join(' — '),
  }));
  const hooks = checks.data?.hooks ?? [];
  const streamChecks = checks.data?.streams.at(-1);

  return (
    <ListDetail
      title="Events"
      rows={rows}
      selected={selected}
      onSelect={(key) => {
        if (key !== selected) setArgs({});
        setSelected(key);
        poll.reset();
        subscribe.reset();
      }}
      emptyList="No event types visible to this identity."
      testidPrefix="event"
      header={
        types.data?.advertised !== undefined && (
          <details className="text-xs" data-testid="event-advertised">
            <summary className="cursor-pointer text-muted-foreground">
              what the server advertises
            </summary>
            <Json value={types.data.advertised} />
          </details>
        )
      }
    >
      {!type && <p className="text-muted-foreground">Select an event type.</p>}
      {type && (
        <div className="space-y-3">
          <div className="sticky top-0 z-10 flex flex-wrap items-start gap-2 bg-background pb-2">
            <div className="min-w-0 flex-1">
              <div className="font-mono font-medium">{type.name}</div>
              {type.description && <p className="text-muted-foreground">{type.description}</p>}
              <p className="text-muted-foreground" data-testid="event-modes">
                delivery: {(type.delivery ?? []).join(', ') || 'none declared'}
              </p>
            </div>
            <button
              className="rounded bg-primary px-3 py-1 text-primary-foreground disabled:opacity-50"
              disabled={poll.isPending || !modes.has('poll')}
              onClick={() =>
                poll.mutate({ subject: type.name, params: { name: type.name, arguments: args } })
              }
              data-testid="event-poll"
            >
              {poll.isPending ? 'polling…' : 'Poll'}
            </button>
            <button
              className="rounded border border-input px-3 py-1 disabled:opacity-50"
              disabled={!modes.has('push')}
              onClick={() => {
                if (stream.open) {
                  onStreamStop();
                } else {
                  setTab('stream');
                  onStreamStart(type.name, args);
                }
              }}
              data-testid="event-stream-toggle"
            >
              {stream.open ? 'Close stream' : 'Stream'}
            </button>
            <button
              className="rounded border border-input px-3 py-1 disabled:opacity-50"
              disabled={subscribe.isPending || !modes.has('webhook')}
              onClick={() =>
                subscribe.mutate({
                  name: type.name,
                  arguments: args,
                  ...(callbackBase.trim() ? { callbackBase: callbackBase.trim() } : {}),
                })
              }
              data-testid="event-subscribe"
            >
              {subscribe.isPending ? 'subscribing…' : 'Webhook'}
            </button>
          </div>

          <SchemaForm
            schema={type.inputSchema as Schema | undefined}
            value={args}
            onChange={setArgs}
            idPrefix={`${targetId}:event:${type.name}`}
          />

          {modes.has('webhook') && (
            <label className="block">
              <span className="mb-1 block text-muted-foreground">
                webhook callback base: where the server reaches this inspector, when that is
                not the address it is served at (a tunnel, an https proxy)
              </span>
              <input
                className="w-full rounded border border-input bg-background px-2 py-1 font-mono"
                placeholder="this inspector's own address"
                value={callbackBase}
                onChange={(e) => setCallbackBase(e.target.value)}
                data-testid="event-callback-base"
              />
            </label>
          )}

          <div className="flex gap-3">
            {type.inputSchema != null && (
              <details className="min-w-0 flex-1">
                <summary className="cursor-pointer text-muted-foreground">input schema</summary>
                <Json value={type.inputSchema} />
              </details>
            )}
            {type.payloadSchema != null && (
              <details className="min-w-0 flex-1">
                <summary className="cursor-pointer text-muted-foreground">payload schema</summary>
                <Json value={type.payloadSchema} testid="event-payload-schema" />
              </details>
            )}
          </div>

          {poll.error && <p className="text-destructive">{(poll.error as Error).message}</p>}
          {poll.data != null && <Json value={poll.data.result} testid="event-poll-result" />}
          {subscribe.error && (
            <p className="text-destructive">{(subscribe.error as Error).message}</p>
          )}

          <nav className="flex gap-1 border-b border-border pb-1">
            {(['stream', 'webhooks'] as Tab[]).map((t) => (
              <button
                key={t}
                className={`rounded px-2 py-0.5 ${tab === t ? 'bg-accent' : ''}`}
                onClick={() => setTab(t)}
                data-testid={`event-tab-${t}`}
              >
                {t}
                {t === 'webhooks' && hooks.length > 0 && (
                  <span className="ml-1 text-muted-foreground">{hooks.length}</span>
                )}
              </button>
            ))}
          </nav>

          {tab === 'stream' && (
            <StreamView
              stream={stream}
              checks={stream.open || stream.frames.length > 0 ? streamChecks?.checks : undefined}
              onClear={onStreamClear}
            />
          )}
          {tab === 'webhooks' && (
            <HooksView
              hooks={hooks}
              onUnsubscribe={(sid) => unsubscribe.mutate(sid)}
              unsubscribing={unsubscribe.isPending}
              error={unsubscribe.error ? (unsubscribe.error as Error).message : undefined}
            />
          )}
        </div>
      )}
    </ListDetail>
  );
}

function StreamView({
  stream,
  checks,
  onClear,
}: {
  stream: EventStream;
  checks?: CheckResult[];
  onClear: () => void;
}) {
  return (
    <div className="space-y-2" data-testid="event-stream">
      <div className="flex flex-wrap items-baseline gap-3">
        <span className="flex items-center gap-2">
          <span
            className={`inline-block size-2 rounded-full ${
              stream.open ? 'bg-emerald-500' : 'bg-muted-foreground/40'
            }`}
            data-testid="event-stream-state"
            data-open={stream.open}
          />
          {stream.name ? (
            <span className="font-mono">
              {stream.name} {JSON.stringify(stream.arguments ?? {})}
            </span>
          ) : (
            <span className="text-muted-foreground">no stream open</span>
          )}
        </span>
        {stream.since && (
          <span className="text-muted-foreground">
            since {new Date(stream.since).toLocaleTimeString()}
          </span>
        )}
        <span className="text-muted-foreground">{stream.frames.length} frame(s)</span>
        <button className="ml-auto rounded border border-input px-2 py-0.5" onClick={onClear}>
          clear
        </button>
      </div>
      {stream.error && <p className="text-destructive">{stream.error}</p>}
      {checks && checks.length > 0 && <CheckList checks={checks} />}
      <ul className="space-y-2">
        {stream.frames.map((frame) => (
          <li key={frame.seq} data-testid="event-stream-frame">
            <div className="text-muted-foreground">
              <span className="font-mono">{frame.method}</span> ·{' '}
              {new Date(frame.at).toLocaleTimeString()}
            </div>
            <Json value={frame.body} />
          </li>
        ))}
      </ul>
    </div>
  );
}

function HooksView({
  hooks,
  onUnsubscribe,
  unsubscribing,
  error,
}: {
  hooks: EventHook[];
  onUnsubscribe: (sid: string) => void;
  unsubscribing: boolean;
  error?: string;
}) {
  if (hooks.length === 0) {
    return (
      <p className="text-muted-foreground">
        No webhook subscriptions. The server has to reach this inspector at the callback URL,
        and many servers send only to https: set a callback base for a tunnel or an https
        proxy when this inspector is not served at one.
      </p>
    );
  }
  return (
    <div className="space-y-4" data-testid="event-hooks">
      {error && <p className="text-destructive">{error}</p>}
      {hooks.map((hook) => (
        <div key={hook.sid} className="space-y-2 rounded border border-border p-2">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="font-mono font-medium">{hook.name}</span>
            <span className="font-mono text-muted-foreground">
              {JSON.stringify(hook.arguments)}
            </span>
            <button
              className="ml-auto rounded border border-input px-2 py-0.5 disabled:opacity-50"
              disabled={unsubscribing}
              onClick={() => onUnsubscribe(hook.sid)}
              data-testid="event-unsubscribe"
            >
              unsubscribe
            </button>
          </div>
          <div className="break-all font-mono text-muted-foreground">{hook.url}</div>
          <div className="text-muted-foreground">
            {hook.deliveries.at(-1)?.seq ?? 0} delivered
            {hook.refused > 0 && `, ${hook.refused} refused for their signature`}
          </div>
          {hook.checks.length > 0 && <CheckList checks={hook.checks} />}
          <ul className="space-y-2">
            {[...hook.deliveries].reverse().map((delivery) => (
              <li key={delivery.seq} data-testid="event-delivery">
                <div className="text-muted-foreground">
                  <span className="font-mono">{delivery.kind}</span>
                  {delivery.eventId && <span className="ml-2 font-mono">{delivery.eventId}</span>}{' '}
                  · {new Date(delivery.receivedAtMs).toLocaleTimeString()}
                </div>
                <Json value={delivery.body} />
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
