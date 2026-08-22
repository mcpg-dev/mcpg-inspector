import { useEffect, useState } from 'react';
import { Empty, Json } from '@/components/EntityPane';
import type { Push, Subscription } from '@/lib/subscriptions';

/**
 * Subscriptions: ask the server to tell you when something changes, and
 * watch what arrives.
 *
 * The stream itself lives above this pane — see `lib/subscriptions.ts` — so
 * that leaving the tab is navigation rather than cancellation. What is left
 * here is the part that has to be read: what is being watched, since when,
 * and what has come in.
 *
 * Pushes are grouped by what they are about, because the question is almost
 * never "what was the 41st push" — it is "which resources are changing, and
 * how often". The raw sequence is one click away for when it is not.
 */
export function SubscriptionsPane({
  connected,
  subscription,
  onStart,
  onStop,
  onClear,
  onSeen,
}: {
  connected: boolean;
  subscription: Subscription;
  onStart: (uris: string, lists: boolean) => void;
  onStop: () => void;
  onClear: () => void;
  onSeen: () => void;
}) {
  const [uris, setUris] = useState('');
  const [lists, setLists] = useState(true);
  const [grouped, setGrouped] = useState(true);

  // Arriving here is what "seen" means; the tab badge is for elsewhere.
  useEffect(() => onSeen(), [subscription.pushes.length, onSeen]);

  if (!connected) return <Empty>Connect the target to subscribe.</Empty>;

  const { watching, pushes } = subscription;
  const groups = groupPushes(pushes);

  return (
    <section className="flex min-h-0 flex-1 flex-col" data-testid="subscriptions-pane">
      <header className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          {/* A dot, not a pulse. "Live" was an infinite animation, which is
              noise on a page you stare at, ignores reduced-motion, and means
              the page never settles — the screenshot harness could not get a
              stable frame of it. The word beside it says the same thing and
              says it to everyone. */}
          <span
            className={`inline-block size-2 rounded-full ${
              watching ? 'bg-emerald-500' : 'bg-muted-foreground/40'
            }`}
            data-testid="subscribe-state"
            data-watching={watching}
          />
          Subscriptions
          <span className="text-xs font-normal text-muted-foreground">
            {watching ? 'live' : 'idle'}
          </span>
        </h2>
        <label className="flex items-center gap-1 text-xs text-muted-foreground">
          <input
            type="checkbox"
            checked={lists}
            disabled={watching}
            onChange={(e) => setLists(e.target.checked)}
            data-testid="subscribe-lists"
          />
          catalog changes
        </label>
        <input
          className="min-w-64 flex-1 rounded border border-input bg-background px-2 py-1 font-mono text-xs"
          placeholder="resource URIs to watch, comma-separated"
          value={uris}
          disabled={watching}
          onChange={(e) => setUris(e.target.value)}
          data-testid="subscribe-uris"
        />
        <button
          className="rounded bg-primary px-3 py-1 text-xs text-primary-foreground"
          onClick={() => (watching ? onStop() : onStart(uris, lists))}
          data-testid="subscribe-toggle"
        >
          {watching ? 'stop' : 'subscribe'}
        </button>
      </header>

      {/* What is actually being watched, since when. An empty watch list is a
          real subscription — catalog notifications need no URI — so it says
          so rather than looking unconfigured. */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border px-4 py-1.5 text-xs">
        <span data-testid="subscribe-watching">
          <span className="text-muted-foreground">watching</span>{' '}
          {subscription.watching || subscription.pushes.length > 0 ? (
            <>
              {subscription.lists && 'catalog changes'}
              {subscription.uris.length > 0 && (
                <>
                  {subscription.lists && ' + '}
                  <span className="font-mono">{subscription.uris.join(', ')}</span>
                </>
              )}
              {!subscription.lists && subscription.uris.length === 0 && 'nothing'}
            </>
          ) : (
            <span className="text-muted-foreground">not subscribed</span>
          )}
        </span>
        {subscription.since && (
          <span className="text-muted-foreground" data-testid="subscribe-since">
            since {new Date(subscription.since).toLocaleTimeString()}
          </span>
        )}
        <span className="text-muted-foreground">{pushes.length} push(es)</span>
        <div className="ml-auto flex items-center gap-2">
          <button
            className={`rounded border border-input px-2 py-0.5 ${grouped ? 'bg-accent' : ''}`}
            onClick={() => setGrouped(true)}
            data-testid="subscribe-view-grouped"
          >
            grouped
          </button>
          <button
            className={`rounded border border-input px-2 py-0.5 ${!grouped ? 'bg-accent' : ''}`}
            onClick={() => setGrouped(false)}
            data-testid="subscribe-view-stream"
          >
            stream
          </button>
          <button
            className="rounded border border-input px-2 py-0.5"
            onClick={onClear}
            data-testid="subscribe-clear"
          >
            clear
          </button>
        </div>
      </div>

      {subscription.error && (
        <p className="border-b border-border px-4 py-1 text-xs text-destructive">
          {subscription.error}
        </p>
      )}

      <div className="min-h-0 min-w-0 flex-1 overflow-auto p-3 text-xs">
        {!watching && pushes.length === 0 && (
          <p className="text-muted-foreground">
            Subscribe to watch what this server pushes. It answers with the subscriptions it
            actually honored — which can be fewer than you asked for. The stream keeps
            running while you use the other tabs.
          </p>
        )}
        {watching && pushes.length === 0 && (
          <p className="text-muted-foreground">Listening. Nothing pushed yet.</p>
        )}

        {grouped && groups.length > 0 && (
          <ul className="space-y-1" data-testid="subscribe-groups">
            {groups.map((group) => (
              <li key={group.key} className="rounded border border-border">
                <div className="flex items-baseline gap-2 px-2 py-1">
                  <span className="font-mono font-medium">{group.method}</span>
                  {group.uri && <span className="font-mono">{group.uri}</span>}
                  <span className="ml-auto text-muted-foreground">
                    ×{group.count} · last {new Date(group.last).toLocaleTimeString()}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}

        {!grouped && (
          <ul className="space-y-2">
            {pushes.map((push) => (
              <li key={push.seq} data-testid="subscription-push">
                <div className="text-muted-foreground">
                  <span className="font-mono">{push.method}</span>
                  {push.uri && <span className="ml-2 font-mono">{push.uri}</span>} ·{' '}
                  {new Date(push.at).toLocaleTimeString()}
                </div>
                <Json value={push.body} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

interface Group {
  key: string;
  method: string;
  uri?: string;
  count: number;
  last: number;
}

/** By method and resource, newest group first. */
function groupPushes(pushes: Push[]): Group[] {
  const byKey = new Map<string, Group>();
  for (const push of pushes) {
    const key = `${push.method}|${push.uri ?? ''}`;
    const found = byKey.get(key);
    if (found) {
      found.count += 1;
      found.last = Math.max(found.last, push.at);
    } else {
      byKey.set(key, {
        key,
        method: push.method,
        uri: push.uri,
        count: 1,
        last: push.at,
      });
    }
  }
  return [...byKey.values()].sort((a, b) => b.last - a.last);
}
