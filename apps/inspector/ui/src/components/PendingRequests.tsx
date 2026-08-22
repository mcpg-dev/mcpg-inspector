import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type PendingRequest } from '@/lib/api';
import { Json } from '@/components/EntityPane';

/**
 * What the server is asking this client, and the answer going back.
 *
 * Not a pane. A queued request is holding a call open — the server will not
 * answer until this does — so it has to be visible from wherever the user
 * happens to be standing, not filed behind a tab they might not open.
 */
export function PendingRequests({
  targetId,
  connected,
}: {
  targetId: string;
  connected: boolean;
}) {
  const queryClient = useQueryClient();
  const [answer, setAnswer] = useState('');
  const [answeringId, setAnsweringId] = useState<number | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  const queue = useQuery({
    queryKey: ['pending', targetId],
    queryFn: () => api.pending(targetId),
    enabled: connected,
    // Nothing pushes this: a request appears while a call the browser already
    // sent is still in flight, so the only way to see it is to look.
    refetchInterval: connected ? 1000 : false,
  });

  const first = queue.data?.pending?.[0];

  // Each request gets its own starting answer. Reusing the last one would
  // silently answer an elicitation with a sampling reply.
  useEffect(() => {
    if (!first) {
      setAnsweringId(null);
      return;
    }
    if (first.id !== answeringId) {
      setAnsweringId(first.id);
      setAnswer(template(first.method));
      setParseError(null);
    }
  }, [first, answeringId]);

  const respond = useMutation({
    mutationFn: ({ id, body }: { id: number; body: unknown }) =>
      api.respond(targetId, id, body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['pending', targetId] }),
  });

  if (!first) return null;

  const send = () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(answer);
    } catch (e) {
      setParseError((e as Error).message);
      return;
    }
    setParseError(null);
    respond.mutate({ id: first.id, body: { result: parsed } });
  };

  const decline = () =>
    respond.mutate({
      id: first.id,
      body: {
        error: { code: -32601, message: 'declined by the operator in mcpg-inspector' },
      },
    });

  return (
    <section
      className="border-b border-amber-500/40 bg-amber-500/10 px-4 py-3"
      data-testid="pending-requests"
    >
      <header className="flex flex-wrap items-center gap-2">
        <span className="rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-800 dark:text-amber-300">
          the server is asking
        </span>
        <span className="font-mono text-xs font-medium" data-testid="pending-method">
          {first.method}
        </span>
        <span className="text-xs text-muted-foreground">{first.regime} wire</span>
        {queue.data && queue.data.pending.length > 1 && (
          <span className="text-xs text-muted-foreground">
            +{queue.data.pending.length - 1} more waiting
          </span>
        )}
        <span className="ml-auto text-xs text-muted-foreground">
          the call that triggered this is waiting for an answer
        </span>
      </header>

      <div className="mt-2 grid gap-3 md:grid-cols-2">
        <div className="min-w-0">
          <p className="mb-1 text-xs text-muted-foreground">the server sent</p>
          <Json value={first.params} testid="pending-params" />
        </div>
        <div className="min-w-0">
          <label className="mb-1 block text-xs text-muted-foreground" htmlFor="pending-answer">
            your answer (JSON)
          </label>
          <textarea
            id="pending-answer"
            className="h-32 w-full rounded border border-input bg-background p-2 font-mono text-xs"
            value={answer}
            onChange={(e) => setAnswer(e.target.value)}
            data-testid="pending-answer"
          />
          {parseError && (
            <p className="text-xs text-destructive" data-testid="pending-parse-error">
              {parseError}
            </p>
          )}
          {respond.error && (
            <p className="text-xs text-destructive">{(respond.error as Error).message}</p>
          )}
          <div className="mt-1 flex gap-2">
            <button
              className="rounded bg-primary px-3 py-1 text-xs text-primary-foreground"
              onClick={send}
              disabled={respond.isPending}
              data-testid="pending-send"
            >
              {respond.isPending ? 'sending…' : 'answer'}
            </button>
            <button
              className="rounded border border-input px-3 py-1 text-xs"
              onClick={decline}
              disabled={respond.isPending}
              data-testid="pending-decline"
            >
              decline
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

/**
 * A starting point per request kind.
 *
 * The inspector will not call a model, so a sampling answer is a shell for a
 * human to type into rather than something generated. An unrecognised method
 * gets an empty object: better a blank than an invented shape.
 */
function template(method: PendingRequest['method']): string {
  switch (method) {
    case 'sampling/createMessage':
      return JSON.stringify(
        {
          role: 'assistant',
          content: { type: 'text', text: '' },
          model: 'mcpg-inspector-human',
          stopReason: 'endTurn',
        },
        null,
        2,
      );
    case 'elicitation/create':
      return JSON.stringify({ action: 'accept', content: {} }, null, 2);
    case 'roots/list':
      return JSON.stringify({ roots: [] }, null, 2);
    default:
      return '{}';
  }
}
