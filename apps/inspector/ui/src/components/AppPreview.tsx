import { useEffect, useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { api } from '@/lib/api';
import {
  type AppDeclaration,
  allowFor,
  appOf,
  cspFor,
  declarationOf,
  documentFor,
  readBridgeCall,
} from '@/lib/apps';

/**
 * A tool's MCP App, rendered — and watched.
 *
 * SEP-1865 lets a tool ship an HTML page and talk to the host over
 * `postMessage`. Every other host renders that page because a user asked for
 * a result. This one renders it because a user is *inspecting a server*,
 * which makes the page hostile by assumption. Three rules follow:
 *
 * 1. **Never automatic.** The page runs when someone clicks, and the click
 *    says what it is agreeing to.
 * 2. **No `allow-same-origin`.** With it, a sandboxed frame can reach this
 *    document, its storage and its session token. Without it the frame runs
 *    in an opaque origin and can reach none of them. This is the single
 *    attribute the whole design rests on.
 * 3. **Every request the app makes is shown.** A host that quietly performed
 *    an app's tool calls would be hiding the exact thing an inspector exists
 *    to reveal; they also cross the real wire, so they appear in the wire
 *    pane like anything else.
 */
export function AppPreview({
  targetId,
  tool,
}: {
  targetId: string;
  tool: { name: string; _meta?: unknown; meta?: unknown };
}) {
  const resourceUri = appOf(tool);
  const [app, setApp] = useState<AppDeclaration | null>(null);
  const [html, setHtml] = useState<string | null>(null);
  const [asked, setAsked] = useState<{ method: string; detail: string; at: string }[]>([]);
  const frame = useRef<HTMLIFrameElement | null>(null);

  const load = useMutation({
    mutationFn: async () => {
      // The op wraps what the server returned under `result`; the contents
      // are inside that, not beside it.
      const body = await api.op<{ result?: { contents?: unknown[] } }>(
        targetId,
        'resources.read',
        { uri: resourceUri },
      );
      const first = (body.result?.contents?.[0] ?? {}) as Record<string, unknown>;
      const text = typeof first.text === 'string' ? first.text : '';
      setApp(declarationOf(resourceUri!, first._meta));
      setHtml(text);
      return text;
    },
  });

  // The bridge. Messages are matched to THIS frame's window rather than to an
  // origin: a sandboxed srcdoc frame has the opaque origin "null", so an
  // origin check would accept any sandboxed frame on the page.
  useEffect(() => {
    if (!html) return;
    const onMessage = async (event: MessageEvent) => {
      if (!frame.current || event.source !== frame.current.contentWindow) return;
      const call = readBridgeCall(event.data);
      if (!call) return;
      const reply = (body: Record<string, unknown>) =>
        frame.current?.contentWindow?.postMessage({ jsonrpc: '2.0', id: call.id, ...body }, '*');

      const at = new Date().toLocaleTimeString();
      if (call.method === 'ui/ready') {
        setAsked((prev) => [...prev, { method: call.method, detail: 'the app reported ready', at }]);
        reply({ result: {} });
        return;
      }
      if (call.method === 'tools/call') {
        const params = (call.params ?? {}) as { name?: string; arguments?: unknown };
        const name = typeof params.name === 'string' ? params.name : '';
        setAsked((prev) => [
          ...prev,
          { method: call.method, detail: `${name} ${JSON.stringify(params.arguments ?? {})}`, at },
        ]);
        try {
          // Through the same engine as any other call, against the same
          // target the app came from — so it is subject to the same identity
          // and lands in the same wire log.
          const body = await api.op<{ result: unknown }>(targetId, 'tools.call', {
            name,
            arguments: params.arguments ?? {},
          });
          reply({ result: body.result });
        } catch (e) {
          reply({ error: { code: -32603, message: (e as Error).message } });
        }
        return;
      }
      // Refused, but still shown WITH its parameters. An inspector that hid
      // what an app asked for because it declined to do it would be hiding
      // the more interesting half.
      setAsked((prev) => [
        ...prev,
        {
          method: call.method,
          detail: `refused — not implemented · ${JSON.stringify(call.params ?? {})}`,
          at,
        },
      ]);
      reply({ error: { code: -32601, message: `this host does not implement ${call.method}` } });
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [html, targetId]);

  if (!resourceUri) return null;

  return (
    <section className="rounded border border-border" data-testid="app-preview">
      <header className="flex flex-wrap items-center gap-2 border-b border-border px-2 py-1.5">
        <span className="rounded bg-accent px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide">
          MCP App
        </span>
        <span className="font-mono text-xs" data-testid="app-uri">
          {resourceUri}
        </span>
        {!html && (
          <button
            className="ml-auto rounded bg-primary px-2 py-0.5 text-xs text-primary-foreground"
            onClick={() => load.mutate()}
            disabled={load.isPending}
            data-testid="app-render"
          >
            {load.isPending ? 'loading…' : 'render this app'}
          </button>
        )}
      </header>

      {!html && (
        <p className="px-2 py-1.5 text-xs text-muted-foreground">
          This tool ships an HTML app. Rendering runs the server's own page in your
          browser — sandboxed, with no access to this page or your session — and lets it
          ask this inspector to call tools on the same target. Nothing runs until you
          ask for it.
        </p>
      )}
      {load.error && (
        <p className="px-2 py-1.5 text-xs text-destructive">{(load.error as Error).message}</p>
      )}

      {html && app && (
        <>
          <div className="border-b border-border px-2 py-1 text-[11px] text-muted-foreground">
            <div data-testid="app-csp">
              <span className="font-medium">csp</span> {cspFor(app)}
            </div>
            <div data-testid="app-permissions">
              <span className="font-medium">permissions</span>{' '}
              {app.permissions.length > 0 ? app.permissions.join(', ') : 'none requested'}
            </div>
          </div>
          {/* sandbox WITHOUT allow-same-origin. The two together would let
              the frame reach this document; apart, it cannot. */}
          <iframe
            ref={frame}
            className="h-80 w-full bg-white"
            sandbox="allow-scripts allow-forms"
            allow={allowFor(app)}
            srcDoc={documentFor(app, html)}
            title={`MCP App for ${tool.name}`}
            data-testid="app-frame"
          />
          <div className="border-t border-border px-2 py-1 text-[11px]">
            <span className="text-muted-foreground">what the app asked for</span>
            {asked.length === 0 && (
              <span className="ml-2 text-muted-foreground">nothing yet</span>
            )}
            <ul className="space-y-0.5" data-testid="app-bridge-log">
              {asked.map((entry, i) => (
                <li key={i} className="font-mono">
                  <span className="text-muted-foreground">{entry.at}</span> {entry.method}{' '}
                  <span className="text-muted-foreground">{entry.detail}</span>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </section>
  );
}
