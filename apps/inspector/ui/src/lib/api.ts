/**
 * Client for the inspector's own API.
 *
 * The session token comes from the page the server rendered
 * (`window.__INSPECTOR_TOKEN__`), falling back to `?token=` on first
 * load. It is held in memory only — never localStorage, so a stale tab
 * cannot resurrect a token from a previous run.
 */

declare global {
  interface Window {
    __INSPECTOR_TOKEN__?: string;
  }
}

function readToken(): string {
  if (window.__INSPECTOR_TOKEN__) return window.__INSPECTOR_TOKEN__;
  const fromUrl = new URLSearchParams(window.location.search).get('token');
  return fromUrl ?? '';
}

const token = readToken();

export class ApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init?.body) headers.set('Content-Type', 'application/json');
  const resp = await fetch(`/api/v1${path}`, { ...init, headers });
  if (!resp.ok) {
    const body = await resp.json().catch(() => null);
    throw new ApiError(
      body?.error?.code ?? 'unknown',
      body?.error?.message ?? `HTTP ${resp.status}`,
      resp.status,
    );
  }
  return (await resp.json()) as T;
}

export interface Meta {
  service: string;
  version: string;
  mode: 'local' | 'hosted';
  authMode: string;
  protocolVersions: string[];
  ops: string[];
}

export type SessionState =
  | { state: 'idle' }
  | { state: 'connecting' }
  | { state: 'ready'; negotiated_version: string }
  | { state: 'failed'; message: string };

export interface Target {
  id: string;
  name: string;
  spec: {
    url?: string;
    command?: string;
    args?: string[];
    protocol_version: string;
    bearerConfigured: boolean;
    headers?: Record<string, string>;
  };
  session: SessionState;
}

export interface WireEvent {
  seq: number;
  ts_ms: number;
  direction: 'sent' | 'received';
  channel: string;
  body: string;
}

export interface Tool {
  name: string;
  /** SEP-1865 rides here: `_meta.ui.resourceUri` names a tool's app. */
  _meta?: unknown;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: unknown;
}

export interface Resource {
  uri: string;
  name?: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

export interface ResourceTemplate {
  uriTemplate: string;
  name?: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

export interface PromptArgument {
  name: string;
  description?: string;
  required?: boolean;
}

export interface Prompt {
  name: string;
  title?: string;
  description?: string;
  arguments?: PromptArgument[];
}

export interface DiscoveryStep {
  step: string;
  url: string;
  ok: boolean;
  detail?: string;
}

export interface AuthReport {
  probe_status: number;
  answered_without_credential: boolean;
  www_authenticate?: string;
  discovery: DiscoveryStep[];
  resource?: string;
  token_endpoint?: string;
  discovery_error?: string;
  /** AAuth lives in a channel of its own — see the pane. */
  aauth?: unknown;
  verdict: string;
}

export interface CheckResult {
  id: string;
  description: string;
  outcome: 'pass' | 'fail' | 'skip';
  detail?: string;
}

export interface CheckReport {
  protocol_version: string;
  passed: number;
  failed: number;
  skipped: number;
  checks: CheckResult[];
}

/**
 * What the mcpg gateway behind a target says about itself. Absent for a
 * server that is not one — the panel says so rather than showing blanks.
 */
export interface GatewayReport {
  url: string;
  service: string;
  version: string;
  uptime_secs: number;
  readiness: string;
  failing_checks?: GatewayCheck[];
  log_level: string;
  plugin_count: number;
  plugins?: GatewayPlugin[];
}

export interface GatewayCheck {
  name: string;
  status: string;
  detail?: string;
}

export interface GatewayPlugin {
  id: string;
  version: string;
  class: string;
  /** `active`, `degraded`, `disabled`. */
  state: string;
}

export interface PendingRequest {
  id: number;
  /** `sampling/createMessage`, `elicitation/create`, `roots/list`. */
  method: string;
  params: unknown;
  /** Which regime produced it — the two differ on timeout and cancellation. */
  regime: string;
}

export interface PendingQueue {
  /** `{ mode: 'interactive' | 'auto-decline' | 'mock', … }` */
  policy: { mode: string } & Record<string, unknown>;
  pending: PendingRequest[];
}

export const api = {
  meta: () => request<Meta>('/meta'),
  targets: () => request<{ targets: Target[] }>('/targets'),
  addTarget: (spec: unknown) =>
    request<Target>('/targets', { method: 'POST', body: JSON.stringify(spec) }),
  removeTarget: (id: string) =>
    request<unknown>(`/targets/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  connect: (id: string) =>
    request<Target>(`/targets/${encodeURIComponent(id)}/connect`, { method: 'POST' }),
  disconnect: (id: string) =>
    request<Target>(`/targets/${encodeURIComponent(id)}/disconnect`, { method: 'POST' }),
  auth: (id: string) => request<AuthReport>(`/targets/${encodeURIComponent(id)}/auth`),
  checks: (id: string) => request<CheckReport>(`/targets/${encodeURIComponent(id)}/checks`),
  gateway: (id: string) => request<GatewayReport>(`/targets/${encodeURIComponent(id)}/gateway`),
  op: <T>(id: string, op: string, params?: unknown) =>
    request<T>(`/targets/${encodeURIComponent(id)}/ops/${op}`, {
      method: 'POST',
      body: JSON.stringify(params ?? {}),
    }),
  /**
   * What the server is asking this client, and how this target is set up to
   * answer. Only the `interactive` policy ever queues anything — the others
   * answer inline, which is the point of them.
   */
  pending: (id: string) =>
    request<PendingQueue>(`/targets/${encodeURIComponent(id)}/pending`),
  /**
   * Answer one queued request. A decline is a legitimate answer rather than
   * an error, so it travels as `{error}` and still resolves the request.
   */
  respond: (id: string, requestId: number, body: unknown) =>
    request<{ answered: number }>(
      `/targets/${encodeURIComponent(id)}/pending/${requestId}`,
      { method: 'POST', body: JSON.stringify(body) },
    ),
  /**
   * What the server suggests for one argument, given what is typed so far.
   * MCP defines completions for prompts and resource templates only — a
   * tool's arguments have no equivalent — so `ref` is one of those two.
   */
  complete: async (
    id: string,
    reference: unknown,
    argument: string,
    typed: string,
  ): Promise<string[]> => {
    const body = await request<{ result?: { completion?: { values?: string[] } } }>(
      `/targets/${encodeURIComponent(id)}/ops/completion.complete`,
      {
        method: 'POST',
        body: JSON.stringify({ ref: reference, argument: { name: argument, value: typed } }),
      },
    );
    return body.result?.completion?.values ?? [];
  },
  exportUrl: (id: string) =>
    `/api/v1/targets/${encodeURIComponent(id)}/export${token ? `?token=${encodeURIComponent(token)}` : ''}`,
  /**
   * Changes the target pushes. A held-open stream, unlike everything
   * else here — see the pane for why that is the one stateful surface.
   */
  subscribe: (id: string, uris: string, lists: boolean): EventSource => {
    const params = new URLSearchParams({ lists: String(lists) });
    if (uris.trim()) params.set('uris', uris.trim());
    if (token) params.set('token', token);
    return new EventSource(
      `/api/v1/targets/${encodeURIComponent(id)}/subscribe?${params}`,
    );
  },
  /**
   * Live wire frames. EventSource cannot set headers, so the token
   * rides the query — the server's origin gate already refused any
   * cross-origin caller before it looks at the token.
   */
  events: (id: string, since: number): EventSource =>
    new EventSource(
      `/api/v1/targets/${encodeURIComponent(id)}/events?since=${since}` +
        (token ? `&token=${encodeURIComponent(token)}` : ''),
    ),
};
