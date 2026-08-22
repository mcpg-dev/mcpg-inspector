/**
 * MCP Apps (SEP-1865, `io.modelcontextprotocol/ui`) as a *host* sees them.
 *
 * A tool may ship an HTML app: `_meta.ui.resourceUri` names a `ui://`
 * resource whose contents are the page, and whose own `_meta.ui` declares the
 * network it wants and the browser permissions it asks for. The host renders
 * it and answers what it asks for over `postMessage`.
 *
 * The inspector is a host that is pointed at servers nobody trusts — that is
 * its job — so the rules here are stricter than a chat client's would be, and
 * every one of them is a rule about what the page may reach, not about what
 * it may say.
 */

export const UI_META_KEY = 'io.modelcontextprotocol/ui';
export const UI_SCHEME = 'ui://';

/** The four CSP axes SEP-1865 carries, and the directives each one feeds. */
const AXES: Record<string, string[]> = {
  connectDomains: ['connect-src'],
  resourceDomains: ['img-src', 'style-src', 'font-src', 'media-src'],
  frameDomains: ['frame-src'],
  baseUriDomains: ['base-uri'],
};

/** The browser permissions SEP-1865 names, and their Permissions-Policy spelling. */
const PERMISSIONS: Record<string, string> = {
  camera: 'camera',
  microphone: 'microphone',
  geolocation: 'geolocation',
  clipboardWrite: 'clipboard-write',
};

export interface AppDeclaration {
  /** The `ui://` resource holding the page. */
  resourceUri: string;
  csp: Record<string, string[]>;
  permissions: string[];
}

/** What a tool says about its app, if it has one. */
export function appOf(tool: { _meta?: unknown; meta?: unknown }): string | null {
  const meta = (tool._meta ?? tool.meta) as Record<string, unknown> | undefined;
  if (!meta) return null;
  const ui = meta.ui as Record<string, unknown> | undefined;
  const uri = (ui?.resourceUri ?? meta['ui/resourceUri']) as string | undefined;
  return typeof uri === 'string' && uri.startsWith(UI_SCHEME) ? uri : null;
}

/** What a `ui://` resource declares about itself. */
export function declarationOf(resourceUri: string, meta: unknown): AppDeclaration {
  const ui = ((meta as Record<string, unknown> | undefined)?.ui ?? {}) as Record<
    string,
    unknown
  >;
  const declaredCsp = (ui.csp ?? {}) as Record<string, unknown>;
  const csp: Record<string, string[]> = {};
  for (const axis of Object.keys(AXES)) {
    const value = declaredCsp[axis];
    if (Array.isArray(value)) csp[axis] = value.filter((v): v is string => typeof v === 'string');
  }
  const declaredPermissions = (ui.permissions ?? {}) as Record<string, unknown>;
  const permissions = Object.keys(PERMISSIONS).filter((key) => declaredPermissions[key] === true);
  return { resourceUri, csp, permissions };
}

/**
 * The Content-Security-Policy the frame runs under.
 *
 * Starts at `default-src 'none'` and adds only what the app declared. A page
 * that declares nothing therefore reaches nothing, which is the right default
 * for HTML that arrived from a server being inspected.
 *
 * `script-src 'unsafe-inline'` is unavoidable and deliberate: the page is
 * rendered from `srcdoc`, so its scripts are inline by construction and there
 * is no origin to serve them from. It is safe *here* only because the frame
 * is sandboxed without `allow-same-origin` — the scripts run in an opaque
 * origin with no access to this page, its storage, or its token.
 */
export function cspFor(app: AppDeclaration): string {
  const directives: string[] = ["default-src 'none'", "script-src 'unsafe-inline'"];
  for (const [axis, mapped] of Object.entries(AXES)) {
    const domains = app.csp[axis];
    if (!domains || domains.length === 0) continue;
    for (const directive of mapped) {
      directives.push(`${directive} ${domains.join(' ')}`);
    }
  }
  // Inline styles are how these pages are written; without this a declared
  // style-src would still not let the page's own <style> block run.
  if (!directives.some((d) => d.startsWith('style-src'))) {
    directives.push("style-src 'unsafe-inline'");
  } else {
    const i = directives.findIndex((d) => d.startsWith('style-src'));
    directives[i] = `${directives[i]} 'unsafe-inline'`;
  }
  return directives.join('; ');
}

/** The `allow` attribute, from the permissions the app actually asked for. */
export function allowFor(app: AppDeclaration): string {
  return app.permissions
    .map((key) => `${PERMISSIONS[key]} 'src'`)
    .join('; ');
}

/**
 * The document handed to the frame: the app's own HTML with the policy
 * injected ahead of it.
 *
 * Prepended rather than merged into any `<head>` the page has, because a
 * `<meta http-equiv>` only binds what follows it — a CSP inserted after the
 * page's own scripts would not govern them.
 */
export function documentFor(app: AppDeclaration, html: string): string {
  return `<meta http-equiv="Content-Security-Policy" content="${cspFor(app).replace(/"/g, '&quot;')}">\n${html}`;
}

/** One thing the app asked the host to do. */
export interface BridgeCall {
  id: string | number | null;
  method: string;
  params: unknown;
}

/**
 * Read a message the frame posted.
 *
 * Only JSON-RPC-shaped objects are considered, and only the methods the host
 * implements are answered — an unknown method gets -32601 rather than being
 * ignored, so an app built against a fuller dialect fails loudly here instead
 * of hanging.
 */
export function readBridgeCall(data: unknown): BridgeCall | null {
  if (!data || typeof data !== 'object') return null;
  const message = data as Record<string, unknown>;
  if (typeof message.method !== 'string') return null;
  const id = message.id;
  return {
    id: typeof id === 'string' || typeof id === 'number' ? id : null,
    method: message.method,
    params: message.params,
  };
}

/** The methods this host answers. Anything else is refused by name. */
export const HOST_METHODS = ['tools/call', 'ui/ready'] as const;
