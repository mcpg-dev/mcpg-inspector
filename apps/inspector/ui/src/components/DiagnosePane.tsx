import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { api, type AuthReport, type CheckReport, type GatewayReport } from '@/lib/api';
import { Empty, Json } from '@/components/EntityPane';

type Tab = 'auth' | 'checks' | 'gateway';

/**
 * Diagnostics: what a server wants, whether it behaves, and what is behind it.
 *
 * Three questions that arrive together in practice. The auth lab answers the
 * first — pointing at a real server and getting a 401 is the common first
 * experience — the protocol checks answer the second, and the gateway tab
 * answers the one the MCP surface cannot: a tool can be missing because the
 * plugin that backs it never came up. All are probes rather than reads, so
 * none runs until asked.
 */
export function DiagnosePane({ targetId, connected }: { targetId: string; connected: boolean }) {
  const [tab, setTab] = useState<Tab>('auth');

  const auth = useMutation({ mutationFn: () => api.auth(targetId) });
  const checks = useMutation({ mutationFn: () => api.checks(targetId) });
  const gateway = useMutation({ mutationFn: () => api.gateway(targetId) });

  const active = { auth, checks, gateway }[tab];
  // Only the auth lab works without a session: it exists to explain a failed
  // connect, so requiring one would close the door it is there to open.
  const blocked = tab !== 'auth' && !connected;

  return (
    <section className="flex min-h-0 flex-1 flex-col" data-testid="diagnose-pane">
      <header className="flex items-center gap-3 border-b border-border px-4 py-2">
        <h2 className="text-sm font-semibold">Diagnose</h2>
        <div className="flex gap-1">
          {(['auth', 'checks', 'gateway'] as const).map((t) => (
            <button
              key={t}
              className={`rounded px-2 py-0.5 text-xs ${tab === t ? 'bg-accent' : ''}`}
              onClick={() => setTab(t)}
              data-testid={`diagnose-tab-${t}`}
            >
              {t}
            </button>
          ))}
        </div>
        <button
          className="ml-auto rounded bg-primary px-3 py-1 text-xs text-primary-foreground disabled:opacity-50"
          disabled={active.isPending || blocked}
          onClick={() => active.mutate()}
          data-testid={`diagnose-run-${tab}`}
        >
          {active.isPending ? 'running…' : 'run'}
        </button>
      </header>
      <div className="min-h-0 min-w-0 flex-1 overflow-auto p-3 text-xs">
        {tab === 'auth' && <AuthView state={auth} />}
        {tab === 'checks' && <ChecksView state={checks} connected={connected} />}
        {tab === 'gateway' && <GatewayView state={gateway} connected={connected} />}
      </div>
    </section>
  );
}

/**
 * What the gateway says about itself.
 *
 * Leads with what is wrong. A gateway runs a dozen plugins and a handful of
 * readiness checks; listing the healthy ones pushes the unhealthy one off the
 * screen, and the unhealthy one is why the tab was opened.
 */
function GatewayView({
  state,
  connected,
}: {
  state: { data?: GatewayReport; error: unknown };
  connected: boolean;
}) {
  if (!connected) return <Empty>Connect the target to read the gateway behind it.</Empty>;
  if (state.error) return <p className="text-destructive">{(state.error as Error).message}</p>;
  if (!state.data) {
    return (
      <Empty>
        Reads what the mcpg gateway serving this endpoint says about itself: readiness, which
        plugins loaded, and which of them are not running. Where a missing tool usually turns
        out to have come from.
      </Empty>
    );
  }
  const report = state.data;
  const failing = report.failing_checks ?? [];
  const plugins = report.plugins ?? [];
  const unhappy = plugins.filter((plugin) => plugin.state !== 'active');
  const healthy = failing.length === 0 && unhappy.length === 0;

  return (
    <div className="space-y-3">
      <p>
        <span className="font-semibold">{report.service}</span>{' '}
        <span className="text-muted-foreground">{report.version}</span>{' '}
        <span
          className={healthy ? 'text-emerald-600' : 'text-destructive'}
          data-testid="gateway-readiness"
        >
          {report.readiness}
        </span>{' '}
        <span className="text-muted-foreground">
          · up {formatUptime(report.uptime_secs)} · log {report.log_level}
        </span>
      </p>

      {failing.length > 0 && (
        <ul className="space-y-1">
          {failing.map((check) => (
            <li key={check.name} data-testid="gateway-failing-check">
              <span className="text-destructive">{check.status}</span>{' '}
              <span className="font-mono">{check.name}</span>
              {check.detail && <div className="text-muted-foreground">{check.detail}</div>}
            </li>
          ))}
        </ul>
      )}

      <p data-testid="gateway-plugins">
        {report.plugin_count} plugin{report.plugin_count === 1 ? '' : 's'} loaded
        {unhappy.length > 0 ? `, ${unhappy.length} not active` : ', all active'}
      </p>
      {unhappy.length > 0 && (
        <ul className="space-y-1">
          {unhappy.map((plugin) => (
            <li key={plugin.id} data-testid="gateway-plugin-degraded">
              <span className="font-mono">{plugin.id}</span>{' '}
              <span className="text-destructive">{plugin.state}</span>{' '}
              <span className="text-muted-foreground">{plugin.class}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="text-muted-foreground">
        From <span className="font-mono">{report.url}</span>, which the gateway serves without
        authentication.
      </p>
    </div>
  );
}

/** Seconds as something readable at a glance. */
function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h${Math.floor((secs % 3600) / 60)}m`;
  return `${Math.floor(secs / 86400)}d${Math.floor((secs % 86400) / 3600)}h`;
}

function AuthView({
  state,
}: {
  state: { data?: AuthReport; error: unknown; isPending: boolean };
}) {
  if (state.error) return <p className="text-destructive">{(state.error as Error).message}</p>;
  if (!state.data) {
    return (
      <Empty>
        Sends one deliberately credential-free request and reports what came back — including
        which step of the discovery chain failed.
      </Empty>
    );
  }
  const report = state.data;
  return (
    <div className="space-y-3">
      <p className="rounded bg-muted p-2" data-testid="auth-verdict">
        {report.verdict}
      </p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3">
        <dt className="text-muted-foreground">probe status</dt>
        <dd>{report.probe_status}</dd>
        {report.www_authenticate && (
          <>
            <dt className="text-muted-foreground">WWW-Authenticate</dt>
            <dd className="break-all font-mono">{report.www_authenticate}</dd>
          </>
        )}
        {report.token_endpoint && (
          <>
            <dt className="text-muted-foreground">token endpoint</dt>
            <dd className="break-all font-mono">{report.token_endpoint}</dd>
          </>
        )}
      </dl>
      {report.discovery.length > 0 && (
        <div>
          <h3 className="mb-1 text-muted-foreground">discovery chain</h3>
          <ul className="space-y-1">
            {report.discovery.map((step, i) => (
              <li key={i} data-testid="discovery-step">
                <span className={step.ok ? 'text-emerald-600' : 'text-destructive'}>
                  {step.ok ? 'ok' : 'fail'}
                </span>{' '}
                <span className="font-mono">{step.step}</span>
                <div className="break-all text-muted-foreground">{step.url}</div>
                {step.detail && <div className="text-destructive">{step.detail}</div>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {report.aauth != null && (
        <div>
          {/* AAuth never speaks through WWW-Authenticate, so a server can be
              fully protected while the chain above finds nothing. */}
          <h3 className="mb-1 text-muted-foreground">AAuth</h3>
          <Json value={report.aauth} testid="auth-aauth" />
        </div>
      )}
    </div>
  );
}

function ChecksView({
  state,
  connected,
}: {
  state: { data?: CheckReport; error: unknown };
  connected: boolean;
}) {
  if (!connected) return <Empty>Connect the target to run the protocol checks.</Empty>;
  if (state.error) return <p className="text-destructive">{(state.error as Error).message}</p>;
  if (!state.data) {
    return (
      <Empty>
        Runs the portable checks any conformant server should pass, against the wire this
        target actually negotiated.
      </Empty>
    );
  }
  const report = state.data;
  return (
    <div className="space-y-3">
      <p>
        <span data-testid="checks-summary">
          {report.passed} passed, {report.failed} failed
          {report.skipped > 0 && `, ${report.skipped} skipped`}
        </span>{' '}
        <span className="text-muted-foreground">· {report.protocol_version}</span>
      </p>
      <ul className="space-y-2">
        {report.checks.map((check) => (
          <li key={check.id} data-testid="check-result">
            <span
              className={
                check.outcome === 'pass'
                  ? 'text-emerald-600'
                  : check.outcome === 'fail'
                    ? 'text-destructive'
                    : 'text-muted-foreground'
              }
            >
              {check.outcome}
            </span>{' '}
            <span className="font-mono">{check.id}</span>
            <div>{check.description}</div>
            {/* A skipped check is not a passing one: the wire this target
                negotiated has nothing for it to assert. */}
            {check.detail && <div className="text-muted-foreground">{check.detail}</div>}
          </li>
        ))}
      </ul>
    </div>
  );
}
