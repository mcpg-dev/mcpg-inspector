import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type Resource, type ResourceTemplate } from '@/lib/api';
import { Empty, ListDetail, type EntityRow } from '@/components/EntityPane';
import { ResultView } from '@/components/ResultView';
import { SchemaForm } from '@/components/SchemaForm';
import { expandUriTemplate, schemaFromUriTemplate } from '@/lib/schema';
import { type RecordedPaneProps, useRecordedOp } from '@/lib/recorded';

type Kind = 'resources' | 'templates';

/**
 * Resources and resource templates, with a read form.
 *
 * The two live behind one switch because they are the same entity at
 * different degrees of resolution: a template becomes a resource once its
 * variables are filled, and the read form is the thing that fills them.
 */
export function ResourcesPane({
  targetId,
  connected,
  onRecord,
  replay,
  onReplayed,
}: RecordedPaneProps) {
  const [kind, setKind] = useState<Kind>('resources');
  const [selected, setSelected] = useState<string | null>(null);
  const [uri, setUri] = useState('');
  /** Whether the user has chosen a list themselves; their choice wins. */
  const [picked, setPicked] = useState(false);
  const [vars, setVars] = useState<Record<string, unknown>>({});

  const resources = useQuery({
    queryKey: ['resources', targetId],
    enabled: connected,
    queryFn: () => api.op<{ resources: Resource[] }>(targetId, 'resources.list'),
  });
  const templates = useQuery({
    queryKey: ['templates', targetId],
    enabled: connected,
    queryFn: () =>
      api.op<{ resourceTemplates: ResourceTemplate[] }>(targetId, 'resources.templates.list'),
  });

  const read = useRecordedOp({
    targetId,
    op: 'resources.read',
    kind: 'resources.read',
    onRecord,
  });

  useEffect(() => {
    if (replay?.kind !== 'resources.read') return;
    const params = (replay.args ?? {}) as { uri?: string };
    if (typeof params.uri === 'string') {
      setUri(params.uri);
      setSelected(params.uri);
    }
    onReplayed();
  }, [replay, onReplayed]);

  // Land on whichever list has something in it. A server that publishes only
  // templates was showing "No resources visible to this identity." on arrival,
  // which reads as "this server has nothing" rather than "look one tab over".
  //
  // Above the early returns: a hook after one runs on some renders and not
  // others, which is React error #310 and takes the whole app down.
  const resourceCount = resources.data?.resources?.length ?? 0;
  const templateCount = templates.data?.resourceTemplates?.length ?? 0;
  useEffect(() => {
    if (!connected || picked) return;
    if (resourceCount === 0 && templateCount > 0) setKind('templates');
  }, [connected, picked, resourceCount, templateCount]);

  if (!connected) return <Empty>Connect the target to list its resources.</Empty>;
  const active = kind === 'resources' ? resources : templates;
  if (active.isLoading) return <Empty>Loading {kind}…</Empty>;
  // A server may implement one and not the other; that is a legal shape,
  // and the error belongs on the tab that asked rather than the pane.
  if (active.error) return <Empty>{(active.error as Error).message}</Empty>;

  const list = resources.data?.resources ?? [];
  const templateList = templates.data?.resourceTemplates ?? [];

  const rows: EntityRow[] =
    kind === 'resources'
      ? list.map((r) => ({
          key: r.uri,
          primary: r.name ?? r.uri,
          secondary: r.description ?? r.uri,
        }))
      : templateList.map((t) => ({
          key: t.uriTemplate,
          primary: t.name ?? t.uriTemplate,
          secondary: t.description ?? t.uriTemplate,
        }));

  const resource = list.find((r) => r.uri === selected);
  const template = templateList.find((t) => t.uriTemplate === selected);
  // Only a template has variables to fill; a concrete resource is read as-is.
  const templateSchema = template ? schemaFromUriTemplate(template.uriTemplate) : null;



  const switcher = (
    <div className="ml-auto flex gap-1">
      {(['resources', 'templates'] as Kind[]).map((k) => (
        <button
          key={k}
          className={`rounded px-2 py-0.5 text-xs ${kind === k ? 'bg-accent' : ''}`}
          onClick={() => {
            setKind(k);
            setPicked(true);
            setSelected(null);
          }}
          data-testid={`resources-kind-${k}`}
        >
          {k}
          <span className="ml-1 text-muted-foreground">
            ({k === 'resources' ? list.length : templateList.length})
          </span>
        </button>
      ))}
    </div>
  );

  return (
    <ListDetail
      title={kind === 'resources' ? 'Resources' : 'Templates'}
      rows={rows}
      selected={selected}
      onSelect={(key) => {
        setSelected(key);
        // A concrete resource can be read as-is; a template needs its
        // variables filled, so the URI is seeded and left editable.
        setUri(key);
        setVars({});
        read.reset();
      }}
      emptyList={
        kind === 'resources'
          ? 'No resources visible to this identity.'
          : 'This server advertises no resource templates.'
      }
      testidPrefix="resource"
      header={switcher}
    >
      {!selected && <p className="text-muted-foreground">Select a {kind.replace(/s$/, '')}.</p>}
      {selected && (
        <div className="space-y-3">
          <div>
            <div className="break-all font-mono font-medium">{selected}</div>
            {(resource?.description ?? template?.description) && (
              <p className="text-muted-foreground">
                {resource?.description ?? template?.description}
              </p>
            )}
            <p className="text-muted-foreground">
              {resource?.mimeType ?? template?.mimeType ?? 'no declared mime type'}
            </p>
          </div>
          {/* A template's variables are fields; the URI they expand to stays
              on screen and editable, because a template this does not parse
              still has to be readable by hand. */}
          {templateSchema && (
            <SchemaForm
              schema={templateSchema}
              value={vars}
              onChange={(next) => {
                setVars(next);
                setUri(expandUriTemplate(selected, next));
              }}
              idPrefix={`${targetId}:${selected}`}
              suggest={(argument, typed) =>
                api.complete(
                  targetId,
                  { type: 'ref/resource', uri: template!.uriTemplate },
                  argument,
                  typed,
                )
              }
            />
          )}
          <div>
            <label className="mb-1 block text-muted-foreground" htmlFor="resource-uri">
              uri {templateSchema && '(expanded from the variables above)'}
            </label>
            <input
              id="resource-uri"
              className="w-full rounded border border-input bg-background p-2 font-mono"
              value={uri}
              data-testid="resource-uri"
              onChange={(e) => setUri(e.target.value)}
            />
          </div>
          <button
            className="rounded bg-primary px-3 py-1 text-primary-foreground disabled:opacity-50"
            disabled={uri.trim() === '' || read.isPending}
            onClick={() => read.mutate({ subject: uri, params: { uri } })}
            data-testid="resource-read"
          >
            {read.isPending ? 'reading…' : 'Read'}
          </button>
          {read.error && <p className="text-destructive">{(read.error as Error).message}</p>}
          {read.data != null && (
            <ResultView result={read.data.result} testid="resource-result" />
          )}
        </div>
      )}
    </ListDetail>
  );
}
