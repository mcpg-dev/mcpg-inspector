import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type Prompt } from '@/lib/api';
import { Empty, ListDetail, type EntityRow } from '@/components/EntityPane';
import { ResultView } from '@/components/ResultView';
import { SchemaForm } from '@/components/SchemaForm';
import { schemaFromPromptArguments } from '@/lib/schema';
import { type RecordedPaneProps, useRecordedOp } from '@/lib/recorded';

/**
 * Prompts: what the server advertises, and what one expands to.
 *
 * Listing a prompt shows only its shape. A prompt is a template, so the
 * rendered messages — which is what a model would actually receive — are
 * only visible by asking the server to expand it.
 */
export function PromptsPane({
  targetId,
  connected,
  onRecord,
  replay,
  onReplayed,
}: RecordedPaneProps) {
  const [selected, setSelected] = useState<string | null>(null);
  const [args, setArgs] = useState<Record<string, unknown>>({});

  useEffect(() => {
    if (replay?.kind !== 'prompts.get') return;
    const params = (replay.args ?? {}) as { name?: string; arguments?: unknown };
    if (typeof params.name === 'string') setSelected(params.name);
    setArgs((params.arguments ?? {}) as Record<string, unknown>);
    onReplayed();
  }, [replay, onReplayed]);

  const prompts = useQuery({
    queryKey: ['prompts', targetId],
    enabled: connected,
    queryFn: () => api.op<{ prompts: Prompt[] }>(targetId, 'prompts.list'),
  });

  const render = useRecordedOp({
    targetId,
    op: 'prompts.get',
    kind: 'prompts.get',
    onRecord,
  });

  if (!connected) return <Empty>Connect the target to list its prompts.</Empty>;
  if (prompts.isLoading) return <Empty>Loading prompts…</Empty>;
  if (prompts.error) return <Empty>{(prompts.error as Error).message}</Empty>;

  const list = prompts.data?.prompts ?? [];
  const prompt = list.find((p) => p.name === selected);
  const rows: EntityRow[] = list.map((p) => ({
    key: p.name,
    primary: p.title ?? p.name,
    secondary: p.description,
  }));

  return (
    <ListDetail
      title="Prompts"
      rows={rows}
      selected={selected}
      onSelect={(key) => {
        if (key !== selected) setArgs({});
        setSelected(key);
        render.reset();
      }}
      emptyList="No prompts visible to this identity."
      testidPrefix="prompt"
    >
      {!prompt && <p className="text-muted-foreground">Select a prompt.</p>}
      {prompt && (
        <div className="space-y-3">
          <div>
            <div className="font-mono font-medium">{prompt.name}</div>
            {prompt.description && <p className="text-muted-foreground">{prompt.description}</p>}
          </div>
          {/* A prompt's arguments are a name/required/description list, not
              JSON Schema — shaped into one so prompts and tools share a form
              rather than growing two that drift. */}
          <SchemaForm
            schema={schemaFromPromptArguments(prompt.arguments)}
            value={args}
            onChange={setArgs}
            idPrefix={`${targetId}:${prompt.name}`}
            suggest={(argument, typed) =>
              api.complete(targetId, { type: 'ref/prompt', name: prompt.name }, argument, typed)
            }
          />
          <button
            className="rounded bg-primary px-3 py-1 text-primary-foreground disabled:opacity-50"
            disabled={render.isPending}
            onClick={() =>
              render.mutate({
                subject: prompt.name,
                params: { name: prompt.name, arguments: args },
              })
            }
            data-testid="prompt-get"
          >
            {render.isPending ? 'rendering…' : 'Render'}
          </button>
          {render.error && <p className="text-destructive">{(render.error as Error).message}</p>}
          {render.data != null && (
            <ResultView result={render.data.result} testid="prompt-result" />
          )}
        </div>
      )}
    </ListDetail>
  );
}
