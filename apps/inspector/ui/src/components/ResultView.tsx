import { useState } from 'react';
import { type JsonValue, type Schema, resultRows } from '@/lib/schema';

/**
 * What came back, read rather than decoded.
 *
 * MCP returns two things at once: `content` blocks meant for a person or a
 * model, and — when the tool declares an output schema — `structuredContent`
 * meant for a program. Showing only the envelope makes the reader do the
 * decoding; showing only the decoded view hides the envelope, which is the
 * thing an inspector is often being used to check. So both are here, and the
 * raw JSON is one click away from either.
 */
export function ResultView({
  result,
  outputSchema,
  testid,
}: {
  result: unknown;
  outputSchema?: Schema | null;
  testid: string;
}) {
  const [raw, setRaw] = useState(false);
  const envelope = (result ?? {}) as Record<string, JsonValue>;
  const structured = envelope.structuredContent;
  const content = Array.isArray(envelope.content) ? envelope.content : [];
  const isError = envelope.isError === true;
  const rows = resultRows(outputSchema, structured);
  const readable = rows.length > 0 || content.length > 0;

  return (
    <div className="space-y-1" data-testid={`${testid}-view`}>
      <div className="flex items-center gap-2">
        <span className="text-muted-foreground">result</span>
        {isError && (
          <span
            className="rounded bg-destructive/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-destructive"
            data-testid={`${testid}-error-flag`}
          >
            isError
          </span>
        )}
        {readable && (
          <div className="ml-auto flex overflow-hidden rounded border border-input">
            <button
              className={`px-2 py-0.5 ${!raw ? 'bg-accent' : ''}`}
              onClick={() => setRaw(false)}
              data-testid={`${testid}-mode-view`}
            >
              view
            </button>
            <button
              className={`px-2 py-0.5 ${raw ? 'bg-accent' : ''}`}
              onClick={() => setRaw(true)}
              data-testid={`${testid}-mode-json`}
            >
              JSON
            </button>
          </div>
        )}
      </div>

      {(raw || !readable) && (
        <pre className="max-w-full overflow-x-auto rounded bg-muted p-2" data-testid={testid}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}

      {!raw && readable && (
        <div className="space-y-2" data-testid={`${testid}-structured`}>
          {rows.length > 0 && (
            <table className="w-full table-fixed border-collapse">
              <tbody>
                {rows.map((row) => (
                  <tr key={row.key} className="border-b border-border align-top last:border-0">
                    <th className="w-1/3 py-1 pr-2 text-left font-medium">
                      <span title={row.key}>{row.label}</span>
                      {row.description && (
                        <p className="font-normal text-muted-foreground">{row.description}</p>
                      )}
                    </th>
                    <td className="min-w-0 py-1">
                      <Scalar value={row.value} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {content.map((block, i) => (
            <ContentBlock key={i} block={block as Record<string, JsonValue>} />
          ))}
          {/* Structured output is only trustworthy against the schema that
              describes it; saying so beats implying the shape was checked. */}
          {rows.length > 0 && !outputSchema && (
            <p className="text-muted-foreground">
              No output schema declared — these are the keys as returned, unlabelled.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/** One `content` block, rendered as the kind it says it is. */
function ContentBlock({ block }: { block: Record<string, JsonValue> }) {
  const kind = typeof block.type === 'string' ? block.type : 'unknown';
  if (kind === 'text' && typeof block.text === 'string') {
    return (
      <div>
        <div className="text-muted-foreground">text</div>
        <p className="whitespace-pre-wrap rounded bg-muted p-2" data-testid="content-text">
          {block.text}
        </p>
      </div>
    );
  }
  if (kind === 'image' && typeof block.data === 'string') {
    const mime = typeof block.mimeType === 'string' ? block.mimeType : 'image/png';
    return (
      <div>
        <div className="text-muted-foreground">image · {mime}</div>
        <img
          className="max-w-full rounded border border-border"
          src={`data:${mime};base64,${block.data}`}
          alt="tool result"
          data-testid="content-image"
        />
      </div>
    );
  }
  if (kind === 'resource') {
    const resource = (block.resource ?? {}) as Record<string, JsonValue>;
    return (
      <div>
        <div className="text-muted-foreground">
          resource · {typeof resource.uri === 'string' ? resource.uri : 'embedded'}
        </div>
        <pre className="max-w-full overflow-x-auto rounded bg-muted p-2">
          {typeof resource.text === 'string'
            ? resource.text
            : JSON.stringify(resource, null, 2)}
        </pre>
      </div>
    );
  }
  return (
    <div>
      <div className="text-muted-foreground">{kind}</div>
      <pre className="max-w-full overflow-x-auto rounded bg-muted p-2">
        {JSON.stringify(block, null, 2)}
      </pre>
    </div>
  );
}

/** A leaf value inline, anything larger as JSON. */
function Scalar({ value }: { value: JsonValue }) {
  if (value === null) return <span className="text-muted-foreground">null</span>;
  if (typeof value === 'boolean' || typeof value === 'number') {
    return <span className="font-mono">{String(value)}</span>;
  }
  if (typeof value === 'string') {
    return <span className="break-words font-mono">{value}</span>;
  }
  return (
    <pre className="max-w-full overflow-x-auto rounded bg-muted p-1.5">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}
