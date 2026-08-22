/**
 * The list-and-detail shell every entity pane wears.
 *
 * Tools, resources and prompts differ in what they *do* with a selection,
 * not in how they present one, so the chrome lives here and each pane
 * supplies only its detail body. That keeps the panes from drifting apart
 * visually as they gain features.
 */
import type { ReactNode } from 'react';

export function Empty({ children }: { children: ReactNode }) {
  return (
    <section className="flex flex-1 items-center justify-center p-6 text-xs text-muted-foreground">
      {children}
    </section>
  );
}

export interface EntityRow {
  /** Stable key, and what the detail body is selected by. */
  key: string;
  primary: string;
  secondary?: string;
}

export function ListDetail({
  title,
  rows,
  selected,
  onSelect,
  emptyList,
  testidPrefix,
  children,
  header,
}: {
  title: string;
  rows: EntityRow[];
  selected: string | null;
  onSelect: (key: string) => void;
  emptyList: string;
  testidPrefix: string;
  children: ReactNode;
  header?: ReactNode;
}) {
  return (
    <section className="flex min-h-0 flex-1 flex-col" data-testid={`${testidPrefix}-pane`}>
      <header className="flex items-center gap-3 border-b border-border px-4 py-2">
        <h2 className="text-sm font-semibold">
          {title} <span className="text-muted-foreground">({rows.length})</span>
        </h2>
        {header}
      </header>
      <div className="flex min-h-0 flex-1">
        <ul
          className="w-1/3 min-w-48 overflow-auto border-r border-border"
          data-testid={`${testidPrefix}-list`}
        >
          {rows.map((row) => (
            <li key={row.key}>
              <button
                className={`w-full px-3 py-2 text-left text-xs hover:bg-accent ${
                  row.key === selected ? 'bg-accent' : ''
                }`}
                onClick={() => onSelect(row.key)}
                data-testid={`${testidPrefix}-item`}
              >
                <div className="break-all font-medium">{row.primary}</div>
                {row.secondary && (
                  <div className="line-clamp-2 text-muted-foreground">{row.secondary}</div>
                )}
              </button>
            </li>
          ))}
          {rows.length === 0 && (
            <li className="px-3 py-2 text-xs text-muted-foreground">{emptyList}</li>
          )}
        </ul>
        {/* min-w-0: a flex child defaults to min-width:auto, so a wide
            <pre> would push the whole page into a horizontal scroll
            instead of scrolling inside its own box. */}
        <div className="min-h-0 min-w-0 flex-1 overflow-auto p-3 text-xs">{children}</div>
      </div>
    </section>
  );
}

/** JSON, scrollable inside its own box rather than widening the page. */
export function Json({ value, testid }: { value: unknown; testid?: string }) {
  return (
    <pre className="max-w-full overflow-x-auto rounded bg-muted p-2" data-testid={testid}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

/** A JSON argument editor that reports its own parse error. */
export function ArgsEditor({
  id,
  value,
  onChange,
  error,
  testid,
}: {
  id: string;
  value: string;
  onChange: (next: string) => void;
  error: string | null;
  testid: string;
}) {
  return (
    <div>
      <label className="mb-1 block text-muted-foreground" htmlFor={id}>
        arguments (JSON)
      </label>
      <textarea
        id={id}
        className="h-32 w-full rounded border border-input bg-background p-2 font-mono"
        value={value}
        data-testid={testid}
        onChange={(e) => onChange(e.target.value)}
      />
      {error && <p className="text-destructive">{error}</p>}
    </div>
  );
}
