import { useEffect, useRef, useState } from 'react';
import type { Target } from '@/lib/api';

/**
 * Which server you are looking at, as a control rather than a column.
 *
 * This was a sidebar: a permanent 16rem of the window given to a list that
 * usually holds one entry, next to panes whose whole problem is that the
 * useful thing has scrolled off. A picker costs the width of its own label
 * and says the same thing — which server, what wire it negotiated, whether
 * it is up.
 */
export function TargetPicker({
  targets,
  selected,
  onSelect,
  onAdd,
  addError,
  busy,
}: {
  targets: Target[];
  selected?: Target;
  onSelect: (id: string) => void;
  onAdd: (url: string) => void;
  addError?: string;
  busy?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState('');
  const box = useRef<HTMLDivElement>(null);

  // A menu that only closes by its own button is a menu you have to fight.
  useEffect(() => {
    if (!open) return;
    const onDown = (event: MouseEvent) => {
      if (box.current && !box.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div className="relative" ref={box}>
      <button
        className="flex items-center gap-2 rounded border border-input px-2 py-1 text-xs hover:bg-accent"
        onClick={() => setOpen((was) => !was)}
        aria-expanded={open}
        aria-haspopup="listbox"
        data-testid="target-picker"
      >
        <StateDot target={selected} />
        <span className="font-medium">{selected?.name ?? 'no target'}</span>
        <span
          className="max-w-64 truncate text-muted-foreground"
          title={endpointOf(selected)}
        >
          {endpointOf(selected)}
        </span>
        <span className="text-muted-foreground">▾</span>
      </button>

      {open && (
        <div
          className="absolute left-0 top-full z-20 mt-1 w-[28rem] rounded border border-border bg-background shadow-lg"
          role="listbox"
          data-testid="target-menu"
        >
          <ul className="max-h-72 overflow-auto">
            {targets.map((target) => (
              <li key={target.id}>
                <button
                  className={`flex w-full items-center gap-2 px-3 py-2 text-left text-xs hover:bg-accent ${
                    target.id === selected?.id ? 'bg-accent' : ''
                  }`}
                  onClick={() => {
                    onSelect(target.id);
                    setOpen(false);
                  }}
                  role="option"
                  aria-selected={target.id === selected?.id}
                  data-testid="target-option"
                >
                  <StateDot target={target} />
                  <span className="font-medium">{target.name}</span>
                  <span
                    className="min-w-0 flex-1 truncate text-muted-foreground"
                    title={endpointOf(target)}
                  >
                    {endpointOf(target)}
                  </span>
                  <span className="text-muted-foreground">{stateLabel(target)}</span>
                </button>
              </li>
            ))}
            {targets.length === 0 && (
              <li className="px-3 py-2 text-xs text-muted-foreground">
                No targets yet — add one below.
              </li>
            )}
          </ul>
          <form
            className="flex gap-1 border-t border-border p-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (url.trim()) {
                onAdd(url.trim());
                setUrl('');
              }
            }}
          >
            <input
              className="h-7 flex-1 rounded border border-input bg-background px-2 text-xs"
              placeholder="https://host/mcp"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              data-testid="add-target-url"
            />
            <button
              className="rounded bg-primary px-2 text-xs text-primary-foreground"
              disabled={busy}
              data-testid="add-target"
            >
              add
            </button>
          </form>
          {addError && (
            <p className="px-2 pb-2 text-xs text-destructive" data-testid="add-target-error">
              {addError}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function endpointOf(target?: Target): string {
  return target?.spec.url ?? target?.spec.command ?? '';
}

function stateLabel(target: Target): string {
  const session = target.session;
  return session.state === 'ready' ? session.negotiated_version : session.state;
}

/**
 * Connection state as a dot rather than a word.
 *
 * The picker is read at a glance and colour is what carries at that speed —
 * but colour alone is not a signal everyone receives, so the title and the
 * menu row both name the state in words.
 */
function StateDot({ target }: { target?: Target }) {
  const state = target?.session.state ?? 'idle';
  const tone =
    state === 'ready'
      ? 'bg-emerald-500'
      : state === 'failed'
        ? 'bg-destructive'
        : state === 'connecting'
          ? 'bg-amber-500'
          : 'bg-muted-foreground/40';
  return (
    <span
      className={`inline-block size-2 shrink-0 rounded-full ${tone}`}
      title={state}
      data-testid="state-dot"
      data-state={state}
    />
  );
}
