import { useEffect, useState } from 'react';
import {
  type Field,
  type Schema,
  fieldsOf,
  fromArguments,
  isFormable,
  problems,
  toArguments,
} from '@/lib/schema';

/**
 * Arguments, edited as the schema describes them — with the JSON always one
 * click away.
 *
 * A form is faster and says what a server will accept without reading a
 * schema; raw JSON is the only way to send what the schema does not
 * describe, which is half of what an inspector is for. Neither is a mode the
 * user should be stuck in, so the two edit one value and the toggle carries
 * it across.
 */
export function SchemaForm({
  schema,
  value,
  onChange,
  idPrefix,
  suggest,
}: {
  schema: Schema | null | undefined;
  /** The arguments object being composed. */
  value: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
  idPrefix: string;
  /**
   * Ask the server what completes a field. Absent where MCP defines no
   * completions — which is every tool, so the control simply does not appear
   * rather than offering something that would always come back empty.
   */
  suggest?: (argument: string, typed: string) => Promise<string[]>;
}) {
  const formable = isFormable(schema);
  const [raw, setRaw] = useState(!formable);
  const [text, setText] = useState(() => JSON.stringify(value, null, 2));
  const [fields, setFields] = useState<Record<string, string>>(() =>
    fromArguments(schema, value),
  );
  const [parseError, setParseError] = useState<string | null>(null);
  const [suggestions, setSuggestions] = useState<Record<string, string[]>>({});

  // A different tool is a different form: the previous one's values must not
  // sit in the new one's fields.
  //
  // Seeded from `value` rather than emptied, because the owner decides what a
  // form starts with — clearing unconditionally also erased the arguments
  // that "load into tools" had just restored from history, which made replay
  // look like it had done nothing.
  useEffect(() => {
    setFields(fromArguments(schema, value));
    setText(JSON.stringify(value ?? {}, null, 2));
    setParseError(null);
    setRaw(!isFormable(schema));
    setSuggestions({});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [idPrefix]);

  const found = problems(schema, fields);

  const setField = (name: string, next: string) => {
    const merged = { ...fields, [name]: next };
    setFields(merged);
    const args = toArguments(schema, merged);
    setText(JSON.stringify(args, null, 2));
    onChange(args);
  };

  const setRawText = (next: string) => {
    setText(next);
    try {
      const parsed = JSON.parse(next) as Record<string, unknown>;
      setParseError(null);
      setFields(fromArguments(schema, parsed));
      onChange(parsed);
    } catch (e) {
      setParseError((e as Error).message);
    }
  };

  return (
    <div className="space-y-2" data-testid="schema-form">
      <div className="flex items-center gap-2">
        <span className="text-muted-foreground">arguments</span>
        {formable && (
          <div className="ml-auto flex overflow-hidden rounded border border-input">
            <button
              className={`px-2 py-0.5 ${!raw ? 'bg-accent' : ''}`}
              onClick={() => setRaw(false)}
              data-testid="args-mode-form"
            >
              form
            </button>
            <button
              className={`px-2 py-0.5 ${raw ? 'bg-accent' : ''}`}
              onClick={() => setRaw(true)}
              data-testid="args-mode-json"
            >
              JSON
            </button>
          </div>
        )}
      </div>

      {!raw && formable && (
        <div className="space-y-2" data-testid="args-fields">
          {fieldsOf(schema).map((field) => (
            <FieldControl
              key={field.name}
              field={field}
              id={`${idPrefix}-${field.name}`}
              value={fields[field.name] ?? ''}
              onChange={(next) => setField(field.name, next)}
              problem={found.find((p) => p.field === field.name)?.message}
              suggestions={suggestions[field.name]}
              onSuggest={
                suggest
                  ? async () => {
                      const values = await suggest(field.name, fields[field.name] ?? '');
                      setSuggestions((prev) => ({ ...prev, [field.name]: values }));
                    }
                  : undefined
              }
            />
          ))}
        </div>
      )}

      {(raw || !formable) && (
        <>
          <textarea
            className="h-32 w-full rounded border border-input bg-background p-2 font-mono"
            value={text}
            onChange={(e) => setRawText(e.target.value)}
            data-testid="tool-args"
            aria-label="arguments (JSON)"
          />
          {parseError && (
            <p className="text-destructive" data-testid="args-parse-error">
              {parseError}
            </p>
          )}
          {!formable && (
            <p className="text-muted-foreground">
              This tool declares no argument properties, so there is no form to build —
              what it accepts is whatever it accepts.
            </p>
          )}
        </>
      )}

      {/* Reported, never enforced: sending what the schema disagrees with is
          a legitimate thing to do from an inspector. */}
      {found.length > 0 && !raw && (
        <p className="text-muted-foreground" data-testid="args-problems">
          {found.map((p) => `${p.field}: ${p.message}`).join(' · ')} — the call is still
          allowed
        </p>
      )}
    </div>
  );
}

function FieldControl({
  field,
  id,
  value,
  onChange,
  problem,
  suggestions,
  onSuggest,
}: {
  field: Field;
  id: string;
  value: string;
  onChange: (next: string) => void;
  problem?: string;
  suggestions?: string[];
  onSuggest?: () => void;
}) {
  const label = (
    <label className="flex items-baseline gap-1.5" htmlFor={id}>
      <span className="font-medium">{field.title}</span>
      {field.required && (
        <span className="text-destructive" title="required">
          *
        </span>
      )}
      <span className="text-muted-foreground">{typeName(field)}</span>
      {/* A missing required field already says so with the asterisk and in
          the summary below the form; repeating it beside every empty field
          shouts at someone who has not started typing yet. Only a value that
          is actually wrong is worth flagging here. */}
      {problem && problem !== 'required' && (
        <span className="ml-auto text-destructive">{problem}</span>
      )}
    </label>
  );

  const control = () => {
    const common = 'w-full rounded border border-input bg-background px-2 py-1 font-mono';
    switch (field.kind) {
      case 'boolean':
        return (
          <label className="flex items-center gap-2">
            <input
              id={id}
              type="checkbox"
              checked={value === 'true'}
              onChange={(e) => onChange(String(e.target.checked))}
              data-testid={`field-${field.name}`}
            />
            <span className="text-muted-foreground">{value === 'true' ? 'true' : 'false'}</span>
          </label>
        );
      case 'enum':
        return (
          <select
            id={id}
            className={common}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            data-testid={`field-${field.name}`}
          >
            <option value="">—</option>
            {(field.options ?? []).map((option) => {
              const text = typeof option === 'string' ? option : JSON.stringify(option);
              return (
                <option key={text} value={text}>
                  {text}
                </option>
              );
            })}
          </select>
        );
      case 'number':
      case 'integer':
        return (
          <input
            id={id}
            type="number"
            step={field.kind === 'integer' ? 1 : 'any'}
            className={common}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            data-testid={`field-${field.name}`}
          />
        );
      case 'text':
      case 'array':
      case 'object':
      case 'json':
        return (
          <textarea
            id={id}
            className={`${common} h-20`}
            value={value}
            placeholder={field.kind === 'array' ? '[]' : field.kind === 'object' ? '{}' : ''}
            onChange={(e) => onChange(e.target.value)}
            data-testid={`field-${field.name}`}
          />
        );
      default:
        return (
          <input
            id={id}
            type="text"
            className={common}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            data-testid={`field-${field.name}`}
          />
        );
    }
  };

  return (
    <div className="space-y-0.5">
      {label}
      {field.description && <p className="text-muted-foreground">{field.description}</p>}
      {control()}
      {onSuggest && (
        <div className="flex flex-wrap items-center gap-1">
          <button
            className="rounded border border-input px-1.5 py-0.5 text-[11px] text-muted-foreground"
            onClick={onSuggest}
            data-testid={`suggest-${field.name}`}
          >
            suggest
          </button>
          {/* The server's own suggestions, only after it was asked — nothing
              here is guessed locally. */}
          {suggestions?.map((option) => (
            <button
              key={option}
              className="rounded bg-accent px-1.5 py-0.5 font-mono text-[11px]"
              onClick={() => onChange(option)}
              data-testid={`suggestion-${field.name}`}
            >
              {option}
            </button>
          ))}
          {suggestions?.length === 0 && (
            <span className="text-[11px] text-muted-foreground">no suggestions</span>
          )}
        </div>
      )}
    </div>
  );
}

function typeName(field: Field): string {
  if (field.kind === 'enum') return 'enum';
  const declared = field.schema.type;
  if (typeof declared === 'string') return declared;
  if (Array.isArray(declared)) return declared.join(' | ');
  return 'any';
}
