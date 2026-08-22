/**
 * Reading a JSON Schema well enough to build a form from it.
 *
 * Deliberately not a validator. A server's schema is a description of what
 * it will accept, and an inspector exists partly to find out what happens
 * when you send something else — so this shapes the input and reports what
 * looks wrong, and never blocks a call the user means to make.
 *
 * The typing is the part that matters. A form control hands back a string
 * for everything; sending `{"count": "3"}` where the schema says integer
 * produces a server-side type error that looks like a server bug, so the
 * declared type is what decides how a value is serialized.
 */

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface Schema {
  type?: string | string[];
  properties?: Record<string, Schema>;
  required?: string[];
  items?: Schema;
  enum?: JsonValue[];
  const?: JsonValue;
  default?: JsonValue;
  title?: string;
  description?: string;
  format?: string;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  [key: string]: unknown;
}

/** What a control needs to know to render itself. */
export interface Field {
  name: string;
  schema: Schema;
  required: boolean;
  /** The single type this field is edited as. */
  kind: FieldKind;
  title: string;
  description?: string;
  /** Values the schema restricts this to, if it does. */
  options?: JsonValue[];
}

export type FieldKind =
  | 'string'
  | 'text'
  | 'number'
  | 'integer'
  | 'boolean'
  | 'enum'
  | 'array'
  | 'object'
  /** No usable type information — edited as raw JSON. */
  | 'json';

/** The declared type, reduced to the one the control is built for. */
export function kindOf(schema: Schema): FieldKind {
  if (Array.isArray(schema.enum) && schema.enum.length > 0) return 'enum';
  const declared = Array.isArray(schema.type)
    ? // A union including "null" is the common "optional" spelling; edit it
      // as the type it actually carries.
      schema.type.find((t) => t !== 'null')
    : schema.type;
  switch (declared) {
    case 'string':
      // A long-form or multi-line string wants room; a one-line input for a
      // document body is the difference between usable and not.
      return schema.format === 'textarea' ||
        (typeof schema.maxLength === 'number' && schema.maxLength > 120)
        ? 'text'
        : 'string';
    case 'number':
      return 'number';
    case 'integer':
      return 'integer';
    case 'boolean':
      return 'boolean';
    case 'array':
      return 'array';
    case 'object':
      return 'object';
    default:
      return 'json';
  }
}

/**
 * The fields of an object schema, required ones first.
 *
 * Not declaration order — that is already gone. A schema reaches here having
 * been parsed and re-serialized on the way, and JSON objects come out of that
 * with their keys sorted, so the author's ordering is not recoverable. Given
 * a choice between alphabetical and useful, the fields a call cannot omit go
 * at the top.
 */
export function fieldsOf(schema: Schema | null | undefined): Field[] {
  if (!schema || typeof schema !== 'object') return [];
  const properties = schema.properties;
  if (!properties || typeof properties !== 'object') return [];
  const required = new Set(Array.isArray(schema.required) ? schema.required : []);
  const fields = Object.entries(properties).map(([name, property]) => {
    const sub = (property ?? {}) as Schema;
    return {
      name,
      schema: sub,
      required: required.has(name),
      kind: kindOf(sub),
      title: typeof sub.title === 'string' ? sub.title : name,
      description: typeof sub.description === 'string' ? sub.description : undefined,
      options: Array.isArray(sub.enum) ? sub.enum : undefined,
    };
  });
  return fields.sort((a, b) => Number(b.required) - Number(a.required));
}

/** True when a form is a fair representation of this schema. */
export function isFormable(schema: Schema | null | undefined): boolean {
  return fieldsOf(schema).length > 0;
}

/**
 * The text a control starts with. A schema default is honoured; everything
 * else starts empty, because a pre-filled guess is indistinguishable from a
 * value the user chose.
 */
export function initialText(field: Field): string {
  if (field.schema.default !== undefined) return textOf(field.schema.default);
  if (field.kind === 'boolean') return 'false';
  return '';
}

function textOf(value: JsonValue): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

export function initialValues(schema: Schema | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const field of fieldsOf(schema)) out[field.name] = initialText(field);
  return out;
}

/** What a field's text means, given its declared type. */
export function parseField(field: Field, text: string): JsonValue | undefined {
  const trimmed = text.trim();
  // Empty means absent, so an optional field left alone is not sent as "".
  if (trimmed === '') return undefined;
  switch (field.kind) {
    case 'boolean':
      return trimmed === 'true';
    case 'number':
    case 'integer': {
      const n = Number(trimmed);
      // A number that will not parse is sent as typed: the server's error is
      // more informative than this one refusing to ask.
      return Number.isNaN(n) ? text : n;
    }
    case 'enum': {
      const match = field.options?.find((option) => textOf(option) === trimmed);
      return match !== undefined ? match : text;
    }
    case 'string':
    case 'text':
      return text;
    default:
      try {
        return JSON.parse(text) as JsonValue;
      } catch {
        // Same reasoning: an unparseable object goes as a string and the
        // server says what it thinks of it.
        return text;
      }
  }
}

/** The arguments object a form's values describe. */
export function toArguments(
  schema: Schema | null | undefined,
  values: Record<string, string>,
): Record<string, JsonValue> {
  const out: Record<string, JsonValue> = {};
  for (const field of fieldsOf(schema)) {
    const parsed = parseField(field, values[field.name] ?? '');
    if (parsed !== undefined) out[field.name] = parsed;
  }
  return out;
}

/** Fill a form from an arguments object — the other direction of the toggle. */
export function fromArguments(
  schema: Schema | null | undefined,
  args: unknown,
): Record<string, string> {
  const out = initialValues(schema);
  if (!args || typeof args !== 'object' || Array.isArray(args)) return out;
  for (const field of fieldsOf(schema)) {
    const value = (args as Record<string, JsonValue>)[field.name];
    if (value !== undefined) out[field.name] = textOf(value);
  }
  return out;
}

export interface Problem {
  field: string;
  message: string;
}

/**
 * What looks wrong, reported rather than enforced.
 *
 * Sending a call the schema disagrees with is a legitimate thing to do from
 * an inspector — finding out how a server handles it is the job — so this
 * never prevents the call.
 */
export function problems(
  schema: Schema | null | undefined,
  values: Record<string, string>,
): Problem[] {
  const found: Problem[] = [];
  for (const field of fieldsOf(schema)) {
    const text = (values[field.name] ?? '').trim();
    if (text === '') {
      if (field.required) found.push({ field: field.name, message: 'required' });
      continue;
    }
    if (field.kind === 'number' || field.kind === 'integer') {
      const n = Number(text);
      if (Number.isNaN(n)) {
        found.push({ field: field.name, message: 'not a number' });
        continue;
      }
      if (field.kind === 'integer' && !Number.isInteger(n)) {
        found.push({ field: field.name, message: 'not an integer' });
      }
      if (typeof field.schema.minimum === 'number' && n < field.schema.minimum) {
        found.push({ field: field.name, message: `below minimum ${field.schema.minimum}` });
      }
      if (typeof field.schema.maximum === 'number' && n > field.schema.maximum) {
        found.push({ field: field.name, message: `above maximum ${field.schema.maximum}` });
      }
    }
    if (field.kind === 'array' || field.kind === 'object' || field.kind === 'json') {
      try {
        JSON.parse(text);
      } catch (e) {
        found.push({ field: field.name, message: (e as Error).message });
      }
    }
  }
  return found;
}

/**
 * The rows a structured result is displayed as.
 *
 * An output schema names and describes what came back; without one the keys
 * are all there is, and showing them is still better than showing nothing.
 */
export interface ResultRow {
  key: string;
  label: string;
  description?: string;
  value: JsonValue;
}

export function resultRows(schema: Schema | null | undefined, value: unknown): ResultRow[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
  const properties = (schema?.properties ?? {}) as Record<string, Schema>;
  return Object.entries(value as Record<string, JsonValue>).map(([key, entry]) => {
    const sub = properties[key];
    return {
      key,
      label: typeof sub?.title === 'string' ? sub.title : key,
      description: typeof sub?.description === 'string' ? sub.description : undefined,
      value: entry,
    };
  });
}

/**
 * A prompt's arguments as a schema.
 *
 * MCP describes prompt arguments as a name/description/required list rather
 * than as JSON Schema, and their values are strings. Shaping them into a
 * schema is what lets one form serve prompts and tools — a second form that
 * drifts from the first is worse than a small translation here.
 */
export function schemaFromPromptArguments(
  args: { name: string; description?: string; required?: boolean }[] | undefined,
): Schema | null {
  if (!args || args.length === 0) return null;
  const properties: Record<string, Schema> = {};
  const required: string[] = [];
  for (const arg of args) {
    properties[arg.name] = { type: 'string', description: arg.description };
    if (arg.required) required.push(arg.name);
  }
  return { type: 'object', properties, required };
}

/**
 * The variables an RFC 6570 URI template names, as a schema.
 *
 * Only the level-1 `{name}` form and the common operators are recognised —
 * enough to fill in what servers actually publish, and a template this does
 * not understand still falls through to being edited as a URI.
 */
export function schemaFromUriTemplate(template: string): Schema | null {
  const names = new Set<string>();
  for (const match of template.matchAll(/\{([^}]+)\}/g)) {
    for (const part of match[1].replace(/^[+#./;?&]/, '').split(',')) {
      const name = part.replace(/[*:].*$/, '').trim();
      if (name) names.add(name);
    }
  }
  if (names.size === 0) return null;
  const properties: Record<string, Schema> = {};
  for (const name of names) properties[name] = { type: 'string' };
  return { type: 'object', properties, required: [...names] };
}

/** Fill a URI template from values, leaving unknown expressions alone. */
export function expandUriTemplate(
  template: string,
  values: Record<string, unknown>,
): string {
  return template.replace(/\{([^}]+)\}/g, (whole, expression: string) => {
    const name = expression
      .replace(/^[+#./;?&]/, '')
      .replace(/[*:].*$/, '')
      .trim();
    const value = values[name];
    if (value === undefined || value === null) return whole;
    return encodeURIComponent(String(value));
  });
}
