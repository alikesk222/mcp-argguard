export type PathSegment =
  | { type: "key"; name: string }
  | { type: "index"; wild: true }
  | { type: "index"; wild: false; index: number };

const TOKEN = /([A-Za-z_][A-Za-z0-9_-]*)|\[\*\]/y;

export class ArgPathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArgPathError";
  }
}

/** Parse `targets[*].id` into segments. Paths are ASCII identifiers plus `[*]`. */
export function parseArgPath(path: string): PathSegment[] {
  if (path.length === 0 || path.length > 512) {
    throw new ArgPathError(`invalid argument path "${path}"`);
  }
  const segments: PathSegment[] = [];
  let index = 0;
  while (index < path.length) {
    if (path[index] === ".") {
      if (segments.length === 0) throw new ArgPathError(`invalid argument path "${path}"`);
      index += 1;
      if (index >= path.length) throw new ArgPathError(`invalid argument path "${path}"`);
    } else if (segments.length > 0 && path[index] !== "[") {
      throw new ArgPathError(`invalid argument path "${path}"`);
    }
    TOKEN.lastIndex = index;
    const match = TOKEN.exec(path);
    if (!match || match.index !== index) throw new ArgPathError(`invalid argument path "${path}"`);
    if (match[0] === "[*]") segments.push({ type: "index", wild: true });
    else segments.push({ type: "key", name: match[0] });
    index = TOKEN.lastIndex;
  }
  if (segments.length === 0 || segments[0]?.type !== "key") {
    throw new ArgPathError(`argument path must start with a name: "${path}"`);
  }
  return segments;
}

export function formatSegments(segments: readonly PathSegment[]): string {
  let out = "";
  for (const segment of segments) {
    if (segment.type === "key") out += out.length === 0 ? segment.name : `.${segment.name}`;
    else if (segment.wild) out += "[*]";
    else out += `[${segment.index}]`;
  }
  return out;
}

export type PathRelation = "exact" | "ancestor" | "descendant" | "none";

/** How a policy path relates to a concrete argument path. */
export function pathRelation(
  pattern: readonly PathSegment[],
  actual: readonly PathSegment[],
): PathRelation {
  const length = Math.min(pattern.length, actual.length);
  for (let i = 0; i < length; i += 1) {
    const left = pattern[i];
    const right = actual[i];
    if (!left || !right) return "none";
    if (left.type === "key" && right.type === "key" && left.name === right.name) continue;
    if (
      left.type === "index" &&
      right.type === "index" &&
      (left.wild || (!right.wild && !left.wild && left.index === right.index))
    ) {
      continue;
    }
    return "none";
  }
  if (pattern.length === actual.length) return "exact";
  if (pattern.length > actual.length) return "ancestor";
  return "descendant";
}

export function patternPresent(value: unknown, segments: readonly PathSegment[]): boolean {
  return presentAt(value, segments, 0);
}

function presentAt(value: unknown, segments: readonly PathSegment[], offset: number): boolean {
  if (offset >= segments.length) return true;
  const head = segments[offset];
  if (!head) return false;
  if (head.type === "key") {
    if (!isPlainObject(value) || !Object.hasOwn(value, head.name)) return false;
    return presentAt(value[head.name], segments, offset + 1);
  }
  if (!Array.isArray(value)) return false;
  if (offset === segments.length - 1) return true;
  return value.every((item) => presentAt(item, segments, offset + 1));
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function walkArguments(
  value: unknown,
  visit: (segments: PathSegment[], node: unknown, container: boolean) => void,
): void {
  walk(value, [], visit);
}

function walk(
  value: unknown,
  segments: PathSegment[],
  visit: (segments: PathSegment[], node: unknown, container: boolean) => void,
): void {
  if (segments.length > 0) {
    const container = Array.isArray(value) || isPlainObject(value);
    visit(segments, value, container);
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      walk(value[i], [...segments, { type: "index", wild: false, index: i }], visit);
    }
    return;
  }
  if (isPlainObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      walk(child, [...segments, { type: "key", name: key }], visit);
    }
  }
}
