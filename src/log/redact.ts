import { isPlainObject } from "../policy/argpath.js";
import type { CompiledSecret } from "../policy/matchers/secrets.js";

export function redactArgs(
  value: unknown,
  redactKeys: readonly string[],
  secrets: readonly CompiledSecret[],
): unknown {
  const keys = new Set(redactKeys.map((key) => key.toLowerCase()));
  return redact(value, null, keys, secrets);
}

function redact(
  value: unknown,
  key: string | null,
  keys: ReadonlySet<string>,
  secrets: readonly CompiledSecret[],
): unknown {
  if (key && keys.has(key.toLowerCase())) return "***";
  if (typeof value === "string") {
    for (const secret of secrets) {
      secret.regex.lastIndex = 0;
      if (secret.regex.test(value)) return "***";
    }
    return value;
  }
  if (Array.isArray(value)) return value.map((item) => redact(item, null, keys, secrets));
  if (!isPlainObject(value)) return value;
  const out: Record<string, unknown> = {};
  for (const [childKey, child] of Object.entries(value)) {
    out[childKey] = redact(child, childKey, keys, secrets);
  }
  return out;
}
