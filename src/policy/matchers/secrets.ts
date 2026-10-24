import { isPlainObject } from "../argpath.js";

export type CompiledSecret = {
  id: string;
  regex: RegExp;
};

export function findSecret(value: unknown, secrets: readonly CompiledSecret[]): string | undefined {
  if (secrets.length === 0) return undefined;
  let found: string | undefined;
  walk(value, (text) => {
    if (found) return;
    for (const secret of secrets) {
      secret.regex.lastIndex = 0;
      if (secret.regex.test(text)) {
        found = secret.id;
        return;
      }
    }
  });
  return found;
}

function walk(value: unknown, visit: (text: string) => void): void {
  if (typeof value === "string") {
    visit(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) walk(item, visit);
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    visit(key);
    walk(child, visit);
  }
}
