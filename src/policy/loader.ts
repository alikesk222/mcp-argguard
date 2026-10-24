import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parse } from "yaml";
import type { CompiledSecret } from "./matchers/secrets.js";
import { compilePolicyRegex } from "./regex.js";
import { type Policy, PolicySchema } from "./schema.js";

export type LoadedPolicy = {
  policy: Policy;
  filePath: string;
  policyHash: string;
  secrets: CompiledSecret[];
  text: string;
};

const MAX_POLICY_BYTES = 1_048_576;

export function loadPolicy(filePath: string): LoadedPolicy {
  const absolute = path.resolve(filePath);
  const text = fs.readFileSync(absolute, "utf8");
  if (Buffer.byteLength(text) > MAX_POLICY_BYTES) {
    throw new Error(`policy file exceeds ${MAX_POLICY_BYTES} bytes`);
  }
  let document: unknown;
  try {
    document = parse(text, { maxAliasCount: 0, uniqueKeys: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "YAML parse failed";
    throw new Error(`invalid policy YAML: ${message}`);
  }
  const parsed = PolicySchema.safeParse(document);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
      .join("; ");
    throw new Error(`invalid policy: ${detail}`);
  }
  return {
    policy: parsed.data,
    filePath: absolute,
    policyHash: createHash("sha256").update(text).digest("hex"),
    secrets: parsed.data.secrets.map((secret) => ({
      id: secret.id,
      regex: compilePolicyRegex(secret.regex, secret.id),
    })),
    text,
  };
}
