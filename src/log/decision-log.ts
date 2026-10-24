import fs from "node:fs";
import path from "node:path";
import type { LoadedPolicy } from "../policy/loader.js";
import { canonicalJson, sha256 } from "./canonical.js";
import { redactArgs } from "./redact.js";

export type DecisionRecord = {
  ts: string;
  server: string;
  method: string;
  tool: string | null;
  decision: "allow" | "deny";
  enforced: boolean;
  mode: "enforce" | "monitor";
  rule_id: string;
  reason: string;
  args_hash: string | null;
  policy_hash: string;
  latency_ms: number;
  protocol: string | null;
  args?: unknown;
};

export class DecisionLog {
  constructor(
    private readonly filePath: string,
    private readonly loaded: LoadedPolicy,
  ) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  }

  write(input: {
    server: string;
    method: string;
    tool: string | null;
    decision: "allow" | "deny";
    enforced: boolean;
    ruleId: string;
    reason: string;
    latencyMs: number;
    protocol: string | null;
    args: unknown;
  }): void {
    const store = this.loaded.policy.log.store_args;
    const record: DecisionRecord = {
      ts: new Date().toISOString(),
      server: input.server,
      method: input.method,
      tool: input.tool,
      decision: input.decision,
      enforced: input.enforced,
      mode: this.loaded.policy.mode,
      rule_id: input.ruleId,
      reason: input.reason,
      args_hash: store === "none" ? null : sha256(canonicalJson(input.args)),
      policy_hash: this.loaded.policyHash,
      latency_ms: Math.round(input.latencyMs * 1000) / 1000,
      protocol: input.protocol,
    };
    if (store === "redacted") {
      record.args = redactArgs(input.args, this.loaded.policy.log.redact_keys, this.loaded.secrets);
    }
    fs.appendFileSync(this.filePath, `${JSON.stringify(record)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
  }
}

export function expandLogPath(input: string, home: string): string {
  if (input === "~") return home;
  if (input.startsWith("~/")) return path.resolve(path.join(home, input.slice(2)));
  return path.resolve(input);
}
