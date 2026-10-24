import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../src/log/canonical.js";
import { DecisionLog } from "../../src/log/decision-log.js";
import { loadPolicy } from "../../src/policy/loader.js";
import { detectProtocolEra } from "../../src/protocol/era.js";
import { attachNdjson } from "../../src/protocol/framing.js";

describe("decision log", () => {
  it("hashes arguments and redacts configured keys and secret values", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "argguard-log-"));
    const policyPath = path.join(dir, "policy.yaml");
    fs.writeFileSync(
      policyPath,
      `
version: 1
mode: enforce
log:
  path: ${path.join(dir, "decisions.jsonl")}
  store_args: redacted
secrets:
  - id: aws-access-key
    regex: "AKIA[0-9A-Z]{16}"
servers: {}
`,
    );
    const loaded = loadPolicy(policyPath);
    const log = new DecisionLog(path.join(dir, "decisions.jsonl"), loaded);
    const args = { token: "raw-token", note: "AKIAIOSFODNN7EXAMPLE", ok: "visible" };
    log.write({
      server: "demo",
      method: "tools/call",
      tool: "fetch",
      decision: "deny",
      enforced: true,
      ruleId: "secrets/aws-access-key",
      reason: "value matched secret rule aws-access-key",
      latencyMs: 1.23456,
      protocol: "2025-11-25",
      args,
    });
    const line = fs.readFileSync(path.join(dir, "decisions.jsonl"), "utf8").trim();
    const record = JSON.parse(line) as {
      args: Record<string, string>;
      args_hash: string;
      reason: string;
    };
    expect(record.args.token).toBe("***");
    expect(record.args.note).toBe("***");
    expect(record.args.ok).toBe("visible");
    expect(record.reason).not.toContain("AKIA");
    expect(record.args_hash).toHaveLength(64);
    expect(line).not.toContain("raw-token");
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
  });
});

describe("framing and era", () => {
  it("emits one oversize event and then a following line", async () => {
    const stream = Readable.from([`${"x".repeat(32)}\n{"ok":true}\n`]);
    const lines: string[] = [];
    let oversize = 0;
    attachNdjson(stream, 16, {
      onLine: (line) => lines.push(line),
      onOversize: () => {
        oversize += 1;
      },
    });
    await new Promise((resolve) => stream.on("end", resolve));
    expect(oversize).toBe(1);
    expect(lines).toEqual(['{"ok":true}']);
  });

  it("recognizes both protocol eras without changing the message", () => {
    expect(
      detectProtocolEra({
        method: "initialize",
        params: { protocolVersion: "2025-11-25" },
      }),
    ).toBe("2025-11-25");
    expect(
      detectProtocolEra({
        method: "tools/call",
        params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } },
      }),
    ).toBe("2026-07-28");
  });
});
