import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { evaluateCall, evaluateRequest } from "../../src/policy/engine.js";
import { lintPolicy } from "../../src/policy/lint.js";
import { loadPolicy } from "../../src/policy/loader.js";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "argguard-engine-"));

function policyFile(body: string): ReturnType<typeof loadPolicy> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "argguard-pol-"));
  const file = path.join(dir, "policy.yaml");
  fs.writeFileSync(file, body);
  return loadPolicy(file);
}

describe("policy engine", () => {
  it("denies an unknown tool and an unknown argument, and allows a nested list element", () => {
    const loaded = policyFile(`
version: 1
mode: enforce
defaults:
  tool: deny
  unknown_args: deny
servers:
  demo:
    tools:
      search:
        decision: allow
        args:
          query:
            type: string
            max_length: 32
          "targets[*].id":
            type: string
            allow: ["alpha", "beta"]
          limit:
            type: number
            minimum: 1
            maximum: 10
            integer: true
`);
    const allow = evaluateCall(loaded, {
      server: "demo",
      tool: "search",
      args: { query: "otters", targets: [{ id: "alpha" }], limit: 2 },
      workspace,
    });
    expect(allow.decision).toBe("allow");

    expect(
      evaluateCall(loaded, {
        server: "demo",
        tool: "search",
        args: { query: "otters", targets: [{ id: "alpha", extra: true }] },
        workspace,
      }).decision,
    ).toBe("deny");
    expect(
      evaluateCall(loaded, { server: "demo", tool: "other", args: {}, workspace }).ruleId,
    ).toBe("defaults/tool");
    expect(
      evaluateCall(loaded, {
        server: "demo",
        tool: "search",
        args: { query: "otters", limit: 2.5 },
        workspace,
      }).decision,
    ).toBe("deny");
  });

  it("scans secrets after an otherwise allowed value", () => {
    const loaded = loadPolicy(path.join(repoRoot, "policies/starter/fetch.yaml"));
    const decision = evaluateCall(loaded, {
      server: "fetch",
      tool: "fetch",
      args: { url: "https://docs.python.org/?q=AKIAIOSFODNN7EXAMPLE" },
      workspace,
    });
    expect(decision.decision).toBe("deny");
    expect(decision.ruleId).toBe("secrets/aws-access-key");
  });

  it("allows initialize and can deny another method", () => {
    const loaded = policyFile(`
version: 1
mode: enforce
methods:
  "resources/read": deny
servers: {}
`);
    const init = evaluateRequest(
      loaded,
      { method: "initialize", params: { protocolVersion: "2025-11-25" } },
      { serverName: "unused", workspace, home: os.homedir() },
    );
    expect(init.decision).toBe("allow");
    const discover = evaluateRequest(
      loaded,
      {
        method: "server/discover",
        params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } },
      },
      { serverName: "unused", workspace, home: os.homedir() },
    );
    expect(discover.decision).toBe("allow");
    const read = evaluateRequest(
      loaded,
      { method: "resources/read", params: { uri: "file:///tmp/x" } },
      { serverName: "unused", workspace, home: os.homedir() },
    );
    expect(read.decision).toBe("deny");
  });

  it("warns on a fail-open tool and stays quiet on the starter profiles", () => {
    const open = policyFile(`
version: 1
mode: enforce
defaults:
  tool: deny
  unknown_args: allow
servers:
  demo:
    tools:
      "*":
        decision: allow
`);
    const warnings = lintPolicy(open, { workspace, home: os.homedir() }).filter(
      (issue) => issue.severity === "warning",
    );
    expect(warnings.length).toBeGreaterThan(0);

    for (const relative of [
      "policies/starter/filesystem.yaml",
      "policies/starter/fetch.yaml",
      "policies/starter/shell.yaml",
    ]) {
      const loaded = loadPolicy(path.join(repoRoot, relative));
      const issues = lintPolicy(loaded, { workspace, home: os.homedir() });
      expect(issues.filter((issue) => issue.severity === "warning")).toEqual([]);
    }
  });

  it("evaluates a few thousand hostname decisions quickly", () => {
    const loaded = loadPolicy(path.join(repoRoot, "policies/cve-classes/cve-2026-18655.yaml"));
    const started = performance.now();
    for (let i = 0; i < 2000; i += 1) {
      evaluateCall(loaded, {
        server: "amazon-mq",
        tool: "rabbimq_broker_initialize_connection",
        args: { broker_hostname: i % 2 === 0 ? "b-1.mq.eu-central-1.amazonaws.com" : "evil.test" },
        workspace,
      });
    }
    expect(performance.now() - started).toBeLessThan(2000);
  });
});
