import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { evaluateLaunch, LAUNCH_GUARD_ENFORCED_IN } from "../../src/launch/guard.js";
import { loadCases, runCases } from "../../src/policy/cases.js";
import { loadPolicy } from "../../src/policy/loader.js";
import { createStreamableHttpProxy } from "../../src/transport/http.js";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

describe("launch classifier", () => {
  it("is present in v0.1 and enforced only in v0.3", () => {
    expect(LAUNCH_GUARD_ENFORCED_IN).toBe("0.3.0");
  });

  it("runs the CVE-2026-40933 corpus without spawning", () => {
    const loaded = loadPolicy(path.join(repoRoot, "policies/cve-classes/cve-2026-40933.yaml"));
    const cases = loadCases(path.join(repoRoot, "policies/cve-classes/cve-2026-40933.cases.yaml"));
    const report = runCases(loaded, cases, { workspace: repoRoot });
    expect(report.failed, JSON.stringify(report.results.filter((result) => !result.ok))).toBe(0);
  });

  it("does not treat an unlisted command as safe, only as uncovered", () => {
    const decision = evaluateLaunch({ command: "curl", args: ["https://example.test"] }, [
      { command: "npx", flags: ["-c"] },
    ]);
    expect(decision.decision).toBe("allow");
    expect(decision.ruleId).toBe("launch/unlisted");
  });
});

describe("http transport", () => {
  it("fails closed in v0.1", () => {
    expect(() => createStreamableHttpProxy()).toThrow(/v0\.2/);
  });
});
