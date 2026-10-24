import fs from "node:fs";
import picomatch from "picomatch";
import type { LoadedPolicy } from "./loader.js";
import { isUniversalHostPattern } from "./matchers/hostglob.js";
import { expandPolicyPath, type PathContext } from "./matchers/path.js";
import type { ArgRule } from "./schema.js";

export type LintIssue = {
  severity: "warning" | "info";
  message: string;
};

export function lintPolicy(loaded: LoadedPolicy, ctx: PathContext): LintIssue[] {
  const issues: LintIssue[] = [];
  const policy = loaded.policy;
  if (policy.mode === "monitor") {
    issues.push({
      severity: "info",
      message: "mode is monitor: decisions are logged and calls are still forwarded",
    });
  }
  if (policy.launch) {
    issues.push({
      severity: "info",
      message:
        "launch.deny_inline_code is recognized but not enforced by wrap until v0.3. `test` and `explain` still evaluate it.",
    });
  }
  if (policy.defaults.tool === "allow") {
    issues.push({
      severity: "warning",
      message: "defaults.tool is allow (fail-open for unknown tools)",
    });
  }
  if (policy.defaults.unknown_args === "allow") {
    issues.push({
      severity: "warning",
      message: "defaults.unknown_args is allow (undeclared arguments are not rejected)",
    });
  }
  for (const method of ["initialize", "notifications/initialized", "server/discover"]) {
    if (policy.methods?.[method] === "deny") {
      issues.push({
        severity: "info",
        message: `methods.${method} is deny, which breaks a normal MCP session`,
      });
    }
  }

  try {
    const stat = fs.statSync(loaded.filePath);
    if ((stat.mode & 0o002) !== 0) {
      issues.push({ severity: "warning", message: "policy file is world-writable" });
    }
  } catch {
    issues.push({ severity: "warning", message: "policy file could not be stat'ed" });
  }

  for (const [serverName, server] of Object.entries(policy.servers)) {
    const patterns = Object.keys(server.tools);
    for (let i = 0; i < patterns.length; i += 1) {
      const later = patterns[i];
      if (!later) continue;
      for (let j = 0; j < i; j += 1) {
        const earlier = patterns[j];
        if (!earlier) continue;
        if (toolCovers(earlier, later)) {
          issues.push({
            severity: "warning",
            message: `servers.${serverName}.tools.${later} is unreachable; ${earlier} comes first and covers it`,
          });
          break;
        }
      }
      const tool = server.tools[later];
      if (tool?.decision !== "allow") continue;
      const args = Object.values(tool.args ?? {});
      const open =
        policy.defaults.unknown_args === "allow" &&
        (args.length === 0 || args.every((rule) => unconstrained(rule)));
      if (open) {
        issues.push({
          severity: "warning",
          message: `servers.${serverName}.tools.${later} allows the tool without narrowing arguments`,
        });
      }
      for (const [argPath, rule] of Object.entries(tool.args ?? {})) {
        issues.push(...lintArg(serverName, later, argPath, rule, ctx));
      }
    }
  }
  return issues;
}

function lintArg(
  serverName: string,
  toolName: string,
  argPath: string,
  rule: ArgRule,
  ctx: PathContext,
): LintIssue[] {
  const where = `servers.${serverName}.tools.${toolName}.args.${argPath}`;
  const issues: LintIssue[] = [];
  if (rule.type === "hostname") {
    if (!rule.deny_ip_literals) {
      issues.push({ severity: "warning", message: `${where} sets deny_ip_literals: false` });
    }
    for (const pattern of rule.allow) {
      if (isUniversalHostPattern(pattern) || pattern.includes("**") || pattern.includes("/")) {
        issues.push({
          severity: "warning",
          message: `${where} hostname allow pattern "${pattern}" does not pin a DNS label`,
        });
      }
    }
  }
  if (rule.type === "url") {
    if (!rule.deny_private_ranges) {
      issues.push({ severity: "warning", message: `${where} sets deny_private_ranges: false` });
    }
    if (!rule.deny_userinfo) {
      issues.push({ severity: "warning", message: `${where} sets deny_userinfo: false` });
    }
    for (const pattern of rule.hosts) {
      if (isUniversalHostPattern(pattern) || pattern.includes("**")) {
        issues.push({
          severity: "warning",
          message: `${where} url host pattern "${pattern}" does not pin a DNS label`,
        });
      }
    }
  }
  if (rule.type === "path") {
    if (!rule.resolve_symlinks) {
      issues.push({ severity: "warning", message: `${where} does not resolve symlinks` });
    }
    for (const within of rule.within) {
      try {
        const root = expandPolicyPath(within, ctx);
        if (root === "/" || root === "") {
          issues.push({
            severity: "warning",
            message: `${where} within root "${within}" is the filesystem root`,
          });
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : "invalid within path";
        issues.push({ severity: "warning", message: `${where} ${message}` });
      }
    }
  }
  if (rule.type === "string" && unconstrained(rule)) {
    issues.push({
      severity: "warning",
      message: `${where} string rule does not constrain the value`,
    });
  }
  if (rule.type === "number" && rule.minimum === undefined && rule.maximum === undefined) {
    issues.push({ severity: "warning", message: `${where} number rule has no minimum or maximum` });
  }
  return issues;
}

function unconstrained(rule: ArgRule): boolean {
  if (rule.type === "string") {
    return (
      rule.allow === undefined &&
      rule.deny === undefined &&
      rule.pattern === undefined &&
      rule.min_length === undefined &&
      rule.max_length === undefined
    );
  }
  if (rule.type === "number") return rule.minimum === undefined && rule.maximum === undefined;
  return false;
}

function toolCovers(earlier: string, later: string): boolean {
  if (earlier === "*" || earlier === later) return true;
  if (!/[*?[]/u.test(earlier)) return false;
  const sample = /[*?[]/u.test(later) ? later.replaceAll("?", "x").replaceAll("*", "x") : later;
  return picomatch(earlier, { dot: true })(sample);
}
