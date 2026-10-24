import fs from "node:fs";
import os from "node:os";
import { parse } from "yaml";
import { z } from "zod";
import { evaluateLaunch, type LaunchDecision } from "../launch/guard.js";
import { evaluateCall, type PolicyDecision } from "./engine.js";
import type { LoadedPolicy } from "./loader.js";
import { WORKSPACE_PLACEHOLDER } from "./placeholders.js";

const CallCaseSchema = z.strictObject({
  server: z.string().min(1),
  tool: z.string().min(1),
  args: z.unknown().optional(),
});

const LaunchCaseSchema = z.strictObject({
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
});

const CaseSchema = z
  .strictObject({
    name: z.string().min(1),
    expect: z.enum(["allow", "deny"]),
    note: z.string().optional(),
    call: CallCaseSchema.optional(),
    launch: LaunchCaseSchema.optional(),
  })
  .superRefine((value, ctx) => {
    const count = Number(value.call !== undefined) + Number(value.launch !== undefined);
    if (count !== 1) {
      ctx.addIssue({ code: "custom", message: "case needs exactly one of call or launch" });
    }
  });

const CaseFileSchema = z.array(CaseSchema).min(1);

export type PolicyCase = z.output<typeof CaseSchema>;

export type CaseResult = {
  name: string;
  ok: boolean;
  expect: "allow" | "deny";
  got: "allow" | "deny";
  detail: string;
};

export function loadCases(filePath: string): PolicyCase[] {
  const text = fs.readFileSync(filePath, "utf8");
  let document: unknown;
  try {
    document = parse(text, { maxAliasCount: 0, uniqueKeys: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "YAML parse failed";
    throw new Error(`invalid cases YAML: ${message}`);
  }
  const parsed = CaseFileSchema.safeParse(document);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
      .join("; ");
    throw new Error(`invalid cases: ${detail}`);
  }
  return parsed.data;
}

export function runCases(
  loaded: LoadedPolicy,
  cases: readonly PolicyCase[],
  options: { workspace: string; home?: string },
): { passed: number; failed: number; results: CaseResult[] } {
  const home = options.home ?? os.homedir();
  const results = cases.map((entry) => runOne(loaded, entry, options.workspace, home));
  const failed = results.filter((result) => !result.ok).length;
  return { passed: results.length - failed, failed, results };
}

function runOne(
  loaded: LoadedPolicy,
  entry: PolicyCase,
  workspace: string,
  home: string,
): CaseResult {
  const verdict = entry.launch
    ? launchVerdict(loaded, entry.launch)
    : callVerdict(loaded, entry, workspace, home);
  const ok = verdict.decision === entry.expect;
  return {
    name: entry.name,
    ok,
    expect: entry.expect,
    got: verdict.decision,
    detail: `${verdict.ruleId}: ${verdict.reason}`,
  };
}

function callVerdict(
  loaded: LoadedPolicy,
  entry: PolicyCase,
  workspace: string,
  home: string,
): PolicyDecision {
  const call = entry.call;
  if (!call) {
    return {
      decision: "deny",
      ruleId: "cases/shape",
      reason: "case has no call",
      tool: null,
      method: "tools/call",
      normalized: {},
      args: undefined,
    };
  }
  return evaluateCall(loaded, {
    server: call.server,
    tool: call.tool,
    args: expandWorkspace(call.args, workspace),
    workspace,
    home,
  });
}

function launchVerdict(
  loaded: LoadedPolicy,
  launch: z.output<typeof LaunchCaseSchema>,
): LaunchDecision {
  const rules = loaded.policy.launch?.deny_inline_code ?? [];
  if (!loaded.policy.launch) {
    return {
      decision: "deny",
      ruleId: "launch/missing",
      reason: "policy has no launch section",
    };
  }
  return evaluateLaunch({ command: launch.command, args: launch.args }, rules);
}

function expandWorkspace(value: unknown, workspace: string): unknown {
  if (typeof value === "string") return value.replaceAll(WORKSPACE_PLACEHOLDER, workspace);
  if (Array.isArray(value)) return value.map((item) => expandWorkspace(item, workspace));
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) out[key] = expandWorkspace(child, workspace);
    return out;
  }
  return value;
}
