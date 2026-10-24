import os from "node:os";
import picomatch from "picomatch";
import { asRequest, isRecord, type JsonRpcRequest } from "../protocol/jsonrpc.js";
import {
  formatSegments,
  isPlainObject,
  type PathSegment,
  parseArgPath,
  pathRelation,
  patternPresent,
  walkArguments,
} from "./argpath.js";
import type { LoadedPolicy } from "./loader.js";
import { matchHostname } from "./matchers/hostname.js";
import { matchPath, type PathContext } from "./matchers/path.js";
import { matchNumber, matchString } from "./matchers/scalar.js";
import { findSecret } from "./matchers/secrets.js";
import { type MatchResult, matchUrl } from "./matchers/url.js";
import type { ArgRule, ToolRule } from "./schema.js";

export type PolicyDecision = {
  decision: "allow" | "deny";
  ruleId: string;
  reason: string;
  tool: string | null;
  method: string;
  normalized: Record<string, string>;
  /** In-memory only. The decision log hashes or redacts this; it is not a reason string. */
  args: unknown;
};

export type EvalContext = PathContext & {
  serverName: string;
};

export function evaluateRequest(
  loaded: LoadedPolicy,
  message: JsonRpcRequest,
  ctx: EvalContext,
): PolicyDecision {
  const method = message.method;
  if (method === "tools/call" && loaded.policy.methods?.["tools/call"] === "deny") {
    return decision(
      "deny",
      "methods/tools/call",
      "tools/call is denied",
      null,
      method,
      {},
      undefined,
    );
  }
  if (method !== "tools/call") {
    const explicit = loaded.policy.methods?.[method];
    const effect = explicit ?? loaded.policy.defaults.method;
    return decision(
      effect,
      explicit ? `methods/${method}` : "defaults/method",
      effect === "allow" ? "method is allowed" : `method ${method} is denied`,
      null,
      method,
      {},
      undefined,
    );
  }

  const params = message.params;
  if (!isRecord(params) || typeof params.name !== "string" || params.name.length === 0) {
    return decision(
      "deny",
      "tools/call/shape",
      "tools/call is missing a tool name",
      null,
      method,
      {},
      params,
    );
  }
  const tool = params.name;
  const args = toolArguments(params);
  const server = loaded.policy.servers[ctx.serverName];
  if (!server) {
    return decision(
      "deny",
      "servers/unknown",
      `server ${ctx.serverName} is not in the policy`,
      tool,
      method,
      {},
      args,
    );
  }

  const matched = findTool(server.tools, tool);
  if (!matched) {
    const effect = loaded.policy.defaults.tool;
    return decision(
      effect,
      "defaults/tool",
      effect === "allow"
        ? `tool ${tool} is allowed by the default`
        : `tool ${tool} is not allowed by policy`,
      tool,
      method,
      {},
      args,
    );
  }

  const base = `servers/${ctx.serverName}/tools/${matched.pattern}`;
  if (matched.rule.decision === "deny") {
    return decision(
      "deny",
      base,
      matched.rule.reason ?? `tool ${tool} is denied`,
      tool,
      method,
      {},
      args,
    );
  }

  if (!isPlainObject(args)) {
    return decision("deny", `${base}/args`, "arguments must be an object", tool, method, {}, args);
  }

  const checked = checkArguments(
    args,
    matched.rule,
    base,
    loaded.policy.defaults.unknown_args,
    ctx,
  );
  if (!checked.ok) {
    return decision("deny", checked.ruleId, checked.reason, tool, method, {}, args);
  }
  const secret = findSecret(args, loaded.secrets);
  if (secret) {
    return decision(
      "deny",
      `secrets/${secret}`,
      `value matched secret rule ${secret}`,
      tool,
      method,
      checked.normalized,
      args,
    );
  }
  return decision(
    "allow",
    base,
    matched.rule.reason ?? `tool ${tool} is allowed`,
    tool,
    method,
    checked.normalized,
    args,
  );
}

export function evaluateCall(
  loaded: LoadedPolicy,
  input: { server: string; tool: string; args?: unknown; workspace: string; home?: string },
): PolicyDecision {
  return evaluateRequest(
    loaded,
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: input.tool, arguments: input.args ?? {} },
    },
    {
      serverName: input.server,
      workspace: input.workspace,
      home: input.home ?? os.homedir(),
    },
  );
}

export function messageFromUnknown(value: unknown): JsonRpcRequest | undefined {
  return asRequest(value);
}

function toolArguments(params: Record<string, unknown>): unknown {
  if (!Object.hasOwn(params, "arguments") || params.arguments === undefined) return {};
  return params.arguments;
}

function findTool(
  tools: Record<string, ToolRule>,
  name: string,
): { pattern: string; rule: ToolRule } | undefined {
  for (const [pattern, rule] of Object.entries(tools)) {
    if (pattern === name || (/[*?[]/u.test(pattern) && picomatch(pattern, { dot: true })(name))) {
      return { pattern, rule };
    }
  }
  return undefined;
}

function checkArguments(
  args: Record<string, unknown>,
  rule: ToolRule,
  base: string,
  unknownArgs: "allow" | "deny",
  ctx: PathContext,
):
  | { ok: true; normalized: Record<string, string> }
  | { ok: false; ruleId: string; reason: string } {
  const compiled = Object.entries(rule.args ?? {}).map(([argPath, argRule]) => ({
    path: argPath,
    segments: parseArgPath(argPath),
    rule: argRule,
  }));
  for (const item of compiled) {
    if (item.rule.required && !patternPresent(args, item.segments)) {
      return {
        ok: false,
        ruleId: `${base}/arg/${item.path}`,
        reason: `missing required argument ${item.path}`,
      };
    }
  }

  const normalized: Record<string, string> = {};
  let failure: { ruleId: string; reason: string } | undefined;
  walkArguments(args, (segments: PathSegment[], node: unknown, container: boolean) => {
    if (failure) return;
    const exact = compiled.filter((item) => pathRelation(item.segments, segments) === "exact");
    const known = compiled.some((item) => {
      const relation = pathRelation(item.segments, segments);
      return relation === "exact" || relation === "ancestor";
    });
    if (!known) {
      if (unknownArgs === "deny") {
        failure = {
          ruleId: `${base}/unknown`,
          reason: `undeclared argument ${formatSegments(segments)}`,
        };
      }
      return;
    }
    if (!container && exact.length === 0) {
      failure = {
        ruleId: `${base}/arg`,
        reason: `argument ${formatSegments(segments)} does not match a declared path`,
      };
      return;
    }
    for (const item of exact) {
      const result = applyMatcher(node, item.rule, ctx);
      if (!result.ok) {
        failure = { ruleId: `${base}/arg/${item.path}`, reason: result.reason };
        return;
      }
      if (result.normalized !== undefined) normalized[formatSegments(segments)] = result.normalized;
    }
  });
  if (failure) return { ok: false, ...failure };
  return { ok: true, normalized };
}

function applyMatcher(value: unknown, rule: ArgRule, ctx: PathContext): MatchResult {
  switch (rule.type) {
    case "hostname":
      return matchHostname(value, rule);
    case "url":
      return matchUrl(value, rule);
    case "path":
      return matchPath(value, rule, ctx);
    case "string":
      return matchString(value, rule);
    case "number":
      return matchNumber(value, rule);
    default: {
      const neverRule: never = rule;
      void neverRule;
      return { ok: false, reason: "unknown argument rule" };
    }
  }
}

function decision(
  effect: "allow" | "deny",
  ruleId: string,
  reason: string,
  tool: string | null,
  method: string,
  normalized: Record<string, string>,
  args: unknown,
): PolicyDecision {
  return { decision: effect, ruleId, reason, tool, method, normalized, args };
}
