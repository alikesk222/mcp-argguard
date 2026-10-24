#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { evaluateLaunch } from "../launch/guard.js";
import { DecisionLog, expandLogPath } from "../log/decision-log.js";
import { RESPONSIBLE_USE_NOTICE } from "../notice.js";
import { loadCases, runCases } from "../policy/cases.js";
import { evaluateCall } from "../policy/engine.js";
import { lintPolicy } from "../policy/lint.js";
import { loadPolicy } from "../policy/loader.js";
import { runStdioProxy } from "../transport/stdio.js";
import { VERSION } from "../version.js";

type Parsed =
  | { command: "help" }
  | { command: "version" }
  | {
      command: "wrap";
      policy: string;
      server: string;
      workspace?: string;
      log?: string;
      child: string[];
    }
  | { command: "validate"; policy: string; workspace?: string; strict: boolean }
  | { command: "test"; policy: string; cases: string; workspace?: string }
  | {
      command: "explain";
      policy: string;
      workspace?: string;
      server?: string;
      tool?: string;
      args?: string;
      launch?: string;
    };

const HELP = `mcp-argguard ${VERSION}

${RESPONSIBLE_USE_NOTICE}

Usage:
  mcp-argguard wrap --policy <file> --server <name> [--workspace <dir>] [--log <file>] -- <command> [args...]
  mcp-argguard validate --policy <file> [--workspace <dir>] [--strict]
  mcp-argguard test --policy <file> --cases <file> [--workspace <dir>]
  mcp-argguard explain --policy <file> --server <name> --tool <name> --args <json> [--workspace <dir>]
  mcp-argguard explain --policy <file> --launch <json>

wrap is a stdio JSON-RPC relay. It judges tools/call arguments and forwards every other
message unchanged, including a 2025-11-25 initialize handshake and 2026-07-28 stateless
calls. Unknown fields are not rewritten. Streamable HTTP is v0.2. Launch-flag enforcement
is v0.3; \`test\` and \`explain --launch\` evaluate those rules without starting a process.

--strict   validate exits 1 when a fail-open warning is present
`;

function main(): void {
  const major = Number(process.versions.node.split(".")[0]);
  if (!Number.isInteger(major) || major < 24) {
    process.stderr.write(
      `mcp-argguard requires Node.js 24 or newer (running ${process.versions.node}).\n`,
    );
    process.exit(1);
  }
  let parsed: Parsed;
  try {
    parsed = parseCli(process.argv.slice(2));
  } catch (error) {
    fail(error);
    return;
  }
  if (parsed.command === "help") {
    process.stdout.write(HELP);
    return;
  }
  if (parsed.command === "version") {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  try {
    if (parsed.command === "validate") validate(parsed);
    else if (parsed.command === "test") testCases(parsed);
    else if (parsed.command === "explain") explain(parsed);
    else wrap(parsed).catch(fail);
  } catch (error) {
    fail(error);
  }
}

function validate(parsed: Extract<Parsed, { command: "validate" }>): void {
  const loaded = loadPolicy(parsed.policy);
  const ctx = context(parsed.workspace);
  const issues = lintPolicy(loaded, ctx);
  process.stdout.write(`policy ok: ${loaded.filePath}\n`);
  for (const issue of issues) process.stdout.write(`${issue.severity}: ${issue.message}\n`);
  const warnings = issues.filter((issue) => issue.severity === "warning").length;
  if (parsed.strict && warnings > 0) process.exitCode = 1;
}

function testCases(parsed: Extract<Parsed, { command: "test" }>): void {
  const loaded = loadPolicy(parsed.policy);
  const cases = loadCases(parsed.cases);
  const ctx = context(parsed.workspace);
  const report = runCases(loaded, cases, ctx);
  for (const result of report.results) {
    const status = result.ok ? "PASS" : "FAIL";
    process.stdout.write(`${status} ${result.name} (${result.got}; ${result.detail})\n`);
  }
  process.stdout.write(`${report.passed} passed, ${report.failed} failed\n`);
  if (report.failed > 0) process.exitCode = 1;
}

function explain(parsed: Extract<Parsed, { command: "explain" }>): void {
  const loaded = loadPolicy(parsed.policy);
  const ctx = context(parsed.workspace);
  if (parsed.launch !== undefined) {
    const spec = parseLaunch(parsed.launch);
    const rules = loaded.policy.launch?.deny_inline_code;
    if (!rules) throw new Error("policy has no launch section");
    const verdict = evaluateLaunch(spec, rules);
    process.stdout.write(`decision: ${verdict.decision}\n`);
    process.stdout.write(`rule: ${verdict.ruleId}\n`);
    process.stdout.write(`reason: ${verdict.reason}\n`);
    process.stdout.write(`enforced_in: 0.3.0\n`);
    process.stdout.write("note: wrap does not enforce launch rules in v0.1\n");
    return;
  }
  if (!parsed.server || !parsed.tool || parsed.args === undefined) {
    throw new Error("explain requires --server, --tool, and --args, or --launch");
  }
  const args = parseJson(parsed.args, "--args");
  const verdict = evaluateCall(loaded, {
    server: parsed.server,
    tool: parsed.tool,
    args,
    workspace: ctx.workspace,
    home: ctx.home,
  });
  const enforced = verdict.decision === "allow" || loaded.policy.mode === "enforce";
  process.stdout.write(`decision: ${verdict.decision}\n`);
  process.stdout.write(`enforced: ${enforced ? "yes" : "no"}\n`);
  process.stdout.write(`mode: ${loaded.policy.mode}\n`);
  process.stdout.write(`rule: ${verdict.ruleId}\n`);
  process.stdout.write(`reason: ${verdict.reason}\n`);
  const names = Object.keys(verdict.normalized);
  if (names.length > 0) {
    process.stdout.write("normalized:\n");
    for (const name of names) {
      const normalized = verdict.normalized[name];
      if (normalized !== undefined) process.stdout.write(`  ${name}: ${normalized}\n`);
    }
  }
}

async function wrap(parsed: Extract<Parsed, { command: "wrap" }>): Promise<void> {
  const loaded = loadPolicy(parsed.policy);
  if (!loaded.policy.servers[parsed.server]) {
    throw new Error(`server "${parsed.server}" is not in the policy`);
  }
  const ctx = context(parsed.workspace);
  const [command, ...args] = parsed.child;
  if (!command) throw new Error("wrap requires a command after --");
  const logPath = expandLogPath(parsed.log ?? loaded.policy.log.path, ctx.home);
  const log = new DecisionLog(logPath, loaded);
  process.stderr.write(`mcp-argguard ${VERSION} — defensive MCP argument proxy\n`);
  process.stderr.write(`${RESPONSIBLE_USE_NOTICE}\n`);
  process.stderr.write(
    `mode=${loaded.policy.mode} server=${parsed.server} policy=${loaded.filePath}\n`,
  );
  const code = await runStdioProxy({
    loaded,
    serverName: parsed.server,
    command,
    args,
    workspace: ctx.workspace,
    home: ctx.home,
    log,
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
  });
  process.exit(code);
}

function context(workspace: string | undefined): { workspace: string; home: string } {
  const requested = workspace ?? process.env.ARGGUARD_WORKSPACE ?? process.cwd();
  return { workspace: path.resolve(requested), home: os.homedir() };
}

function parseCli(argv: string[]): Parsed {
  const split = argv.indexOf("--");
  const ours = split === -1 ? argv : argv.slice(0, split);
  const child = split === -1 ? [] : argv.slice(split + 1);
  if (ours.length === 0 || ours.includes("--help") || ours.includes("-h"))
    return { command: "help" };
  if (ours[0] === "--version" || ours[0] === "-V") return { command: "version" };
  const command = ours[0];
  if (command === "help") return { command: "help" };
  if (command === "version") return { command: "version" };
  const flags = readFlags(ours.slice(1));
  if (command === "wrap") {
    return {
      command: "wrap",
      policy: required(flags, "policy"),
      server: required(flags, "server"),
      workspace: flags.get("workspace"),
      log: flags.get("log"),
      child,
    };
  }
  if (command === "validate") {
    return {
      command: "validate",
      policy: required(flags, "policy"),
      workspace: flags.get("workspace"),
      strict: flags.has("strict"),
    };
  }
  if (command === "test") {
    return {
      command: "test",
      policy: required(flags, "policy"),
      cases: required(flags, "cases"),
      workspace: flags.get("workspace"),
    };
  }
  if (command === "explain") {
    return {
      command: "explain",
      policy: required(flags, "policy"),
      workspace: flags.get("workspace"),
      server: flags.get("server"),
      tool: flags.get("tool"),
      args: flags.get("args"),
      launch: flags.get("launch"),
    };
  }
  throw new Error(`unknown command "${command ?? ""}". See mcp-argguard --help`);
}

const KNOWN_FLAGS = new Set([
  "policy",
  "server",
  "workspace",
  "log",
  "cases",
  "tool",
  "args",
  "launch",
  "strict",
]);

function readFlags(argv: string[]): Map<string, string> {
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--strict") {
      flags.set("strict", "true");
      continue;
    }
    if (!token?.startsWith("--")) throw new Error(`unexpected argument "${token ?? ""}"`);
    const key = token.slice(2);
    if (!KNOWN_FLAGS.has(key)) throw new Error(`unknown flag --${key}`);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--"))
      throw new Error(`missing value for --${key}`);
    flags.set(key, value);
    i += 1;
  }
  return flags;
}

function required(flags: Map<string, string>, key: string): string {
  const value = flags.get(key);
  if (!value) throw new Error(`--${key} is required`);
  return value;
}

function parseJson(text: string, label: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseLaunch(text: string): { command: string; args: string[] } {
  const value = parseJson(text, "--launch");
  if (!isPlainRecord(value)) throw new Error("--launch must be a JSON object");
  const command = value.command;
  const args = value.args;
  const argsAreStrings = Array.isArray(args) && args.every((item) => typeof item === "string");
  if (typeof command !== "string" || !argsAreStrings) {
    throw new Error('--launch must be {"command": string, "args": string[]}');
  }
  return { command, args };
}

function fail(error: unknown): void {
  const message = error instanceof Error ? error.message : "unknown error";
  process.stderr.write(`mcp-argguard: ${message}\n`);
  process.exit(1);
}

const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(fs.realpathSync(entry)).href) {
  main();
}
