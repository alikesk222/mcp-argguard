import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { evaluateLaunch } from "../launch/guard.js";
import type { DecisionLog } from "../log/decision-log.js";
import {
  type EvalContext,
  evaluateRequest,
  messageFromUnknown,
  type PolicyDecision,
} from "../policy/engine.js";
import type { LoadedPolicy } from "../policy/loader.js";
import { detectProtocolEra } from "../protocol/era.js";
import { attachNdjson } from "../protocol/framing.js";
import {
  CODE_LOG_UNAVAILABLE,
  CODE_MESSAGE_TOO_LARGE,
  CODE_POLICY_DENY,
  isRecord,
  jsonRpcError,
  requestId,
} from "../protocol/jsonrpc.js";

export type StdioProxyOptions = {
  loaded: LoadedPolicy;
  serverName: string;
  command: string;
  args: string[];
  workspace: string;
  home: string;
  log: DecisionLog;
  stdin: Readable;
  stdout: Writable;
  stderr: Writable;
};

/**
 * Byte-preserving JSON-RPC relay. Only `tools/call` (and configured methods) are judged.
 * Allowed messages are forwarded as the original line. Denied messages are not written to the child.
 * Launch rules are not enforced here (v0.3).
 */
export function runStdioProxy(options: StdioProxyOptions): Promise<number> {
  const { loaded, stderr } = options;
  if (loaded.policy.launch) {
    const verdict = evaluateLaunch(
      { command: options.command, args: options.args },
      loaded.policy.launch.deny_inline_code,
    );
    if (verdict.decision === "deny") {
      stderr.write(
        `mcp-argguard: launch guard is not enforced until v0.3 (${verdict.reason}). The child process will still be started.\n`,
      );
    } else {
      stderr.write("mcp-argguard: launch rules are loaded but not enforced until v0.3.\n");
    }
  }

  return new Promise((resolve) => {
    let settled = false;
    const finish = (code: number): void => {
      if (settled) return;
      settled = true;
      resolve(code);
    };

    const child = spawn(options.command, options.args, {
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });
    child.once("error", (error: NodeJS.ErrnoException) => {
      stderr.write(`mcp-argguard: failed to start ${options.command}: ${error.message}\n`);
      finish(1);
    });
    const streams = child as ChildProcessWithoutNullStreams;
    streams.stderr.on("data", (chunk: Buffer) => {
      stderr.write(chunk);
    });

    const maxBytes = loaded.policy.limits.max_message_bytes;
    const ctx: EvalContext = {
      serverName: options.serverName,
      workspace: options.workspace,
      home: options.home,
    };

    attachNdjson(options.stdin, maxBytes, {
      onLine: (line) => handleClientLine(line),
      onOversize: () => {
        writeClient(
          jsonRpcError(null, CODE_MESSAGE_TOO_LARGE, "mcp-argguard rejected an oversized message"),
        );
      },
    });
    attachNdjson(streams.stdout, maxBytes, {
      onLine: (line) => handleServerLine(line),
      onOversize: () => {
        stderr.write("mcp-argguard: server message exceeded max_message_bytes; closing\n");
        streams.kill("SIGTERM");
        finish(1);
      },
    });

    options.stdin.on("end", () => {
      if (!streams.stdin.destroyed) streams.stdin.end();
    });
    options.stdin.on("error", () => finish(1));
    streams.on("close", (code) => finish(code ?? 1));

    function writeClient(line: string): void {
      options.stdout.write(`${line}\n`);
    }

    function writeChild(line: string): void {
      if (settled || streams.stdin.destroyed) return;
      streams.stdin.write(`${line}\n`);
    }

    function handleServerLine(line: string): void {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line) as unknown;
      } catch {
        stderr.write("mcp-argguard: server sent invalid JSON; closing\n");
        streams.kill("SIGTERM");
        finish(1);
        return;
      }
      if (Array.isArray(parsed) || !isRecord(parsed)) {
        stderr.write("mcp-argguard: server sent a non-object message; closing\n");
        streams.kill("SIGTERM");
        finish(1);
        return;
      }
      writeClient(line);
    }

    function handleClientLine(line: string): void {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line) as unknown;
      } catch {
        writeClient(jsonRpcError(null, -32700, "Parse error"));
        return;
      }
      if (Array.isArray(parsed)) {
        writeClient(jsonRpcError(null, -32600, "mcp-argguard rejected a JSON-RPC batch"));
        return;
      }
      const request = messageFromUnknown(parsed);
      if (!request || !isRecord(parsed)) {
        writeChild(line);
        return;
      }

      const started = performance.now();
      let verdict: PolicyDecision;
      try {
        verdict = evaluateRequest(loaded, request, ctx);
      } catch (error) {
        const name = error instanceof Error ? error.name : "Error";
        stderr.write(`mcp-argguard: policy evaluation failed (${name})\n`);
        const id = requestId(parsed);
        if (id !== undefined) {
          writeClient(
            jsonRpcError(
              id,
              CODE_POLICY_DENY,
              "mcp-argguard denied the request: policy evaluation failed",
            ),
          );
        }
        return;
      }
      const latency = performance.now() - started;
      const block = verdict.decision === "deny" && loaded.policy.mode === "enforce";
      const enforced = verdict.decision === "allow" || loaded.policy.mode === "enforce";
      const shouldLog = verdict.method === "tools/call" || verdict.decision === "deny";
      let logged = true;
      if (shouldLog) {
        try {
          options.log.write({
            server: options.serverName,
            method: verdict.method,
            tool: verdict.tool,
            decision: verdict.decision,
            enforced,
            ruleId: verdict.ruleId,
            reason: verdict.reason,
            latencyMs: latency,
            protocol: (() => {
              const era = detectProtocolEra(parsed);
              return era === "unknown" ? null : era;
            })(),
            args: verdict.args,
          });
        } catch (error) {
          logged = false;
          const message = error instanceof Error ? error.message : "log write failed";
          stderr.write(`mcp-argguard: decision log write failed: ${message}\n`);
        }
      }
      const id = requestId(parsed);
      if (!logged && loaded.policy.mode === "enforce") {
        if (id !== undefined) {
          const code = verdict.decision === "deny" ? CODE_POLICY_DENY : CODE_LOG_UNAVAILABLE;
          const message =
            verdict.decision === "deny"
              ? denyMessage(verdict.method, verdict.tool, verdict.reason)
              : "mcp-argguard could not write the decision log";
          writeClient(
            jsonRpcError(id, code, message, {
              origin: "mcp-argguard",
              decision: verdict.decision,
              rule_id: verdict.ruleId,
              server: options.serverName,
              tool: verdict.tool,
            }),
          );
        }
        return;
      }
      if (block) {
        if (id !== undefined) {
          writeClient(
            jsonRpcError(
              id,
              CODE_POLICY_DENY,
              denyMessage(verdict.method, verdict.tool, verdict.reason),
              {
                origin: "mcp-argguard",
                decision: "deny",
                rule_id: verdict.ruleId,
                server: options.serverName,
                tool: verdict.tool,
              },
            ),
          );
        }
        return;
      }
      writeChild(line);
    }
  });
}

function denyMessage(method: string, tool: string | null, reason: string): string {
  const subject = tool ? `${method} ${tool}` : method;
  return `mcp-argguard denied ${subject}: ${reason}`;
}
