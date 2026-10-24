import { type ChildProcess, execFile, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client, ProtocolError } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { afterEach, describe, expect, it } from "vitest";
import { RESPONSIBLE_USE_NOTICE } from "../../src/notice.js";

const execFileAsync = promisify(execFile);
const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const cli = path.join(repoRoot, "dist/cli/main.js");
const recorder = path.join(repoRoot, "test/fixtures/mock-servers/recorder.ts");
const sink = path.join(repoRoot, "test/fixtures/mock-servers/sink.ts");
const brokerPolicy = path.join(repoRoot, "policies/cve-classes/cve-2026-18655.yaml");

const children: ChildProcess[] = [];

afterEach(async () => {
  for (const child of children.splice(0)) {
    if (!child.killed) child.kill("SIGTERM");
  }
});

function stringEnv(extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value === "string") env[key] = value;
  }
  return { ...env, ...extra };
}

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "argguard-it-"));
}

async function connectMcp(options: {
  policy: string;
  server: string;
  workspace: string;
  record: string;
  log: string;
  era: "legacy" | "2026-07-28";
}): Promise<{ client: Client; stderr: () => string; close: () => Promise<void> }> {
  let stderr = "";
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      cli,
      "wrap",
      "--policy",
      options.policy,
      "--server",
      options.server,
      "--workspace",
      options.workspace,
      "--log",
      options.log,
      "--",
      process.execPath,
      recorder,
    ],
    env: stringEnv({ ARGGUARD_RECORD: options.record }),
    stderr: "pipe",
  });
  transport.stderr?.on("data", (chunk: Buffer | string) => {
    stderr += typeof chunk === "string" ? chunk : chunk.toString("utf8");
  });
  const client = new Client(
    { name: "argguard-test", version: "0.0.0" },
    options.era === "legacy" ? undefined : { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  try {
    await client.connect(transport);
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : "connect failed"}\n${stderr}`, {
      cause: error,
    });
  }
  return {
    client,
    stderr: () => stderr,
    close: async () => {
      await client.close();
    },
  };
}

function recorded(file: string): string[] {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => (JSON.parse(line) as { tool: string }).tool);
}

describe("sdk clients through the proxy", () => {
  it.each(["legacy", "2026-07-28"] as const)(
    "forwards an allow and withholds a deny (%s)",
    async (era) => {
      const dir = tempDir();
      const record = path.join(dir, "record.jsonl");
      const session = await connectMcp({
        policy: brokerPolicy,
        server: "amazon-mq",
        workspace: dir,
        record,
        log: path.join(dir, "decisions.jsonl"),
        era,
      });
      try {
        const tools = await session.client.listTools();
        expect(tools.tools.map((tool) => tool.name)).toContain(
          "rabbimq_broker_initialize_connection",
        );

        const allowed = await session.client.callTool({
          name: "rabbimq_broker_initialize_connection",
          arguments: { broker_hostname: "b-1.mq.eu-central-1.amazonaws.com" },
        });
        expect(JSON.stringify(allowed)).toContain("not-connected");
        expect(recorded(record)).toContain("rabbimq_broker_initialize_connection");

        const before = recorded(record).length;
        await expect(
          session.client.callTool({
            name: "rabbimq_broker_initialize_connection",
            arguments: { broker_hostname: "broker.attacker.example" },
          }),
        ).rejects.toBeInstanceOf(ProtocolError);
        expect(recorded(record)).toHaveLength(before);

        const log = fs.readFileSync(path.join(dir, "decisions.jsonl"), "utf8");
        expect(log).toContain('"decision":"deny"');
        expect(log).toContain("broker.attacker.example");
        expect(log).not.toContain("AKIA");
      } finally {
        await session.close();
      }
    },
  );

  it("monitor mode forwards a call the policy would deny", async () => {
    const dir = tempDir();
    const policy = path.join(dir, "policy.yaml");
    fs.writeFileSync(
      policy,
      fs.readFileSync(brokerPolicy, "utf8").replace("mode: enforce", "mode: monitor"),
    );
    const record = path.join(dir, "record.jsonl");
    const session = await connectMcp({
      policy,
      server: "amazon-mq",
      workspace: dir,
      record,
      log: path.join(dir, "decisions.jsonl"),
      era: "legacy",
    });
    try {
      const result = await session.client.callTool({
        name: "rabbimq_broker_initialize_connection",
        arguments: { broker_hostname: "broker.attacker.example" },
      });
      expect(JSON.stringify(result)).toContain("not-connected");
      expect(recorded(record)).toContain("rabbimq_broker_initialize_connection");
      const log = fs.readFileSync(path.join(dir, "decisions.jsonl"), "utf8");
      expect(log).toContain('"decision":"deny"');
      expect(log).toContain('"enforced":false');
    } finally {
      await session.close();
    }
  });
});

describe("raw relay", () => {
  it("rejects an oversized line and still serves the next call", async () => {
    const dir = tempDir();
    const policy = path.join(dir, "policy.yaml");
    const record = path.join(dir, "record.jsonl");
    fs.writeFileSync(
      policy,
      `
version: 1
mode: enforce
limits:
  max_message_bytes: 128
defaults:
  tool: deny
  unknown_args: deny
servers:
  sink:
    tools:
      echo:
        decision: allow
        args:
          msg:
            type: string
            max_length: 40
`,
    );
    const child = spawn(
      process.execPath,
      [
        cli,
        "wrap",
        "--policy",
        policy,
        "--server",
        "sink",
        "--log",
        path.join(dir, "decisions.jsonl"),
        "--",
        process.execPath,
        sink,
      ],
      { env: stringEnv({ ARGGUARD_RECORD: record }), stdio: ["pipe", "pipe", "pipe"] },
    );
    children.push(child);
    const lines = new LineQueue(child);

    const oversize = await lines.request({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "echo", arguments: { msg: "x".repeat(200) } },
    });
    expect(JSON.parse(oversize).error.code).toBe(-32003);
    expect(fs.existsSync(record) ? fs.readFileSync(record, "utf8") : "").not.toContain("xxxx");

    const ok = await lines.request({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "echo", arguments: { msg: "hi" } },
    });
    expect(JSON.parse(ok).result.ok).toBe(true);
    expect(fs.readFileSync(record, "utf8")).toContain('"msg":"hi"');

    const bad = await lines.requestText("{");
    expect(JSON.parse(bad).error.code).toBe(-32700);

    const passed = await lines.request({
      jsonrpc: "2.0",
      id: 3,
      method: "server/discover",
      params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } },
    });
    expect(JSON.parse(passed).result.ok).toBe(true);
    child.kill("SIGTERM");
  });
});

describe("cli", () => {
  it("prints the responsible-use notice and runs validate, test, and explain", async () => {
    const help = await execFileAsync(process.execPath, [cli, "--help"], { encoding: "utf8" });
    expect(help.stdout).toContain(RESPONSIBLE_USE_NOTICE);

    const starter = path.join(repoRoot, "policies/starter/fetch.yaml");
    const validated = await execFileAsync(
      process.execPath,
      [cli, "validate", "--policy", starter, "--strict"],
      { encoding: "utf8" },
    );
    expect(validated.stdout).toContain("policy ok");

    const tested = await execFileAsync(
      process.execPath,
      [
        cli,
        "test",
        "--policy",
        brokerPolicy,
        "--cases",
        path.join(repoRoot, "policies/cve-classes/cve-2026-18655.cases.yaml"),
      ],
      { encoding: "utf8" },
    );
    expect(tested.stdout).toContain("0 failed");

    const explained = await execFileAsync(
      process.execPath,
      [
        cli,
        "explain",
        "--policy",
        brokerPolicy,
        "--server",
        "amazon-mq",
        "--tool",
        "rabbimq_broker_initialize_connection",
        "--args",
        JSON.stringify({ broker_hostname: "broker.attacker.example" }),
      ],
      { encoding: "utf8" },
    );
    expect(explained.stdout).toContain("decision: deny");
  });
});

class LineQueue {
  private buffer = "";
  private readonly waiters: Array<(line: string) => void> = [];

  constructor(private readonly child: ChildProcess) {
    this.child.stdout?.setEncoding("utf8");
    this.child.stdout?.on("data", (chunk: string) => {
      this.buffer += chunk;
      this.drain();
    });
  }

  request(message: unknown): Promise<string> {
    return this.requestText(JSON.stringify(message));
  }

  requestText(line: string): Promise<string> {
    const next = new Promise<string>((resolve) => {
      this.waiters.push(resolve);
    });
    this.child.stdin?.write(`${line}\n`);
    return next;
  }

  private drain(): void {
    let newline = this.buffer.indexOf("\n");
    while (newline !== -1) {
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      this.waiters.shift()?.(line);
      newline = this.buffer.indexOf("\n");
    }
  }
}
