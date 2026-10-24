import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { describe, expect, it } from "vitest";
import { loadCases, runCases } from "../../src/policy/cases.js";
import { loadPolicy } from "../../src/policy/loader.js";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const cli = path.join(repoRoot, "dist/cli/main.js");
const recorder = path.join(repoRoot, "test/fixtures/mock-servers/recorder.ts");

const packs = ["cve-2026-18655", "cve-2026-75130", "cve-2026-40933"];

describe("cve class corpora", () => {
  it.each(packs)("%s cases match the pack", (pack) => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "argguard-case-"));
    fs.writeFileSync(path.join(workspace, "README.md"), "hello\n");
    fs.writeFileSync(path.join(workspace, ".env"), "CANARY=fake-canary-not-a-credential\n");
    const loaded = loadPolicy(path.join(repoRoot, "policies/cve-classes", `${pack}.yaml`));
    const cases = loadCases(path.join(repoRoot, "policies/cve-classes", `${pack}.cases.yaml`));
    const report = runCases(loaded, cases, { workspace });
    const failures = report.results.filter((result) => !result.ok);
    expect(failures, JSON.stringify(failures, null, 2)).toEqual([]);
  });
});

describe("cve class mock servers", () => {
  it("does not deliver the 75130 follow-up calls to the server", async () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "argguard-75130-"));
    fs.writeFileSync(path.join(workspace, "README.md"), "hello\n");
    fs.writeFileSync(path.join(workspace, ".env"), "CANARY=fake-canary-not-a-credential\n");
    const record = path.join(workspace, "record.jsonl");
    const log = path.join(workspace, "decisions.jsonl");
    let stderr = "";
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [
        cli,
        "wrap",
        "--policy",
        path.join(repoRoot, "policies/cve-classes/cve-2026-75130.yaml"),
        "--server",
        "workspace",
        "--workspace",
        workspace,
        "--log",
        log,
        "--",
        process.execPath,
        recorder,
      ],
      env: stringEnv({ ARGGUARD_RECORD: record }),
      stderr: "pipe",
    });
    transport.stderr?.on("data", (chunk: Buffer | string) => {
      stderr += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    });
    const client = new Client({ name: "argguard-regression", version: "0.0.0" });
    try {
      await client.connect(transport);
      const docs = await client.callTool({ name: "get_docs", arguments: {} });
      expect(JSON.stringify(docs)).toContain("Fixture documentation");
      expect(JSON.stringify(docs)).not.toContain(".env");

      await expectDenied(client, "read_file", { path: path.join(workspace, ".env") });
      await expectDenied(client, "fetch", { url: "https://exfil.test/collect" });
      await expectDenied(client, "delete_file", { path: path.join(workspace, "notes.txt") });

      const readme = await client.callTool({
        name: "read_file",
        arguments: { path: path.join(workspace, "README.md") },
      });
      expect(JSON.stringify(readme)).toContain("not-read");

      const tools = readRecord(record);
      expect(tools).toContain("get_docs");
      expect(tools).toContain("read_file");
      expect(tools).not.toContain("fetch");
      expect(tools).not.toContain("delete_file");
      const envReads = readRecordObjects(record).filter(
        (entry) => entry.tool === "read_file" && JSON.stringify(entry.args).includes(".env"),
      );
      expect(envReads).toEqual([]);
    } catch (error) {
      throw new Error(
        `${error instanceof Error ? error.message : "regression failed"}\n${stderr}`,
        {
          cause: error,
        },
      );
    } finally {
      await client.close();
    }
  });
});

async function expectDenied(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<void> {
  await expect(client.callTool({ name, arguments: args })).rejects.toThrow(/denied|mcp-argguard/i);
}

function readRecord(file: string): string[] {
  return readRecordObjects(file).map((entry) => entry.tool);
}

function readRecordObjects(file: string): Array<{ tool: string; args: unknown }> {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as { tool: string; args: unknown });
}

function stringEnv(extra: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value === "string") env[key] = value;
  }
  return { ...env, ...extra };
}
