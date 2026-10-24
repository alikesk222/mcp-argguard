/**
 * Line sink for relay tests. Records each stdin line and answers requests.
 * It does not interpret MCP and does not open sockets.
 */
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const record = process.env.ARGGUARD_RECORD;
const lines = createInterface({ input: process.stdin });

lines.on("line", (line) => {
  if (record) appendFileSync(record, `${line}\n`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(line) as unknown;
  } catch {
    return;
  }
  if (typeof parsed !== "object" || parsed === null || !("id" in parsed)) return;
  const id = parsed.id;
  if (typeof id !== "string" && typeof id !== "number" && id !== null) return;
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result: { ok: true } })}\n`);
});
