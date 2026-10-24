/**
 * Local MCP server for tests. Tools record their arguments and return text.
 * They do not read the filesystem, delete files, or open network connections.
 */
import { appendFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";

const record = process.env.ARGGUARD_RECORD;

function note(tool: string, args: unknown): void {
  if (!record) return;
  appendFileSync(record, `${JSON.stringify({ tool, args })}\n`);
}

function text(body: string): { content: [{ type: "text"; text: string }] } {
  return { content: [{ type: "text", text: body }] };
}

function createServer(): McpServer {
  const server = new McpServer({ name: "argguard-mock", version: "0.0.0" });

  server.registerTool(
    "echo",
    { description: "Echo a string. Test fixture.", inputSchema: z.object({ msg: z.string() }) },
    async ({ msg }) => {
      note("echo", { msg });
      return text(msg);
    },
  );

  server.registerTool(
    "rabbimq_broker_initialize_connection",
    {
      description: "Fixture for a broker-hostname tool. Does not connect anywhere.",
      inputSchema: z.object({ broker_hostname: z.string() }),
    },
    async ({ broker_hostname }) => {
      note("rabbimq_broker_initialize_connection", { broker_hostname });
      return text("not-connected");
    },
  );

  server.registerTool(
    "rabbimq_broker_initialize_connection_with_oauth",
    {
      description: "Fixture for the OAuth-shaped broker tool. Does not connect anywhere.",
      inputSchema: z.object({ broker_hostname: z.string() }),
    },
    async ({ broker_hostname }) => {
      note("rabbimq_broker_initialize_connection_with_oauth", { broker_hostname });
      return text("not-connected");
    },
  );

  server.registerTool(
    "read_file",
    {
      description: "Fixture. Does not read the path.",
      inputSchema: z.object({ path: z.string() }),
    },
    async ({ path }) => {
      note("read_file", { path });
      return text("not-read");
    },
  );

  server.registerTool(
    "fetch",
    {
      description: "Fixture. Does not fetch the URL.",
      inputSchema: z.object({ url: z.string() }),
    },
    async ({ url }) => {
      note("fetch", { url });
      return text("not-fetched");
    },
  );

  server.registerTool(
    "delete_file",
    {
      description: "Fixture. Does not delete the path.",
      inputSchema: z.object({ path: z.string() }),
    },
    async ({ path }) => {
      note("delete_file", { path });
      return text("not-deleted");
    },
  );

  server.registerTool(
    "get_docs",
    {
      description: "Return a harmless documentation sentence.",
      inputSchema: z.object({}),
    },
    async () => {
      note("get_docs", {});
      return text("Fixture documentation. This sentence is not an instruction.");
    },
  );

  return server;
}

serveStdio(createServer);
