import type { Readable } from "node:stream";

export type NdjsonHandlers = {
  onLine: (line: string) => void;
  onOversize: () => void;
};

/**
 * Newline-delimited JSON framing used by MCP stdio.
 * A line, or a buffer waiting for a newline, that exceeds `maxBytes` is discarded
 * and reported. The payload is never forwarded by this helper.
 */
export function attachNdjson(stream: Readable, maxBytes: number, handlers: NdjsonHandlers): void {
  let buffer = Buffer.alloc(0);
  let discarding = false;

  stream.on("data", (chunk: Buffer | string) => {
    buffer = Buffer.concat([buffer, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
    for (;;) {
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) {
        if (buffer.length > maxBytes) {
          discarding = true;
          buffer = Buffer.alloc(0);
          handlers.onOversize();
        }
        return;
      }
      const lineBuffer = buffer.subarray(0, newline);
      buffer = buffer.subarray(newline + 1);
      if (discarding) {
        discarding = false;
        continue;
      }
      if (lineBuffer.length > maxBytes) {
        handlers.onOversize();
        continue;
      }
      const line = lineBuffer.toString("utf8").replace(/\r$/, "");
      if (line.length === 0) continue;
      handlers.onLine(line);
    }
  });
}
