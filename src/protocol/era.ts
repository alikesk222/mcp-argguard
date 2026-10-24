import { isRecord } from "./jsonrpc.js";

export const PROTOCOL_2025_11_25 = "2025-11-25";
export const PROTOCOL_2026_07_28 = "2026-07-28";
const PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion";

export type ProtocolEra = "2025-11-25" | "2026-07-28" | "unknown";

/**
 * Observes which spec era a message claims. The relay does not branch on this:
 * unknown methods and fields are forwarded unchanged so both eras pass through.
 */
export function detectProtocolEra(message: Record<string, unknown>): ProtocolEra {
  if (message.method === "initialize" && isRecord(message.params)) {
    const version = message.params.protocolVersion;
    if (version === PROTOCOL_2026_07_28) return "2026-07-28";
    if (typeof version === "string" && version.startsWith("2025")) return "2025-11-25";
    if (typeof version === "string" && version.startsWith("2024")) return "2025-11-25";
  }
  const params = message.params;
  if (!isRecord(params)) return "unknown";
  const meta = params._meta;
  if (!isRecord(meta)) return "unknown";
  const claimed = meta[PROTOCOL_VERSION_META];
  if (claimed === PROTOCOL_2026_07_28) return "2026-07-28";
  if (typeof claimed === "string" && claimed.startsWith("2025")) return "2025-11-25";
  return "unknown";
}
