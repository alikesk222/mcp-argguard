export const JSONRPC_VERSION = "2.0";

/** Policy denial. Inside the range the spec leaves to implementations. */
export const CODE_POLICY_DENY = -32001;
/** Message exceeded the configured byte limit. Avoids -32002 (historical resource-not-found). */
export const CODE_MESSAGE_TOO_LARGE = -32003;
/** Enforce mode refuses to forward when the decision log cannot be written. */
export const CODE_LOG_UNAVAILABLE = -32004;

export type JsonRpcId = string | number | null;

export type JsonRpcRequest = {
  jsonrpc?: unknown;
  id?: unknown;
  method: string;
  params?: unknown;
};

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function requestId(message: Record<string, unknown>): JsonRpcId | undefined {
  if (!Object.hasOwn(message, "id")) return undefined;
  const id = message.id;
  if (typeof id === "string" || typeof id === "number" || id === null) return id;
  return null;
}

export function jsonRpcError(
  id: JsonRpcId,
  code: number,
  message: string,
  data?: Record<string, unknown>,
): string {
  const error: Record<string, unknown> = { code, message };
  if (data) error.data = data;
  return JSON.stringify({ jsonrpc: JSONRPC_VERSION, id, error });
}

export function asRequest(value: unknown): JsonRpcRequest | undefined {
  if (!isRecord(value)) return undefined;
  if (typeof value.method !== "string") return undefined;
  return value as JsonRpcRequest;
}
