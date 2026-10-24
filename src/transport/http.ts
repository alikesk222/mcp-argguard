/**
 * Streamable HTTP reverse proxy is a v0.2 deliverable.
 * v0.1 exposes this function so callers fail closed instead of assuming HTTP is filtered.
 */
export function createStreamableHttpProxy(): never {
  throw new Error(
    "Streamable HTTP reverse proxy is not implemented in mcp-argguard v0.1. It is planned for v0.2.",
  );
}
