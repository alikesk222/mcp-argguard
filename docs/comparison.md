# Comparison

Argument-level policy for MCP is not a new idea. Several open-source proxies already sit on the `tools/call` path and can reject an argument. mcp-argguard is one more implementation, with a narrower bet: CVE-linked policy packs, normalization before comparison, and a launch-flag classifier that `wrap` will enforce in v0.3.

MCP Shield Runtime is the closest existing project. It already covers stdio and Streamable HTTP, path roots, secret paths, metadata URLs, an approval flow, and a schema lockfile. mcp-argguard v0.1 does not. Choosing it over Shield only makes sense when you want the packs and the matcher semantics below, and you can accept stdio-only enforcement.

| Project                                                                                   | What it does                                                                                                      | Where mcp-argguard differs                                                                            |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [trailofbits/mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) | Pins server configuration and tool descriptions (trust on first use), quarantines responses, strips ANSI. Python. | Does not apply a policy to argument values.                                                           |
| [PolicyLayer/Intercept](https://github.com/PolicyLayer/Intercept/)                        | YAML argument rules, rate limits, spend accounting, tool hiding, default deny, hot reload.                        | A general rules engine. No CVE-class corpus of mock-server regressions.                               |
| [mcp-policy-gateway](https://github.com/Spuddy10345/mcp-policy-gateway)                   | Per-token argument policy, dry-run, a hash-chained audit log, a policy linter. Python.                            | An authorization reverse proxy. mcp-argguard is a local stdio wrap with no token model.               |
| [MCP Shield Runtime](https://github.com/samsgates/mcp-shield-runtime)                     | stdio and Streamable HTTP, path within/exclude, secret-path and metadata URL blocks, approval, schema lockfile.   | The closest project, and a broader gateway. mcp-argguard v0.1 is stdio-only and has no approval flow. |
| [sigma5667/mcp-airlock](https://github.com/sigma5667/mcp-airlock)                         | stdio proxy, regex checks on serialized JSON, budgets, a JSONL ledger.                                            | Regex on the serialized body. mcp-argguard canonicalizes hostname, URL, and path before matching.     |
| [docker/mcp-gateway](https://github.com/docker/mcp-gateway/)                              | Runs servers in containers, enables tools per profile, manages secrets.                                           | Isolation and tool on/off, not argument policy.                                                       |
| [sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy)                           | Bridges stdio to Streamable HTTP or SSE.                                                                          | No policy.                                                                                            |

## What v0.1 actually adds

- Policy packs tied to CVE-2026-18655, CVE-2026-75130, and CVE-2026-40933, each with cases that run against local mock MCP servers only.
- Matchers that normalize before they compare, with property tests against the WHATWG URL parser for hostnames.
- A pure launch classifier for embedded-code flags (`npx -c`, `node -e`, and the flags listed in the Flowise-class pack). `wrap` does not enforce it until v0.3. `test` and `explain --launch` do evaluate it, and they do not spawn the classified command.
- A small local core: three runtime dependencies (`yaml`, `zod`, `picomatch`), no telemetry, MIT license, and a JSON-RPC relay that does not depend on one MCP protocol revision.

## What v0.1 does not add

Rate limits, spend caps, tool hiding, hot reload, human approval, schema pinning, response quarantine, container isolation, and Streamable HTTP are out of this version. Sandboxing and LLM-based injection detection are out of scope for the project, not just deferred.

Descriptions in the table are summaries of public READMEs as of October 2026. They are not a feature matrix maintained by those projects.
