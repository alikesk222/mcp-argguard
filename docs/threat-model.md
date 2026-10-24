# Threat model

mcp-argguard is a local boundary on MCP `tools/call` arguments. An operator writes a policy. A client talks stdio JSON-RPC to the proxy. The proxy talks stdio JSON-RPC to one child server. The policy file is trusted. The client's messages are not.

## What v0.1 is for

- Stopping a `tools/call` whose tool is not allowed, whose argument is not declared, or whose declared argument fails a hostname, URL, path, string, or number rule.
- Stopping secret-shaped strings (for example a private-key banner, or a caller-supplied access-key pattern) anywhere in the argument tree, including object keys.
- Giving the operator a JSONL decision log of those calls, with arguments hashed or redacted.
- Letting the operator watch the same decisions in `monitor` mode without blocking, before switching to `enforce`.
- Checking, offline, whether a stdio launch command uses a listed inline-code flag. v0.1 does not block the spawn.

The three CVE-class packs are examples of that boundary:

- CVE-2026-18655: a broker hostname that is not on an example allowlist, so a connection tool cannot be pointed at an arbitrary host through the argument named in the advisory.
- CVE-2026-75130: later tool calls that read a `.env` path, fetch a host outside an allowlist, or delete a file. The pack does not detect the instruction text that would cause those calls.
- CVE-2026-40933: a denylist of inline-code flags on `npx`, `node`, `python`, `python3`, `bash`, and `sh`. The classifier does not start a process. `wrap` does not apply it until v0.3.

## What v0.1 is not for

- Detecting prompt injection, hidden instructions, or malicious tool descriptions. There is no model in the path.
- Sandboxing the child. An allowed call runs with the child's privileges. If the server then opens its own network connection, this proxy does not see it.
- Replacing a vendor patch. Packs are an extra layer for a server you still have to upgrade.
- Authenticating the client or the server.
- Filtering Streamable HTTP. `src/transport/http.ts` throws. Header and body disagreement is a v0.2 concern.
- DNS rebinding. Hostnames are not resolved. A name that is public in DNS and private in a later lookup is out of scope. IP literals, IPv4-mapped IPv6, and the metadata names `metadata.google.internal` and `metadata.goog` are in scope for URL rules with `deny_private_ranges` (the default).
- Policy for `resources/read` URIs or prompt bodies, beyond a whole-method allow or deny. `defaults.method` is allow so `initialize`, `tools/list`, and `server/discover` keep working.
- Stopping someone from editing the client config and removing the proxy. A config linter is v0.3 (`lint-config`).

## Trust boundaries

| Boundary     | Assumption                                                                                                                              |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| Policy YAML  | Trusted. Whoever can write it chooses what is allowed. `validate` warns on world-writable files and fail-open defaults.                 |
| Client stdin | Untrusted JSON-RPC. Oversized frames and batches are rejected. Allowed `tools/call` lines are forwarded as the original bytes.          |
| Child stdout | Framed and forwarded. Tool results are not judged. Invalid JSON or an oversized server line closes the child.                           |
| Child stderr | Copied to the proxy stderr. It is not parsed.                                                                                           |
| Decision log | Sensitive. Mode `0600`. Reasons are not supposed to echo a matched secret. `store_args: redacted` can still reveal the shape of a call. |
| Launch argv  | Visible to `wrap`. In v0.1 a matching deny rule produces a stderr warning and the child still starts.                                   |

## Residual risk

A bypass that encodes the same host, URL, or path in another form is the failure this design is aimed at, and it remains possible. Matchers canonicalize first and deny on parse failure. Property tests compare hostname normalization with the WHATWG URL parser. They are not a proof.

Unknown arguments are denied only when `defaults.unknown_args` is `deny`. A policy that allows a tool with no argument rules and `unknown_args: allow` allows the body through, then still runs the secrets scan.

`monitor` mode records a deny and forwards the call. That is intentional and it is not enforcement.
