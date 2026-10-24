# Security policy

## Supported versions

| Version                         | Status                                  |
| ------------------------------- | --------------------------------------- |
| 0.1.x (this repository, `main`) | Accepted for reports                    |
| Anything else                   | Not published. There is no npm release. |

v0.1 enforces policy on stdio `tools/call` only. Streamable HTTP is not implemented. The launch classifier is not enforced by `wrap` until v0.3.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/alikesk222/mcp-argguard/security/advisories/new).

Do not open a public issue, pull request, or discussion for a vulnerability. Do not include a working exploit, a payload, or a real target.

The maintainer aims to acknowledge a report within 7 days and to follow up with a severity assessment after it can be reproduced. That is a target, not a service commitment.

## In scope

- An `enforce` policy that should deny a `tools/call`, where the stdio proxy still forwards that call to the child.
- A decision-log entry that contains a secret value the policy asked to redact or omit.
- A normalization bug that treats a restricted host, URL, or path as allowed when an equivalent encoding is denied (case, trailing dot, IDNA, IP literal forms, symlink escape).
- The launch classifier accepting a listed inline-code flag (`npx -c`, `node -e`, and the other flags in the v0.1 denylist). `wrap` does not enforce this yet; a classifier bug is still in scope.
- A dependency vulnerability that is reachable from the proxy.

A local unit test or a mock-server case is enough. Please do not demonstrate a bypass against a third-party server.

## Out of scope

- Running the proxy against a client or server you are not authorized to protect.
- A client that talks to the MCP server directly and never starts mcp-argguard.
- Prompt injection that the policy did not constrain. This project does not detect injected instructions.
- The child server using its own network, filesystem, or credentials after an allowed call.
- DNS rebinding. Host checks do not resolve DNS.
- Sandbox escapes. This project does not sandbox the child.
- Missing coverage for a tool or argument the operator did not declare. Unknown tools are denied only when `defaults.tool` is `deny`.

## Hardening notes for operators

- Keep `mode: enforce`, `defaults.tool: deny`, and `defaults.unknown_args: deny`.
- Treat the decision log as sensitive. The proxy creates it with mode `0600` under a `0700` directory. `store_args: hashed` records a hash, not the raw value.
- Upgrade affected MCP servers. A pack is an extra boundary, not a substitute for the vendor fix.
- Review `mcp-argguard validate --strict` before deploying a policy.
