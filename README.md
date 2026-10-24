# mcp-argguard

Defensive runtime policy proxy for MCP. It sits on stdio between a client and a server and applies a per-tool argument policy to `tools/call`.

**mcp-argguard is a defensive control layer, not a security guarantee and not an exploit tool. Use it only on MCP clients and servers you are authorized to protect. It does not ship attack payloads, and it does not replace patches: upgrade affected servers.**

The same notice is printed by `mcp-argguard --help` and on the `wrap` startup banner (stderr). See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

This package is not published to npm or any other registry. `npm publish` is disabled. Install from a git checkout and run the compiled CLI.

## v0.1

v0.1 is stdio only. The core is a newline-delimited JSON-RPC relay, not the MCP SDK's high-level server, so a 2025-11-25 `initialize` handshake and stateless 2026-07-28 traffic both pass through. The SDK is a development dependency for types, mock servers, and tests.

In this version:

- `tools/call` is allowed only when the selected server profile has a matching tool rule. The default for an unknown tool is deny. The default for an argument the rule does not mention is deny.
- `mode: enforce` drops the denied line and returns a JSON-RPC error. `mode: monitor` logs the same deny and still forwards the line.
- Hostname, URL, and file-path rules normalize the value and then compare. They are not regexes over the raw string.
- Secret patterns (private-key banners, access-key shapes, `.env` paths) can deny a call.
- Decisions are appended to a JSONL log, mode `0600`.
- `validate`, `test`, and `explain` inspect a policy without starting a server.
- A launch-flag classifier recognizes embedded-code flags such as `npx -c` and `node -e`. `wrap` does not enforce it until v0.3. It warns and still starts the child.

Streamable HTTP is v0.2. Launch enforcement and `lint-config` are v0.3. Sandboxing and LLM-based injection detection are out of scope. See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md).

## Requirements

Node.js 24 LTS or newer. The CLI exits on older Node versions.

## Install

```sh
git clone https://github.com/alikesk222/mcp-argguard.git
cd mcp-argguard
npm ci --ignore-scripts
npm run build
node dist/cli/main.js --help
```

## Quick start

Check a starter policy, then ask the engine about one call. `explain` exits 0 for both allow and deny and prints the decision.

```sh
node dist/cli/main.js validate --policy policies/starter/filesystem.yaml --strict
node dist/cli/main.js explain \
  --policy policies/starter/filesystem.yaml \
  --server filesystem \
  --tool read_file \
  --args "{\"path\":\"/tmp/not-in-the-workspace\"}"
```

Run the CVE-class cases. They do not open a socket and they do not start the classified launch commands.

```sh
node dist/cli/main.js test \
  --policy policies/cve-classes/cve-2026-18655.yaml \
  --cases policies/cve-classes/cve-2026-18655.cases.yaml
```

Wrap a server you are authorized to run. Everything after `--` is the child process (`shell: false`). The proxy banner goes to stderr.

```sh
node dist/cli/main.js wrap \
  --policy policies/starter/filesystem.yaml \
  --server filesystem \
  --workspace "$PWD" \
  --log "$PWD/.argguard/decisions.jsonl" \
  -- node /path/to/your-mcp-server.js
```

A client config points `command` at Node and this CLI, and only then at the real server:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": [
        "/absolute/path/to/mcp-argguard/dist/cli/main.js",
        "wrap",
        "--policy",
        "/absolute/path/to/mcp-argguard/policies/starter/filesystem.yaml",
        "--server",
        "filesystem",
        "--workspace",
        "/absolute/path/to/the/project",
        "--",
        "node",
        "/absolute/path/to/your-mcp-server.js"
      ]
    }
  }
}
```

## Policy example

`mode` is required. Unknown tools and unknown arguments default to deny. `${workspace}` is expanded in path roots, not in argument values. The full field list is [docs/policy-reference.md](docs/policy-reference.md). A combined file lives at [policies/examples/policy.example.yaml](policies/examples/policy.example.yaml).

```yaml
version: 1
mode: enforce
defaults:
  tool: deny
  unknown_args: deny
log:
  path: ~/.argguard/decisions.jsonl
  store_args: hashed
servers:
  filesystem:
    tools:
      read_file:
        decision: allow
        args:
          path:
            type: path
            within: ["${workspace}"]
            deny: ["**/.env*", "**/.ssh/**", "**/*.pem", "**/*.key"]
            resolve_symlinks: true
      "delete_*":
        decision: deny
        reason: "deletion is disabled in this profile"
```

Starter profiles: [policies/starter/filesystem.yaml](policies/starter/filesystem.yaml), [policies/starter/fetch.yaml](policies/starter/fetch.yaml), [policies/starter/shell.yaml](policies/starter/shell.yaml).

## CVE-class packs

Each pack is an example boundary plus a regression corpus. Tests use local mock MCP servers. They do not contain exploit text and they do not contact a network.

### CVE-2026-18655

Amazon MQ MCP hostname credential leak, in versions before 2.0.24. [GHSA-xwj6-8x5h-hjp6](https://github.com/advisories/GHSA-xwj6-8x5h-hjp6), [AWS bulletin 2026-070](https://aws.amazon.com/security/security-bulletins/2026-070-aws/). Policy: [cve-2026-18655.yaml](policies/cve-classes/cve-2026-18655.yaml).

Advisory text names `broker_hostname` and the tools `rabbimq_broker_initialize_connection` and `rabbimq_broker_initialize_connection_with_oauth` (spelling as published). This repo does not vendor that server and has not re-parsed its schema. The allowlist `b-*.mq.eu-central-1.amazonaws.com` is an example for one region, not a claim about every Amazon MQ endpoint. The vendor workaround example is `<broker_id>.mq.<region>.on.aws`. The plan's placeholder tool name `connect` is not in the advisory and is denied.

### CVE-2026-75130

Context7 served custom instruction text that a coding agent might obey. The vendor reports a server-side fix on 2026-02-23. Policy: [cve-2026-75130.yaml](policies/cve-classes/cve-2026-75130.yaml).

The pack does not detect the instruction. It bounds later calls: `read_file` stays inside the workspace and off `.env` / key paths, `fetch` stays on an HTTPS host allowlist, and `delete_*` is denied. The mock `get_docs` tool returns a harmless sentence. The test client sends the follow-up calls itself.

### CVE-2026-40933

Flowise before 3.1.0 accepted allowlisted stdio commands that still take an inline-code flag. [GHSA-c9gw-hvqq-f33r](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-c9gw-hvqq-f33r). Policy: [cve-2026-40933.yaml](policies/cve-classes/cve-2026-40933.yaml).

The pack is a denylist of flags (`npx -c` / `--call`, `node -e` / `--eval` / `-p`, `python -c`, `python3 -c`, `bash -c`, `sh -c`). Unlisted commands are not a safety claim. Cases use the inert token `marker` and never spawn. `wrap` does not enforce this section until v0.3.


## Comparison

Open-source MCP proxies with argument-level policy already exist. mcp-argguard does not replace them. [MCP Shield Runtime](https://github.com/samsgates/mcp-shield-runtime) is the closest: stdio and Streamable HTTP, path rules, secret paths, metadata URLs, approval, and a schema lockfile. v0.1 of this project is a smaller stdio relay.

The differentiation is the CVE-linked packs and their mock-server regression tests, normalization-based hostname, URL, and path checks, and the v0.3 launch guard for embedded-code flags. The longer table, including PolicyLayer Intercept, mcp-policy-gateway, mcp-airlock, mcp-context-protector, docker/mcp-gateway, and sparfenyuk/mcp-proxy, is in [docs/comparison.md](docs/comparison.md).

## Roadmap

| Version          | Contents                                                                                                                                                                           |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| v0.1 (this tree) | stdio relay, `tools/call` policy, enforce and monitor, JSONL log, `validate` / `test` / `explain`, three CVE-class packs, launch classifier available to `test` and `explain` only |
| v0.2             | Streamable HTTP reverse proxy                                                                                                                                                      |
| v0.3             | Enforce the launch guard inside `wrap`. `lint-config` reports an MCP client config that does not go through the proxy                                                              |

Sandboxing the child process, and detecting prompt injection with a model, are out of scope.

## Development

```sh
npm test          # compile, then unit + integration + fuzz + regression
npm run lint      # biome ci
npm run typecheck
npm run test:fuzz # longer property run
```

CI on GitHub Actions runs lint, typecheck, and test on Node.js 24 (Ubuntu). A weekly workflow reruns the property tests. There is no release workflow.

## License

[MIT](LICENSE). Copyright 2026 Ali Kesik.

[Security reports](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Code of conduct](CODE_OF_CONDUCT.md)
