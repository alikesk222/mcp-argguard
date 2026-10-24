# Contributing

mcp-argguard is a defensive project. Read [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before sending a change. The project is not published to npm. Do not add a release workflow, a git tag, or a publish script that succeeds.

## Setup

Node.js 24 or newer:

```sh
npm ci --ignore-scripts
npm test
npm run lint
npm run typecheck
```

`npm test` compiles `src/` and runs unit, integration, fuzz, and regression tests. Integration tests spawn the compiled CLI and local mock servers only.

## What a change should include

- A policy behavior change needs a unit test. A `tools/call` relay change needs an integration test through `dist/cli/main.js`.
- A new CVE-class pack is a YAML policy, a `.cases.yaml` file, and a regression test that uses a local mock. Document which names come from an advisory and which names this repository did not re-parse.
- Hosts in fixtures are RFC 2606 names (`.example`, `.test`) or local paths. Do not add a live network target.
- Do not copy exploit text, inline-code payloads, or real credentials into the tree. Launch cases must not spawn a process.

## Policy packs

1. Add `policies/cve-classes/<id>.yaml` with `version: 1` and an explicit `mode`.
2. Add `policies/cve-classes/<id>.cases.yaml`. Each case is one `call` or one `launch`, plus `expect: allow` or `expect: deny`.
3. Run `node dist/cli/main.js test --policy <pack> --cases <cases>`.
4. Explain, in the YAML header, what the pack bounds and what it does not detect.

`validate --strict` fails on fail-open warnings (`defaults.tool: allow`, `unknown_args: allow`, universal host globs, and the other warnings in `src/policy/lint.ts`). Info findings, including monitor mode and the v0.3 launch note, do not fail `--strict`.

## Code

TypeScript, Node 24, ESM, relative imports ending in `.js`. The relay is a newline-delimited JSON-RPC pipe. Do not route it through the MCP SDK's high-level server. The SDK is a devDependency for types, mock servers, and tests.

Format and lint with Biome (`npm run format`, `npm run lint`).

## Commits

Write a sentence that says what changed and why. Keep unrelated changes in separate commits.

## Security reports

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).
