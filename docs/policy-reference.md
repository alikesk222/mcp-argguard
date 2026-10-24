# Policy reference

Policies are YAML, `version: 1`. The loader rejects files over 1 MiB, YAML aliases, and duplicate keys. `mode` is required. There is no implicit mode.

```yaml
version: 1
mode: enforce # enforce | monitor
defaults:
  tool: deny # default
  unknown_args: deny # default
  method: allow # default; keeps initialize and discovery working
limits:
  max_message_bytes: 1048576 # default; maximum 33554432
log:
  path: ~/.argguard/decisions.jsonl
  store_args: hashed # none | hashed | redacted
  redact_keys: [password, token, secret, authorization, api_key]
secrets: []
servers: {}
methods: {} # optional per-method allow or deny
launch: # optional; evaluated by test and explain, not by wrap until v0.3
  deny_inline_code: []
```

`~` in `log.path` and in path roots is the home directory. `${workspace}` and `${home}` expand in path roots only. Set the workspace with `--workspace` or `ARGGUARD_WORKSPACE`. Otherwise it is the current directory. `--log` overrides `log.path`.

## Servers and tools

`mcp-argguard wrap --server <name>` selects one key under `servers`. A missing server denies the call.

Tool keys are matched in YAML order. A key without `*`, `?`, or `[` is exact. Otherwise it is a picomatch glob. The first match wins, so a broad glob placed above a specific tool makes the specific tool unreachable (`validate` warns).

```yaml
servers:
  filesystem:
    tools:
      read_file:
        decision: allow
        args:
          path:
            type: path
            within: ["${workspace}"]
      "delete_*":
        decision: deny
        reason: "deletion is disabled in this profile"
```

Argument paths are ASCII identifiers plus `[*]`, for example `path` or `targets[*].id`. A path must start with an identifier.

`required` defaults to true. A required path must be present. For `[*]`, an empty array does not satisfy required. After required paths are checked, every value in the argument tree is either covered by a matcher path (exact or ancestor), an element of a declared array, or unknown. Unknown values are denied when `defaults.unknown_args` is `deny`.

## Matchers

### hostname

Canonicalized with the WHATWG URL parser after the value is rejected for whitespace, controls, `@`, slashes, query or fragment characters, and a port. Trailing dots are removed. IDNA is applied. `deny_ip_literals` defaults to true.

`allow` entries are host globs. `*` and `?` match inside one DNS label. `*.example.com` does not match `a.b.example.com`. A pattern of only `*` and `?` (`*`, `*.*`) is a `validate` warning.

### url

`schemes` and `hosts` are required. `deny_userinfo` and `deny_private_ranges` default to true. The reason string names the host, not the raw URL.

With `deny_private_ranges`, these are denied: `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `100.64.0.0/10` (RFC 6598, an extra range beyond RFC 1918), `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `255.255.255.255`, IPv6 `::`, `::1`, `fe80::/10`, `fc00::/7`, `fec0::/10`, and IPv4-mapped or IPv4-compatible tails of those ranges. The hostnames `metadata.google.internal` and `metadata.goog` are denied. DNS is not queried.

### path

`within` is one or more roots. `deny` is a list of picomatch globs (`dot: true`), matched against the absolute path and against the path relative to each root. `resolve_symlinks` defaults to true: the walk uses `lstat` and `readlink`, fails closed, and stops after 32 hops. A missing leaf is allowed to stay lexical so a not-yet-created file can still be checked against the root.

### string and number

Strings may set `min_length`, `max_length`, a `pattern` (JavaScript regex, flag `u`, at most 256 characters, nested quantifiers rejected), and `allow` or `deny` globs. Numbers must be finite JSON numbers. Numeric strings are not coerced. `integer` defaults to false. `minimum` must be less than or equal to `maximum` when both are set.

## Secrets

Each secret has an `id` (`^[a-z0-9][a-z0-9-]{0,63}$`) and a `regex` under the same limits as string patterns. The scan walks strings and object keys. The deny reason names the secret id and does not include the matched text.

## Launch

```yaml
launch:
  deny_inline_code:
    - command: npx
      flags: ["-c", "--call"]
    - command: node
      flags: ["-e", "--eval", "-p"]
```

The command comparison uses the basename, without `.exe` or `.cmd`, case-insensitive. A short flag matches a cluster (`-ec` counts as `-e`). `--eval=marker` counts as `--eval`. A command that is not listed returns `launch/unlisted`. That is not a safety claim. Nothing in the classifier spawns a process. `wrap` prints a warning when a launch section is present and still starts the child until v0.3.

## Decision log

One JSON object per line: `ts`, `server`, `method`, `tool`, `decision`, `enforced`, `mode`, `rule_id`, `reason`, `args_hash`, `policy_hash`, `latency_ms`, `protocol`, and `args` when `store_args` is `redacted`.

`policy_hash` is the SHA-256 of the raw policy file. `args_hash` is the SHA-256 of canonical JSON (sorted keys) of the unredacted arguments when `store_args` is `hashed` or `redacted`, and null when `store_args` is `none`. `protocol` is null until a message reveals the era.

## CLI

```text
mcp-argguard wrap --policy <file> --server <name> [--workspace <dir>] [--log <file>] -- <command> [args...]
mcp-argguard validate --policy <file> [--workspace <dir>] [--strict]
mcp-argguard test --policy <file> --cases <file> [--workspace <dir>]
mcp-argguard explain --policy <file> --server <name> --tool <name> --args <json>
mcp-argguard explain --policy <file> --launch <json>
```

`validate` prints warnings and info. `--strict` exits 1 on warnings only. `test` prints `PASS` or `FAIL` per case and exits 1 if any case fails. It compares the engine decision, not live enforcement, and it does not write the decision log. `explain` exits 0 for both allow and deny. `explain --launch` prints `enforced_in: 0.3.0`.

Case files are a YAML list. Each item has `name`, `expect` (`allow` or `deny`), and exactly one of `call` or `launch`. `${workspace}` inside a case file is expanded to the workspace directory. It is not expanded inside a policy argument value.

## JSON-RPC errors

| Code   | Meaning                                                                 |
| ------ | ----------------------------------------------------------------------- |
| -32700 | The client line is not JSON.                                            |
| -32600 | The line is a batch or not a valid request where a request is required. |
| -32001 | Policy deny in enforce mode, or policy evaluation threw.                |
| -32003 | The client message exceeds `max_message_bytes`.                         |
| -32004 | Enforce mode could not write the decision log.                          |

The id of the request is preserved. A denied notification (no id) is dropped.
