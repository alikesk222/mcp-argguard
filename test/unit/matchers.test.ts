import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadPolicy } from "../../src/policy/loader.js";
import { hostGlobMatch } from "../../src/policy/matchers/hostglob.js";
import { matchHostname, normalizeHostname } from "../../src/policy/matchers/hostname.js";
import { parseIp, restrictionOf } from "../../src/policy/matchers/ip.js";
import { matchPath } from "../../src/policy/matchers/path.js";
import { findSecret } from "../../src/policy/matchers/secrets.js";
import { matchUrl } from "../../src/policy/matchers/url.js";
import { WORKSPACE_PLACEHOLDER } from "../../src/policy/placeholders.js";
import { compilePolicyRegex } from "../../src/policy/regex.js";
import type { HostnameArg, UrlArg } from "../../src/policy/schema.js";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

const hostRule: HostnameArg = {
  type: "hostname",
  allow: ["b-*.mq.eu-central-1.amazonaws.com"],
  deny_ip_literals: true,
  required: true,
};

const urlRule: UrlArg = {
  type: "url",
  schemes: ["https"],
  hosts: ["docs.python.org", "*.github.com"],
  deny_private_ranges: true,
  deny_userinfo: true,
  required: true,
};

describe("hostname normalization", () => {
  it("folds case and strips a trailing dot before the allowlist", () => {
    const decision = matchHostname("B-1.MQ.EU-CENTRAL-1.AMAZONAWS.COM.", hostRule);
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.normalized).toBe("b-1.mq.eu-central-1.amazonaws.com");
  });

  it("does not let a suffix hide behind case and a trailing dot", () => {
    const decision = matchHostname("B-1.MQ.EU-CENTRAL-1.AMAZONAWS.COM.evil.test.", hostRule);
    expect(decision.ok).toBe(false);
  });

  it("rejects a cyrillic lookalike label", () => {
    const host = `b-1.mq.eu-central-1.${"\u0430"}mazonaws.com`;
    const decision = matchHostname(host, hostRule);
    expect(decision.ok).toBe(false);
    const normalized = normalizeHostname(host);
    expect(normalized.ok).toBe(true);
    if (normalized.ok) expect(normalized.value.hostname).toContain("xn--");
  });

  it.each([
    "2130706433",
    "0177.0.0.1",
    "0x7f.0.0.1",
    "127.1",
    "127.0.0.1",
    "::1",
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
  ])("treats %s as an IP literal", (host) => {
    const normalized = normalizeHostname(host);
    expect(normalized.ok).toBe(true);
    if (normalized.ok) expect(normalized.value.ip).not.toBeNull();
    expect(matchHostname(host, hostRule).ok).toBe(false);
  });

  it("rejects userinfo and paths", () => {
    expect(matchHostname("user@b-1.mq.eu-central-1.amazonaws.com", hostRule).ok).toBe(false);
    expect(matchHostname("b-1.mq.eu-central-1.amazonaws.com/path", hostRule).ok).toBe(false);
  });

  it("does not let a star cross a dot", () => {
    expect(hostGlobMatch("*.example.com", "good.example.com")).toBe(true);
    expect(hostGlobMatch("*.example.com", "a.b.example.com")).toBe(false);
    expect(hostGlobMatch("*.example.com", "example.com.evil.test")).toBe(false);
  });
});

describe("url normalization", () => {
  it("allows a canonical docs host and a wildcard label", () => {
    expect(matchUrl("https://docs.python.org/3/library/", urlRule).ok).toBe(true);
    expect(matchUrl("https://DOCS.PYTHON.ORG./", urlRule).ok).toBe(true);
    expect(matchUrl("https://gist.github.com/org/repo", urlRule).ok).toBe(true);
  });

  it.each([
    "http://docs.python.org/",
    "https://docs.python.org.evil.test/",
    "https://user@docs.python.org/",
    "https://docs.python.org@evil.test/",
    "https://127.0.0.1/",
    "https://2130706433/",
    "https://0177.0.0.1/",
    "https://0x7f.0.0.1/",
    "https://127.1/",
    "https://[::1]/",
    "https://[::ffff:127.0.0.1]/",
    "https://[::ffff:7f00:1]/",
    "https://169.254.169.254/latest/",
    "https://10.1.2.3/",
    "https://192.168.0.5/",
    "https://172.16.0.1/",
    "https://metadata.google.internal/",
    "https://0.0.0.0/",
    "not a url",
  ])("denies %s", (value) => {
    expect(matchUrl(value, urlRule).ok).toBe(false);
  });

  it("classifies restricted addresses", () => {
    const ip = (value: string) => {
      const parsed = parseIp(value);
      if (!parsed) throw new Error(`expected ${value} to parse`);
      return parsed;
    };
    expect(restrictionOf(ip("127.0.0.1"))).toBe("loopback");
    expect(restrictionOf(ip("10.0.0.1"))).toBe("rfc1918");
    expect(restrictionOf(ip("100.64.1.1"))).toBe("cgnat");
    expect(restrictionOf(ip("8.8.8.8"))).toBeUndefined();
    expect(restrictionOf(ip("::ffff:7f00:1"))).toBe("loopback");
    expect(restrictionOf(ip("169.254.169.254"))).toBe("link-local");
  });
});

describe("path normalization", () => {
  it("allows a file inside the workspace and denies escapes, env files, and symlinks", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "argguard-path-"));
    const workspace = path.join(root, "proj");
    fs.mkdirSync(workspace);
    fs.writeFileSync(path.join(workspace, "README.md"), "hello\n");
    fs.writeFileSync(path.join(workspace, ".env"), "CANARY=fake-canary-not-a-credential\n");
    fs.mkdirSync(path.join(root, "outside"));
    fs.writeFileSync(path.join(root, "outside", "secret.txt"), "nope\n");
    fs.symlinkSync(path.join(root, "outside", "secret.txt"), path.join(workspace, "linked.txt"));
    const rule = {
      type: "path" as const,
      within: [WORKSPACE_PLACEHOLDER],
      deny: ["**/.env*", "**/.ssh/**", "**/*.pem", "**/*.key"],
      resolve_symlinks: true,
      required: true,
    };
    const ctx = { workspace, home: os.homedir() };
    expect(matchPath(path.join(workspace, "README.md"), rule, ctx).ok).toBe(true);
    expect(matchPath(path.join(workspace, "sub", "..", "README.md"), rule, ctx).ok).toBe(true);
    expect(matchPath(path.join(workspace, ".env"), rule, ctx).ok).toBe(false);
    expect(matchPath(path.join(workspace, ".env.local"), rule, ctx).ok).toBe(false);
    expect(matchPath(path.join(workspace, "..", "outside", "secret.txt"), rule, ctx).ok).toBe(
      false,
    );
    expect(matchPath(path.join(workspace, "linked.txt"), rule, ctx).ok).toBe(false);
    expect(matchPath(`${workspace}/README.md\0`, rule, ctx).ok).toBe(false);
  });
});

describe("secrets", () => {
  it("matches the example access-key shape and a private-key banner, including nested values", () => {
    const secrets = [
      { id: "aws-access-key", regex: compilePolicyRegex("AKIA[0-9A-Z]{16}", "aws-access-key") },
      {
        id: "private-key-block",
        regex: compilePolicyRegex("-----BEGIN [A-Z ]*PRIVATE KEY-----", "private-key-block"),
      },
    ];
    expect(findSecret({ note: "prefix AKIAIOSFODNN7EXAMPLE suffix" }, secrets)).toBe(
      "aws-access-key",
    );
    expect(findSecret({ nested: [{ blob: "-----BEGIN TEST PRIVATE KEY-----" }] }, secrets)).toBe(
      "private-key-block",
    );
    expect(findSecret({ note: "harmless" }, secrets)).toBeUndefined();
  });
});

describe("shipped policies", () => {
  it("loads the example and starter profiles", () => {
    for (const relative of [
      "policies/examples/policy.example.yaml",
      "policies/starter/filesystem.yaml",
      "policies/starter/fetch.yaml",
      "policies/starter/shell.yaml",
      "policies/cve-classes/cve-2026-18655.yaml",
      "policies/cve-classes/cve-2026-75130.yaml",
      "policies/cve-classes/cve-2026-40933.yaml",
    ]) {
      expect(() => loadPolicy(path.join(repoRoot, relative))).not.toThrow();
    }
  });
});
