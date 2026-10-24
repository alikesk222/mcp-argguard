import type { HostnameArg } from "../schema.js";
import { hostGlobMatch } from "./hostglob.js";
import { canonicalIp, type IpAddress, parseIp } from "./ip.js";
import { includesCharCode, includesCharCodeAtMost } from "./text.js";
import type { MatchResult } from "./url.js";

export type NormalizedHost = {
  hostname: string;
  ip: IpAddress | null;
};

export type HostResult = { ok: true; value: NormalizedHost } | { ok: false; reason: string };

/**
 * Canonicalize a hostname with the WHATWG URL parser (IDNA, case, IPv4 encodings)
 * after rejecting userinfo, paths, and ports. Comparison uses the canonical form.
 */
export function normalizeHostname(input: string): HostResult {
  if (input.length === 0 || input.trim().length === 0) {
    return { ok: false, reason: "hostname is empty" };
  }
  if (input !== input.trim()) {
    return { ok: false, reason: "hostname has surrounding whitespace" };
  }
  if (input.length > 4096) return { ok: false, reason: "hostname is too long" };
  if (
    includesCharCodeAtMost(input, 0x20) ||
    includesCharCode(input, 0x7f) ||
    /[\\/?#@]/u.test(input)
  ) {
    return { ok: false, reason: "hostname contains forbidden characters" };
  }

  const colonCount = countChar(input, ":");
  const bracketed = input.startsWith("[") && input.endsWith("]");
  const ipv6 = bracketed || colonCount >= 2;
  if (colonCount > 0 && !ipv6) {
    return { ok: false, reason: "a port is not part of a hostname" };
  }
  if (bracketed && input.slice(1, -1).includes("]")) {
    return { ok: false, reason: "malformed bracketed hostname" };
  }

  const hostForUrl = ipv6 && !bracketed ? `[${input}]` : input;
  let url: URL;
  try {
    url = new URL(`http://${hostForUrl}`);
  } catch {
    return { ok: false, reason: "hostname is not a valid host" };
  }
  if (
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    return { ok: false, reason: "hostname is not a bare host" };
  }

  let hostname = url.hostname;
  while (hostname.endsWith(".")) hostname = hostname.slice(0, -1);
  if (hostname.startsWith("[") && hostname.endsWith("]")) hostname = hostname.slice(1, -1);
  if (hostname.length === 0) return { ok: false, reason: "hostname is empty" };

  const ip = parseIp(hostname);
  if (ip) {
    const canonical = ip.family === "v4" ? canonicalIp(ip) : hostname;
    return { ok: true, value: { hostname: canonical, ip } };
  }
  if (!isDnsName(hostname)) return { ok: false, reason: "hostname is not a DNS name" };
  return { ok: true, value: { hostname, ip: null } };
}

export function matchHostname(value: unknown, rule: HostnameArg): MatchResult {
  if (typeof value !== "string") return { ok: false, reason: "hostname must be a string" };
  const normalized = normalizeHostname(value);
  if (!normalized.ok) return normalized;
  if (rule.deny_ip_literals && normalized.value.ip) {
    return { ok: false, reason: "ip literals are not allowed for this hostname" };
  }
  const allowed = rule.allow.some((pattern) => hostGlobMatch(pattern, normalized.value.hostname));
  if (!allowed) {
    return { ok: false, reason: `host ${normalized.value.hostname} is not in the allowlist` };
  }
  return { ok: true, normalized: normalized.value.hostname };
}

function isDnsName(hostname: string): boolean {
  if (hostname.length > 253) return false;
  const labels = hostname.split(".");
  if (labels.some((label) => label.length === 0)) return false;
  return labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label));
}

function countChar(text: string, needle: string): number {
  let count = 0;
  for (const char of text) if (char === needle) count += 1;
  return count;
}
