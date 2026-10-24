import type { UrlArg } from "../schema.js";
import { hostGlobMatch } from "./hostglob.js";
import { normalizeHostname } from "./hostname.js";
import { restrictionOf } from "./ip.js";
import { includesCharCode, includesCharCodeAtMost } from "./text.js";

export type MatchResult = { ok: true; normalized?: string } | { ok: false; reason: string };

const METADATA_NAMES = new Set(["metadata.google.internal", "metadata.goog"]);

export function matchUrl(value: unknown, rule: UrlArg): MatchResult {
  if (typeof value !== "string") return { ok: false, reason: "url must be a string" };
  if (value.length === 0 || value.length > 8192)
    return { ok: false, reason: "url length is not allowed" };
  if (includesCharCodeAtMost(value, 0x1f) || includesCharCode(value, 0x7f)) {
    return { ok: false, reason: "url contains control characters" };
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, reason: "url did not parse" };
  }
  if ((url.username.length > 0 || url.password.length > 0) && rule.deny_userinfo) {
    return { ok: false, reason: "url userinfo is not allowed" };
  }
  const scheme = url.protocol.replace(/:$/u, "").toLowerCase();
  const schemes = new Set(rule.schemes.map((item) => item.toLowerCase()));
  if (!schemes.has(scheme)) return { ok: false, reason: `scheme ${scheme} is not allowed` };

  const host = normalizeHostname(url.hostname);
  if (!host.ok) return { ok: false, reason: host.reason };
  if (rule.deny_private_ranges && host.value.ip) {
    const restriction = restrictionOf(host.value.ip);
    if (restriction) {
      return { ok: false, reason: `url host is a ${restriction} address` };
    }
  }
  if (rule.deny_private_ranges && METADATA_NAMES.has(host.value.hostname)) {
    return { ok: false, reason: "url host is a well-known metadata name" };
  }
  const allowed = rule.hosts.some((pattern) => hostGlobMatch(pattern, host.value.hostname));
  if (!allowed) return { ok: false, reason: `host ${host.value.hostname} is not in the allowlist` };
  return { ok: true, normalized: `${scheme}://${host.value.hostname}${url.pathname}${url.search}` };
}
