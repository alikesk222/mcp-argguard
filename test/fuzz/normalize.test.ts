import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { matchHostname, normalizeHostname } from "../../src/policy/matchers/hostname.js";
import { restrictionOf } from "../../src/policy/matchers/ip.js";
import type { HostnameArg } from "../../src/policy/schema.js";

const runs = Number(process.env.ARGGUARD_FUZZ_RUNS ?? 100);

const hostRule: HostnameArg = {
  type: "hostname",
  allow: ["b-*.mq.eu-central-1.amazonaws.com"],
  deny_ip_literals: true,
  required: true,
};

describe("hostname properties", () => {
  it("keeps the decision when case and a trailing dot change", () => {
    fc.assert(
      fc.property(fc.domain(), (domain) => {
        const lower = matchHostname(domain, hostRule);
        const variant = matchHostname(`${domain.toUpperCase()}.`, hostRule);
        if (lower.ok || variant.ok) expect(variant.ok).toBe(lower.ok);
        if (lower.ok && variant.ok) expect(variant.normalized).toBe(lower.normalized);
      }),
      { numRuns: runs },
    );
  });

  it("agrees with the WHATWG host on names that both accept", () => {
    fc.assert(
      fc.property(fc.domain(), (domain) => {
        let url: URL;
        try {
          url = new URL(`https://${domain}/`);
        } catch {
          return;
        }
        const normalized = normalizeHostname(url.hostname);
        if (!normalized.ok || normalized.value.ip) return;
        const cleaned = url.hostname.replace(/^\[|\]$/gu, "").replace(/\.+$/u, "");
        expect(normalized.value.hostname).toBe(cleaned);
      }),
      { numRuns: runs },
    );
  });

  it("treats generated loopback integers as restricted after canonicalization", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0x7f000000, max: 0x7fffffff }), (value) => {
        const normalized = normalizeHostname(String(value));
        expect(normalized.ok).toBe(true);
        if (!normalized.ok || !normalized.value.ip) return;
        expect(restrictionOf(normalized.value.ip)).toBe("loopback");
        expect(matchHostname(String(value), hostRule).ok).toBe(false);
      }),
      { numRuns: runs },
    );
  });
});
