import picomatch from "picomatch";
import type { NumberArg, StringArg } from "../schema.js";
import type { MatchResult } from "./url.js";

export function matchString(value: unknown, rule: StringArg): MatchResult {
  if (typeof value !== "string") return { ok: false, reason: "value must be a string" };
  if (rule.min_length !== undefined && value.length < rule.min_length) {
    return { ok: false, reason: `string is shorter than ${rule.min_length}` };
  }
  if (rule.max_length !== undefined && value.length > rule.max_length) {
    return { ok: false, reason: `string is longer than ${rule.max_length}` };
  }
  if (rule.pattern !== undefined && !new RegExp(rule.pattern, "u").test(value)) {
    return { ok: false, reason: "string does not match the required pattern" };
  }
  if (rule.deny?.some((pattern) => glob(pattern, value))) {
    return { ok: false, reason: "string matches a deny pattern" };
  }
  if (rule.allow && !rule.allow.some((pattern) => glob(pattern, value))) {
    return { ok: false, reason: "string is not in the allowlist" };
  }
  return { ok: true };
}

export function matchNumber(value: unknown, rule: NumberArg): MatchResult {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return { ok: false, reason: "value must be a finite number" };
  }
  if (rule.integer && !Number.isInteger(value)) {
    return { ok: false, reason: "value must be an integer" };
  }
  if (rule.minimum !== undefined && value < rule.minimum) {
    return { ok: false, reason: `number is below ${rule.minimum}` };
  }
  if (rule.maximum !== undefined && value > rule.maximum) {
    return { ok: false, reason: `number is above ${rule.maximum}` };
  }
  return { ok: true };
}

function glob(pattern: string, value: string): boolean {
  if (!/[*?[\]]/u.test(pattern)) return pattern === value;
  return picomatch(pattern, { dot: true })(value);
}
