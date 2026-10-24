import path from "node:path";
import type { LaunchRule } from "../policy/schema.js";

/**
 * v0.1 ships the classifier and the regression corpus.
 * `wrap` does not consult this function when it spawns a child. Enforcement is v0.3.
 */
export const LAUNCH_GUARD_ENFORCED_IN = "0.3.0";

export type LaunchSpec = {
  command: string;
  args: readonly string[];
};

export type LaunchDecision = {
  decision: "allow" | "deny";
  ruleId: string;
  reason: string;
};

/**
 * Deny-list of inline-code flags on a command basename.
 * A command that is not listed is not denied here. That is not a safety claim.
 * Nothing in this module spawns a process.
 */
export function evaluateLaunch(spec: LaunchSpec, rules: readonly LaunchRule[]): LaunchDecision {
  const base = commandBasename(spec.command);
  const applicable = rules.filter((rule) => rule.command.toLowerCase() === base);
  if (applicable.length === 0) {
    return {
      decision: "allow",
      ruleId: "launch/unlisted",
      reason: `command ${base || spec.command} is not covered by deny_inline_code`,
    };
  }
  for (const rule of applicable) {
    for (const flag of rule.flags) {
      const hit = spec.args.find((arg) => invokesFlag(arg, flag));
      if (hit !== undefined) {
        return {
          decision: "deny",
          ruleId: `launch/${rule.command}/${flag}`,
          reason: `inline-code flag ${flag} on ${rule.command}`,
        };
      }
    }
  }
  return {
    decision: "allow",
    ruleId: `launch/${base}/no-inline-flag`,
    reason: `no listed inline-code flag on ${base}`,
  };
}

export function commandBasename(command: string): string {
  return path
    .basename(command)
    .toLowerCase()
    .replace(/(\.cmd|\.exe)$/iu, "");
}

function invokesFlag(arg: string, flag: string): boolean {
  if (arg === flag) return true;
  if (flag.startsWith("--") && flag.length > 2) return arg.startsWith(`${flag}=`);
  if (flag.startsWith("-") && !flag.startsWith("--") && flag.length === 2) {
    if (!arg.startsWith("-") || arg.startsWith("--")) return false;
    const letter = flag[1];
    const body = arg.slice(1).split("=", 1)[0] ?? "";
    return letter !== undefined && body.includes(letter);
  }
  return false;
}
