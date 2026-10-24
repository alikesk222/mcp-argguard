import fs from "node:fs";
import path from "node:path";
import picomatch from "picomatch";
import { HOME_PLACEHOLDER, WORKSPACE_PLACEHOLDER } from "../placeholders.js";
import type { PathArg } from "../schema.js";
import { includesCharCodeAtMost } from "./text.js";
import type { MatchResult } from "./url.js";

export type PathContext = {
  workspace: string;
  home: string;
};

const matchers = new Map<string, (value: string) => boolean>();

export function matchPath(value: unknown, rule: PathArg, ctx: PathContext): MatchResult {
  if (typeof value !== "string" || value.length === 0) {
    return { ok: false, reason: "path must be a non-empty string" };
  }
  if (includesCharCodeAtMost(value, 0x1f)) {
    return { ok: false, reason: "path contains control characters" };
  }

  const expanded = expandHome(value, ctx.home);
  const absolute = path.resolve(ctx.workspace, expanded);
  let candidate = absolute;
  if (rule.resolve_symlinks) {
    const resolved = resolveSymlinks(absolute);
    if (!resolved.ok) return resolved;
    candidate = resolved.path;
  }

  const roots: string[] = [];
  for (const within of rule.within) {
    let root: string;
    try {
      root = resolvePolicyRoot(within, ctx);
    } catch (error) {
      const message = error instanceof Error ? error.message : "invalid within path";
      return { ok: false, reason: message };
    }
    if (rule.resolve_symlinks) {
      const resolvedRoot = resolveSymlinks(root);
      if (!resolvedRoot.ok) return resolvedRoot;
      roots.push(resolvedRoot.path);
    } else {
      roots.push(root);
    }
  }

  if (!roots.some((root) => isWithin(root, candidate))) {
    return { ok: false, reason: "path is outside the allowed roots" };
  }

  for (const pattern of rule.deny) {
    const relativeHits = roots.some((root) => {
      const relative = path.relative(root, candidate);
      if (!isRelativeInside(relative)) return false;
      return globHit(pattern, relative);
    });
    if (globHit(pattern, candidate) || relativeHits) {
      return { ok: false, reason: `path matches deny pattern ${pattern}` };
    }
  }

  return { ok: true, normalized: candidate };
}

export function resolvePolicyRoot(input: string, ctx: PathContext): string {
  const value = expandPolicyPath(input, ctx);
  return path.resolve(ctx.workspace, value);
}

export function expandPolicyPath(input: string, ctx: PathContext): string {
  const replaced = input
    .replaceAll(WORKSPACE_PLACEHOLDER, ctx.workspace)
    .replaceAll(HOME_PLACEHOLDER, ctx.home);
  if (replaced.includes("${")) {
    throw new Error(`unsupported substitution in policy path "${input}"`);
  }
  return expandHome(replaced, ctx.home);
}

export function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return isRelativeInside(relative) || relative === "";
}

function isRelativeInside(relative: string): boolean {
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function expandHome(input: string, home: string): string {
  if (input === "~") return home;
  if (input.startsWith("~/")) return path.join(home, input.slice(2));
  return input;
}

function globHit(pattern: string, filePath: string): boolean {
  const posix = filePath.split(path.sep).join("/");
  const isMatch = cached(pattern);
  if (isMatch(posix)) return true;
  const parts = posix.split("/");
  for (let i = 0; i < parts.length; i += 1) {
    const suffix = parts.slice(i).join("/");
    if (suffix.length > 0 && isMatch(suffix)) return true;
  }
  return false;
}

function cached(pattern: string): (value: string) => boolean {
  const existing = matchers.get(pattern);
  if (existing) return existing;
  const compiled = picomatch(pattern, { dot: true });
  matchers.set(pattern, compiled);
  return compiled;
}

function resolveSymlinks(
  candidate: string,
  depth = 0,
): { ok: true; path: string } | { ok: false; reason: string } {
  if (depth > 32) return { ok: false, reason: "symlink resolution exceeded the hop limit" };
  const root = path.parse(candidate).root;
  const relative = path.relative(root, candidate);
  const parts = relative === "" ? [] : relative.split(path.sep).filter((part) => part.length > 0);
  let current = root;
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i];
    if (!part) continue;
    current = path.join(current, part);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(current);
    } catch (error) {
      const code = error instanceof Error && "code" in error ? String(error.code) : "";
      if (code === "ENOENT") {
        return { ok: true, path: path.join(current, ...parts.slice(i + 1)) };
      }
      return { ok: false, reason: "path could not be resolved" };
    }
    if (!stat.isSymbolicLink()) continue;
    let link: string;
    try {
      link = fs.readlinkSync(current);
    } catch {
      return { ok: false, reason: "symlink could not be read" };
    }
    const target = path.resolve(path.dirname(current), link);
    return resolveSymlinks(path.join(target, ...parts.slice(i + 1)), depth + 1);
  }
  return { ok: true, path: current };
}
