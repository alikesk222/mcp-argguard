function escapeRegex(text: string): string {
  return text.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}

/**
 * Hostname glob. `*` and `?` match inside a single DNS label.
 * `*` does not cross dots, so `*.example.com` does not match `a.b.example.com`.
 */
export function hostGlobMatch(pattern: string, hostname: string): boolean {
  const pat = pattern.trim().toLowerCase().replace(/\.+$/u, "");
  const host = hostname.toLowerCase().replace(/\.+$/u, "");
  if (pat.length === 0 || host.length === 0) return false;
  if (pat.includes("/") || pat.includes("**") || pat.includes(":") || pat.includes("@"))
    return false;
  const patternLabels = pat.split(".");
  const hostLabels = host.split(".");
  if (patternLabels.length !== hostLabels.length) return false;
  for (let i = 0; i < patternLabels.length; i += 1) {
    const left = patternLabels[i];
    const right = hostLabels[i];
    if (left === undefined || right === undefined || !labelMatch(left, right)) return false;
  }
  return true;
}

function labelMatch(pattern: string, label: string): boolean {
  let source = "^";
  for (const char of pattern) {
    if (char === "*") source += ".*";
    else if (char === "?") source += ".";
    else source += escapeRegex(char);
  }
  source += "$";
  return new RegExp(source, "u").test(label);
}

/** True when the pattern pins no literal label characters (`*`, `*.*`, ...). */
export function isUniversalHostPattern(pattern: string): boolean {
  const labels = pattern.trim().toLowerCase().replace(/\.+$/u, "").split(".");
  return labels.length > 0 && labels.every((label) => /^[*?]+$/u.test(label));
}
