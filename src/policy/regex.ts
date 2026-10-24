const NESTED_GROUP = /\([^)]*[+*][^)]*\)[+*{]/;
const NESTED_DOT = /(?:^|[^\\])\.\*[+*{]/;

/** Compile a policy regex. Nested quantifiers are rejected so a value cannot hang the proxy. */
export function compilePolicyRegex(source: string, label: string): RegExp {
  if (source.length === 0 || source.length > 256) {
    throw new Error(`${label} regex must be 1..256 characters`);
  }
  if (NESTED_GROUP.test(source) || NESTED_DOT.test(source)) {
    throw new Error(`${label} regex contains nested quantifiers, which are not allowed`);
  }
  try {
    return new RegExp(source, "u");
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid pattern";
    throw new Error(`${label} regex does not compile: ${message}`);
  }
}
