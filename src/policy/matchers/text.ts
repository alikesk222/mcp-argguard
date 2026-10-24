/** True when any code unit is at most `max` (used for C0 controls and space). */
export function includesCharCodeAtMost(value: string, max: number): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= max) return true;
  }
  return false;
}

/** True when any code unit equals `code` (used for DEL, which sits above the C0 range). */
export function includesCharCode(value: string, code: number): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) === code) return true;
  }
  return false;
}
