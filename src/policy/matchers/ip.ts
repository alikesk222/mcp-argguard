export type Ipv4 = { family: "v4"; octets: readonly [number, number, number, number] };
export type Ipv6 = {
  family: "v6";
  hextets: readonly [number, number, number, number, number, number, number, number];
};
export type IpAddress = Ipv4 | Ipv6;

export type Restriction =
  | "unspecified"
  | "loopback"
  | "rfc1918"
  | "link-local"
  | "cgnat"
  | "broadcast"
  | "ula"
  | "site-local";

export function parseIp(host: string): IpAddress | null {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (bare.includes(":")) return parseIpv6(bare);
  return parseIpv4(bare);
}

export function restrictionOf(ip: IpAddress): Restriction | undefined {
  if (ip.family === "v4") return restrictionV4(ip.octets);
  if (isMappedV4(ip.hextets) || isCompatibleV4(ip.hextets)) {
    return restrictionV4(octetsFromTail(ip.hextets));
  }
  if (isAllZero(ip.hextets)) return "unspecified";
  if (isLoopbackV6(ip.hextets)) return "loopback";
  const head = ip.hextets[0];
  if (head === undefined) return undefined;
  if (head >= 0xfe80 && head <= 0xfebf) return "link-local";
  if ((head & 0xfe00) === 0xfc00) return "ula";
  if (head >= 0xfec0 && head <= 0xfeff) return "site-local";
  return undefined;
}

export function canonicalIp(ip: IpAddress): string {
  if (ip.family === "v4") return ip.octets.join(".");
  return ip.hextets.map((part) => part.toString(16)).join(":");
}

function parseIpv4(host: string): Ipv4 | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/u.test(part)) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value > 255) return null;
    octets.push(value);
  }
  if (octets.length !== 4) return null;
  const a = octets[0];
  const b = octets[1];
  const c = octets[2];
  const d = octets[3];
  if (a === undefined || b === undefined || c === undefined || d === undefined) return null;
  return { family: "v4", octets: [a, b, c, d] };
}

function parseIpv6(host: string): Ipv6 | null {
  let text = host.toLowerCase();
  const dotted = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/u.exec(text);
  if (dotted?.[1] && dotted[2]) {
    const v4 = parseIpv4(dotted[2]);
    if (!v4) return null;
    const hi = ((v4.octets[0] << 8) | v4.octets[1]).toString(16);
    const lo = ((v4.octets[2] << 8) | v4.octets[3]).toString(16);
    text = `${dotted[1]}${hi}:${lo}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = splitHextets(halves[0] ?? "");
  if (!head) return null;
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    return { family: "v6", hextets: asEight(head) };
  }
  const tail = splitHextets(halves[1] ?? "");
  if (!tail) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 1) return null;
  const full = [...head, ...new Array<number>(missing).fill(0), ...tail];
  if (full.length !== 8) return null;
  return { family: "v6", hextets: asEight(full) };
}

function splitHextets(text: string): number[] | null {
  if (text.length === 0) return [];
  const parts = text.split(":");
  const numbers: number[] = [];
  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/u.test(part)) return null;
    numbers.push(Number.parseInt(part, 16));
  }
  return numbers;
}

function asEight(values: readonly number[]): Ipv6["hextets"] {
  return [
    values[0] ?? 0,
    values[1] ?? 0,
    values[2] ?? 0,
    values[3] ?? 0,
    values[4] ?? 0,
    values[5] ?? 0,
    values[6] ?? 0,
    values[7] ?? 0,
  ];
}

function restrictionV4(octets: readonly [number, number, number, number]): Restriction | undefined {
  const a = octets[0];
  const b = octets[1];
  const c = octets[2];
  const d = octets[3];
  if (a === 0) return "unspecified";
  if (a === 10) return "rfc1918";
  if (a === 127) return "loopback";
  if (a === 100 && b >= 64 && b <= 127) return "cgnat";
  if (a === 169 && b === 254) return "link-local";
  if (a === 172 && b >= 16 && b <= 31) return "rfc1918";
  if (a === 192 && b === 168) return "rfc1918";
  if (a === 255 && b === 255 && c === 255 && d === 255) return "broadcast";
  return undefined;
}

function isAllZero(hextets: Ipv6["hextets"]): boolean {
  return hextets.every((part) => part === 0);
}

function isLoopbackV6(hextets: Ipv6["hextets"]): boolean {
  return hextets[7] === 1 && hextets.slice(0, 7).every((part) => part === 0);
}

function isMappedV4(hextets: Ipv6["hextets"]): boolean {
  return (
    hextets[0] === 0 &&
    hextets[1] === 0 &&
    hextets[2] === 0 &&
    hextets[3] === 0 &&
    hextets[4] === 0 &&
    hextets[5] === 0xffff
  );
}

function isCompatibleV4(hextets: Ipv6["hextets"]): boolean {
  if (isLoopbackV6(hextets) || isAllZero(hextets)) return false;
  return (
    hextets[0] === 0 &&
    hextets[1] === 0 &&
    hextets[2] === 0 &&
    hextets[3] === 0 &&
    hextets[4] === 0 &&
    hextets[5] === 0
  );
}

function octetsFromTail(hextets: Ipv6["hextets"]): Ipv4["octets"] {
  const hi = hextets[6] ?? 0;
  const lo = hextets[7] ?? 0;
  return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff];
}
