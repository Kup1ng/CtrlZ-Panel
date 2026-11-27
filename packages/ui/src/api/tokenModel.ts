import {isIPv4, isIPv6} from "../destinations/destinations.ts";
import {stripInvisible} from "../forms/invisible.ts";

// What the API tokens page decides without the server (spec p3 6.4): the list of addresses a token may be used from, and the words of its
// state. The server checks everything again (`apitoken.ParseAllowed`); this only spares a round trip and a reauth for a value that cannot pass.
//
// An allowed entry is an address or a subnet with no host bits: `203.0.113.7`, `203.0.113.0/24`, `2001:db8::/32`. A zone (`fe80::1%eth0`) and an
// IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) are refused by the API, so they are here. At most 32 entries, and a repeated entry is kept once.

export const MAX_ALLOWED = 32;
export const NAME_MAX = 64;

export type AllowedProblem = "invalid" | "hostBits" | "duplicate" | "max";

/** The 128-bit value of an IPv6 text that `isIPv6` accepted (a dotted IPv4 tail is two groups), or the 32-bit value of an IPv4 one, as a BigInt. */
function bitsOf(address: string, v6: boolean): bigint {
  const ipv4 = (text: string) => text.split(".").reduce((n, part) => (n << 8n) | BigInt(part), 0n);
  if (!v6) return ipv4(address);
  let text = address;
  const cut = text.lastIndexOf(":") + 1;
  if (text.slice(cut).includes(".")) {
    const tail = ipv4(text.slice(cut));
    text = `${text.slice(0, cut)}${(tail >> 16n).toString(16)}:${(tail & 0xffffn).toString(16)}`;
  }
  const [head, rest] = text.split("::") as [string, string | undefined];
  const side = (s: string) => (s === "" ? [] : s.split(":"));
  const left = side(head);
  const right = rest === undefined ? [] : side(rest);
  const groups = [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right];
  return groups.reduce((n, g) => (n << 16n) | BigInt(`0x${g}`), 0n);
}

type Parsed = {family: 4 | 6; bits: bigint; prefix: number};

function parse(text: string): Parsed | null {
  const slash = text.indexOf("/");
  const address = slash < 0 ? text : text.slice(0, slash);
  // The schema of an entry opens with a hex digit (`^[0-9A-Fa-f][0-9A-Fa-f:.]*`), so `::1` and `::/0` are refused before the handler runs, with a bare 400 that no
  // field can show. They are refused here, where the words are.
  if (!/^[0-9A-Fa-f]/.test(address)) return null;
  const v4 = isIPv4(address);
  const v6 = !v4 && isIPv6(address);
  if (!v4 && !v6) return null;
  const width = v4 ? 32 : 128;
  let prefix = width;
  if (slash >= 0) {
    const digits = text.slice(slash + 1);
    // No leading zero: `/024` fits the schema and netip refuses it.
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(digits)) return null;
    prefix = Number(digits);
    if (prefix > width) return null;
  }
  const bits = bitsOf(address, v6);
  // ::ffff:a.b.c.d, in hex groups or with its dotted tail, is the one IPv4-mapped form the API refuses; a NAT64 spelling such as 64:ff9b::192.0.2.1 is not mapped.
  if (v6 && bits >> 32n === 0xffffn) return null;
  return {family: v4 ? 4 : 6, bits, prefix};
}

/** The one spelling the list compares by: the family, the bits and the prefix, so `2001:db8::` and `2001:0DB8:0::` are one entry and an address with no mask is its /32 or /128. */
export function canonicalAllowed(text: string): string | null {
  const parsed = parse(text);
  return parsed ? `${parsed.family}:${parsed.bits.toString(16)}/${parsed.prefix}` : null;
}

/** The value as it would be kept (trimmed, invisible characters dropped, an address with no mask left as typed) and what is wrong with it. */
export function checkAllowed(typed: string, list: readonly string[]): {value: string; problem: AllowedProblem | null} {
  const value = stripInvisible(typed).trim();
  if (value === "") return {value, problem: "invalid"};
  if (list.length >= MAX_ALLOWED) return {value, problem: "max"};
  const parsed = parse(value);
  if (!parsed) return {value, problem: "invalid"};
  const width = parsed.family === 4 ? 32n : 128n;
  const hostMask = (1n << (width - BigInt(parsed.prefix))) - 1n;
  if ((parsed.bits & hostMask) !== 0n) return {value, problem: "hostBits"};
  const canonical = canonicalAllowed(value);
  if (list.some((entry) => canonicalAllowed(entry) === canonical)) return {value, problem: "duplicate"};
  return {value, problem: null};
}

/** The list in the form the API compares it in, so an edit that changes nothing sends nothing. */
export function sameAllowed(a: readonly string[], b: readonly string[]): boolean {
  const canon = (list: readonly string[]) => [...list.map((entry) => canonicalAllowed(entry) ?? entry)].sort();
  const left = canon(a);
  const right = canon(b);
  return left.length === right.length && left.every((entry, index) => entry === right[index]);
}

/** How many entries a row shows before it says "and N more" (the Edit dialog has all of them). */
export const ALLOWED_SHOWN = 2;
