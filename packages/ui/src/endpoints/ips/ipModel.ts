import type {AuthorizedIP, IPClaim} from "@ctrlz/api-client/hooks/clients.ts";

// The IPs page (spec p3 10, 4, 5; T-262, T-263, T-267), without React so a plain test holds its rules.

export const MAX_CIDRS = 100;

const V4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
// Hex groups and colons, with at most one `::`, and an optional trailing dotted quad. The server decides what is a real address and what range
// is allowed (it knows /16 and /32 limits); this only keeps a sentence or a typo from costing a request.
function isV6(text: string): boolean {
  if (!/^[0-9a-f:.]+$/i.test(text) || !text.includes(":")) return false;
  if ((text.match(/::/g) ?? []).length > 1 || text.includes(":::")) return false;
  const tail = text.split(":").pop() ?? "";
  const dotted = tail.includes(".");
  if (dotted && !V4.test(tail)) return false;
  const groups = text.split(":").filter((g) => g !== "");
  const count = groups.length + (dotted ? 1 : 0);
  if (groups.some((g, i) => !(dotted && i === groups.length - 1) && !/^[0-9a-f]{1,4}$/i.test(g))) return false;
  return text.includes("::") ? count <= 7 : count === 8;
}

/** An address or a prefix as a person writes it: `203.0.113.7`, `198.51.100.0/24`, `2001:db8::/48`. */
export function looksLikeCidr(text: string): boolean {
  const [address = "", length, ...rest] = text.split("/");
  if (rest.length > 0 || address === "") return false;
  const v4 = V4.test(address);
  if (!v4 && !isV6(address)) return false;
  if (length === undefined) return true;
  if (!/^\d{1,3}$/.test(length)) return false;
  return Number(length) <= (v4 ? 32 : 128);
}

/** Digits of the Persian and Arabic-Indic sets are read as the Latin ones, since an address is typed on whichever keyboard is in use. */
export const latinDigits = (text: string): string =>
  text.replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 0x6f0)).replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x660));

export type ParsedCidrs = {items: string[]; bad: {index: number; text: string}[]; tooMany: boolean};

/** One address or prefix to a line, or separated by commas, spaces or semicolons: what a paste from a router's page looks like. Repeats are dropped. */
export function parseCidrs(text: string): ParsedCidrs {
  const seen = new Set<string>();
  const items: string[] = [];
  const bad: ParsedCidrs["bad"] = [];
  const pieces = latinDigits(text)
    .split(/[\s,;،؛]+/)
    .filter(Boolean);
  for (const piece of pieces) {
    if (seen.has(piece)) continue;
    seen.add(piece);
    if (!looksLikeCidr(piece)) bad.push({index: items.length, text: piece});
    items.push(piece);
  }
  return {items, bad, tooMany: items.length > MAX_CIDRS};
}

export type ClaimStateWord = "active" | "pending_proof" | "grace" | "suspended";

/** The proof button is offered on a claim that proof can still change: waiting, in grace, or active and not proven. Not on a suspended one, nor one that waits for an administrator. */
export const canProve = (c: Pick<IPClaim, "state" | "proven" | "needs_admin">): boolean => c.state !== "suspended" && !c.needs_admin && (c.state !== "active" || !c.proven);

/** A live challenge, or null: one that has not expired by `now`. */
export const liveChallenge = (c: Pick<IPClaim, "challenge">, now: number) => (c.challenge && Date.parse(c.challenge.expires_at) > now ? c.challenge : null);

// What the proof dialog takes from the server is put into a URL and into shell lines the person pastes, so it is checked for its shape first
// (defence in depth: today the label comes from our database and the address is the pair’s own). A challenge label is one DNS label of
// letters and digits, a name is dot-separated labels with no label starting with a hyphen (so none can read as an option), and an address is bare.
const PROBE_LABEL = /^[a-z0-9]{1,63}$/;
const DNS_NAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const SCHEME = "https";

export const isDnsName = (text: string): boolean => text.length <= 253 && DNS_NAME.test(text);
/** An address with no prefix length: what `dig @` and `nslookup` take as a server. */
export const isBareIp = (text: string): boolean => !text.includes("/") && looksLikeCidr(text);
/** A probe name: `<label>.<rest>` with a safe label and a safe name as a whole. */
export const isProbeHost = (host: string): boolean => isDnsName(host) && PROBE_LABEL.test(host.split(".")[0] ?? "");

/** `<label>.verify.<zone>` from the zone of a Resolver host (everything after its first label), or null while there is no zone or the label is odd. */
export function verifyHostOf(label: string, resolverHost: string | undefined): string | null {
  if (!resolverHost || !PROBE_LABEL.test(label)) return null;
  const dot = resolverHost.indexOf(".");
  const host = dot < 1 ? null : `${label}.verify.${resolverHost.slice(dot + 1)}`;
  return host !== null && isProbeHost(host) ? host : null;
}

/** The three commands the proof dialog copies, for a name and the first address of the pair, or null when either has an odd shape. */
export function proofCommands(host: string, dns1: string) {
  if (!isProbeHost(host) || !isBareIp(dns1)) return null;
  return {
    dig: `dig TXT ${host} @${dns1}`,
    digTcp: `dig +tcp TXT ${host} @${dns1}`,
    nslookup: `nslookup -vc -type=TXT ${host} ${dns1}`,
  };
}

/** Whether the proof's fetch may be made from this page: the host is one label under the verify origin the page's policy allows (spec 15.3). */
export function inVerifyOrigin(host: string, verifyOrigin: string | readonly string[] | null): boolean {
  if (!isProbeHost(host)) return false;
  const origins = typeof verifyOrigin === "string" ? [verifyOrigin] : (verifyOrigin ?? []);
  return origins.some((origin) => {
    const suffix = origin.replace(/^https:\/\/\*/, "");
    return suffix.startsWith(".verify.") && host.endsWith(suffix) && host.length > suffix.length && !host.slice(0, -suffix.length).includes(".");
  });
}

/**
 * What protects an authorized address from a delete (T-263): it is the address of this browser, or it is the last one while Require is on.
 * `total` is how many the Endpoint holds; the screen knows it only from the pages it loaded, so while more pages may exist a row is not called
 * the last (the server refuses a delete of the last one all the same, with `last_authorized`).
 */
export type Protection = "current" | "last" | null;
export function protectionOf(row: Pick<AuthorizedIP, "is_current">, requireOn: boolean, loaded: number, complete: boolean): Protection {
  if (row.is_current) return "current";
  if (requireOn && complete && loaded <= 1) return "last";
  return null;
}

/** A selection of authorized rows that a delete would leave empty under Require. */
export const emptiesRequire = (requireOn: boolean, loaded: number, complete: boolean, selected: number): boolean => requireOn && complete && selected >= loaded;

/** The URL the browser fetches for the probe, built by the URL parser and kept only when its host is the one that was checked. Null otherwise. */
export function probeUrl(host: string, verifyOrigin: string | readonly string[] | null): string | null {
  if (!inVerifyOrigin(host, verifyOrigin)) return null;
  try {
    const url = new URL(`${SCHEME}://${host}/v`);
    return url.hostname === host.toLowerCase() && url.port === "" && url.username === "" ? url.href : null;
  } catch {
    return null;
  }
}

// Plain DNS counts one identity per active or grace claim while the Endpoint has it on (spec p3 3.3), and each identity has its own stack. A
// write that removes such a claim empties that identity's stack, so every locked profile in it is needed, not any one (S6-r3-5).
const holdsIdentity = (claim: Pick<IPClaim, "state">): boolean => claim.state === "active" || claim.state === "grace";

/** Whether releasing this claim takes away a Plain DNS identity of the Endpoint. */
export const releaseEmptiesStack = (legacyDns: boolean, claim: Pick<IPClaim, "state">): boolean => legacyDns && holdsIdentity(claim);

/**
 * Whether deleting a Dynamic DNS host takes the stack away: under Require it does, and with Plain DNS on it releases the claims the host's
 * addresses made. The claims of one host are not told apart on the page, so any claim from Dynamic DNS counts; while they are not read yet
 * the answer is the cautious one.
 */
export function hostDeleteEmptiesStack(requireOn: boolean, legacyDns: boolean, claims: readonly Pick<IPClaim, "state" | "source">[] | undefined): boolean {
  if (requireOn) return true;
  if (!legacyDns) return false;
  return claims === undefined || claims.some((c) => c.source === "ddns" && holdsIdentity(c));
}
