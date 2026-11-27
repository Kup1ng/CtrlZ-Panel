import {onSessionEnd} from "@ctrlz/api-client/sessionEnd.ts";

// The rules behind the free DNS texts of Plan T-557, without React so a plain test holds them.

const V4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export const isIpv4 = (text: string): boolean => V4.test(text);

/** A colon is what an IPv6 address has and an IPv4 one never has: the advertised addresses come from the API, which has judged them already. */
export const isIpv6 = (text: string): boolean => text.includes(":");

const toNumber = (ip: string): number => ip.split(".").reduce((n, part) => n * 256 + Number(part), 0);

/** Whether the IPv4 address `ip` is inside the IPv4 prefix `cidr` (`203.0.113.0/24`). A claim is always IPv4; anything else holds nothing. */
export function claimHolds(cidr: string, ip: string): boolean {
  const [net = "", bits = ""] = cidr.split("/");
  if (!isIpv4(net) || !isIpv4(ip) || !/^\d{1,2}$/.test(bits) || Number(bits) > 32) return false;
  const length = Number(bits);
  if (length === 0) return true;
  const shift = 2 ** (32 - length);
  return Math.floor(toNumber(net) / shift) === Math.floor(toNumber(ip) / shift);
}

/** The claims the node compiles: `active` and `grace` (spec p3 3.3 and 4.1). A `pending_proof` or `suspended` one identifies nobody. */
export const identifies = (claim: {state: string}): boolean => claim.state === "active" || claim.state === "grace";

/** The advertised pair is IPv6 when either address is: claims are IPv4 only, so Plain DNS over it is never matched to an Endpoint. */
export const pairIsIpv6 = (primary?: string, fallback?: string): boolean => [primary, fallback].some((ip) => ip !== undefined && isIpv6(ip));

/**
 * Whether the add-address reminder shows: free DNS is on (the one state in which an unclaimed network gets unfiltered answers), the Endpoint
 * has Plain DNS on, the panel sees the browser at an IPv4 address, no claim that identifies holds that address, and the person has not
 * closed the reminder for this very address.
 */
export function shouldRemind(input: {
  enabled: boolean | null;
  legacyDns: boolean;
  ip: string | undefined;
  claims: readonly {cidr: string; state: string}[] | undefined;
  closedFor: string | null;
}): boolean {
  const {enabled, legacyDns, ip, claims, closedFor} = input;
  if (enabled !== true || !legacyDns || !ip || !isIpv4(ip) || !claims) return false;
  if (closedFor === ip) return false;
  return !claims.some((claim) => identifies(claim) && claimHolds(claim.cidr, ip));
}

const CLOSED_PREFIX = "ctrlz.freeDnsRemind.";
const CLOSED_KEY = (endpointId: string) => `${CLOSED_PREFIX}${endpointId}`;

// A close made while storage is refused still holds for the rest of the visit, from memory; the listeners are the components that show the reminder.
const memory = new Map<string, string>();
const listeners = new Set<() => void>();

/** The address the reminder was closed for, or `null`. Storage is a convenience: it may be missing or throw, and the reminder then shows again. */
export function readClosed(endpointId: string): string | null {
  const remembered = memory.get(endpointId);
  if (remembered !== undefined) return remembered;
  try {
    return window.localStorage.getItem(CLOSED_KEY(endpointId));
  } catch {
    return null;
  }
}

export function writeClosed(endpointId: string, ip: string): void {
  memory.set(endpointId, ip);
  try {
    window.localStorage.setItem(CLOSED_KEY(endpointId), ip);
  } catch {
    // The reminder comes back at the next visit; nothing else depends on it.
  }
  for (const listener of listeners) listener();
}

/**
 * Forgets every close, in memory and in storage. The value is the public IPv4 address of a sign-in, which belongs to the person who was signed in: it
 * must not stay on a shared computer after logout or the idle cover (V1-r1-6). Every end of a session reaches it through the registry below.
 */
export function clearClosed(): void {
  memory.clear();
  try {
    const keys: string[] = [];
    for (let i = 0; i < window.localStorage.length; i++) {
      const key = window.localStorage.key(i);
      if (key?.startsWith(CLOSED_PREFIX)) keys.push(key);
    }
    for (const key of keys) window.localStorage.removeItem(key);
  } catch {
    // Storage is refused or absent: there is nothing of ours in it to remove.
  }
  for (const listener of listeners) listener();
}

onSessionEnd(clearClosed);

export function subscribeClosed(listener: () => void): () => void {
  listeners.add(listener);
  window.addEventListener("storage", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", listener);
  };
}
