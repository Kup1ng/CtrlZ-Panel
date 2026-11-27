import {readFileSync} from "node:fs";

import {runSessionEnd} from "@ctrlz/api-client/sessionEnd.ts";
import {afterEach, describe, expect, it, vi} from "vitest";

import {claimHolds, identifies, isIpv4, pairIsIpv6, readClosed, shouldRemind, writeClosed} from "./freeDnsModel.ts";

// T-557: the rules of the reminder and of the IPv6 pair warning.

describe("claimHolds", () => {
  it("matches an address inside the prefix and refuses one outside it", () => {
    expect(claimHolds("203.0.113.7/32", "203.0.113.7")).toBe(true);
    expect(claimHolds("203.0.113.7/32", "203.0.113.8")).toBe(false);
    expect(claimHolds("198.51.100.0/24", "198.51.100.200")).toBe(true);
    expect(claimHolds("198.51.100.0/24", "198.51.101.1")).toBe(false);
    expect(claimHolds("192.0.2.64/26", "192.0.2.127")).toBe(true);
    expect(claimHolds("192.0.2.64/26", "192.0.2.128")).toBe(false);
  });
  it("holds nothing for what is not an IPv4 prefix and address", () => {
    expect(claimHolds("2001:db8::/48", "203.0.113.7")).toBe(false);
    expect(claimHolds("203.0.113.0/33", "203.0.113.7")).toBe(false);
    expect(claimHolds("203.0.113.0", "203.0.113.7")).toBe(false);
    expect(claimHolds("203.0.113.0/24", "2001:db8::1")).toBe(false);
  });
  it("a /0 holds every address", () => {
    expect(claimHolds("0.0.0.0/0", "8.8.8.8")).toBe(true);
  });
});

describe("shouldRemind", () => {
  const base = {enabled: true as boolean | null, legacyDns: true, ip: "203.0.113.9" as string | undefined, claims: [] as {cidr: string; state: string}[] | undefined, closedFor: null as string | null};
  it("shows for an unclaimed IPv4 address while free DNS is on", () => {
    expect(shouldRemind(base)).toBe(true);
  });
  it("is quiet while the switch is off or not known: the text is the one that depends on it", () => {
    expect(shouldRemind({...base, enabled: false})).toBe(false);
    expect(shouldRemind({...base, enabled: null})).toBe(false);
  });
  it("is quiet without Plain DNS, for an IPv6 browser, and while the claims are unread", () => {
    expect(shouldRemind({...base, legacyDns: false})).toBe(false);
    expect(shouldRemind({...base, ip: "2001:db8::9"})).toBe(false);
    expect(shouldRemind({...base, ip: undefined})).toBe(false);
    expect(shouldRemind({...base, claims: undefined})).toBe(false);
  });
  it("counts an active and a grace claim that holds the address, and no other state", () => {
    expect(shouldRemind({...base, claims: [{cidr: "203.0.113.9/32", state: "active"}]})).toBe(false);
    expect(shouldRemind({...base, claims: [{cidr: "203.0.113.0/24", state: "grace"}]})).toBe(false);
    expect(shouldRemind({...base, claims: [{cidr: "203.0.113.9/32", state: "pending_proof"}]})).toBe(true);
    expect(shouldRemind({...base, claims: [{cidr: "203.0.113.9/32", state: "suspended"}]})).toBe(true);
    expect(shouldRemind({...base, claims: [{cidr: "203.0.113.10/32", state: "active"}]})).toBe(true);
  });
  it("stays closed for the address it was closed for, and comes back when the address changes", () => {
    expect(shouldRemind({...base, closedFor: "203.0.113.9"})).toBe(false);
    expect(shouldRemind({...base, closedFor: "203.0.113.8"})).toBe(true);
  });
});

describe("pairIsIpv6, identifies, isIpv4", () => {
  it("is IPv6 when either address is", () => {
    expect(pairIsIpv6("2001:db8::53", "2001:db8::54")).toBe(true);
    expect(pairIsIpv6("203.0.113.53", "2001:db8::54")).toBe(true);
    expect(pairIsIpv6("203.0.113.53", "203.0.113.54")).toBe(false);
    expect(pairIsIpv6(undefined, undefined)).toBe(false);
  });
  it("identifies only active and grace", () => {
    expect(["active", "grace", "pending_proof", "suspended"].map((state) => identifies({state}))).toEqual([true, true, false, false]);
  });
  it("reads a dotted quad only", () => {
    expect(isIpv4("203.0.113.7")).toBe(true);
    expect(isIpv4("203.0.113.256")).toBe(false);
    expect(isIpv4("2001:db8::1")).toBe(false);
  });
});

// V1-r1-6: the closed address is a person's public IPv4 address; it does not outlive the session on a shared computer.
describe("the closed reminders at the end of a session", () => {
  afterEach(() => vi.unstubAllGlobals());
  const storage = () => {
    const items = new Map<string, string>([["ctrlz.theme", "dark"]]);
    return {
      items,
      getItem: (k: string) => items.get(k) ?? null,
      setItem: (k: string, v: string) => void items.set(k, v),
      removeItem: (k: string) => void items.delete(k),
      key: (i: number) => [...items.keys()][i] ?? null,
      get length() {
        return items.size;
      },
    };
  };
  it("removes every ctrlz.freeDnsRemind key and the memory of a close, and leaves other keys alone", () => {
    const local = storage();
    vi.stubGlobal("window", {localStorage: local, addEventListener: () => undefined, removeEventListener: () => undefined});
    writeClosed("ep-1", "203.0.113.200");
    writeClosed("ep-2", "203.0.113.201");
    expect([...local.items.keys()].filter((k) => k.startsWith("ctrlz.freeDnsRemind."))).toHaveLength(2);
    runSessionEnd();
    expect([...local.items.keys()]).toEqual(["ctrlz.theme"]);
    expect(readClosed("ep-1")).toBeNull();
    expect(readClosed("ep-2")).toBeNull();
  });
});

// V1-r2-2: the clear is registered when freeDnsModel loads, so it must load in every page, not only where the Endpoint chunk does. The
// shell's provider is on every page of the panel and the admin; a person who closes a reminder, reloads on the dashboard and logs out
// there would otherwise leave the sign-in address in localStorage.
describe("the session-end clear is loaded by the shell", () => {
  it("is imported for its effect by AppProviders", () => {
    const text = readFileSync(new URL("../providers/AppProviders.tsx", import.meta.url), "utf8");
    expect(text).toMatch(/^import "\.\.\/freeDns\/freeDnsModel\.ts";$/m);
  });
});
