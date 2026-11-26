import {readFileSync} from "node:fs";

import {describe, expect, it} from "vitest";

import {claimFixture, freeCounterFixture, nodeFixture, pairFixture} from "../../testing/adminFixtures.ts";
import {groupCounters} from "./freeDns.ts";
import {contactState, hubParts, nodeHealth, permilleToPercent, reportClaims, reportsStalled, STALE_AFTER_MS} from "./nodes.ts";
import {globalPairAddresses} from "./pairs.ts";

// T-339: the health a row shows is a function of what the database holds. T-556: the addresses free DNS gives out are the advertised
// DNS addresses of the global pair, primary first.

const NOW = Date.parse("2026-11-24T10:00:00Z");
const ago = (ms: number) => new Date(NOW - ms).toISOString();

describe("contactState (T-339)", () => {
  it("is never without a Heartbeat, recent inside two missed ones and stale after", () => {
    expect(contactState({}, NOW)).toBe("never");
    expect(contactState({last_heartbeat_at: ago(60_000)}, NOW)).toBe("recent");
    expect(contactState({last_heartbeat_at: ago(STALE_AFTER_MS + 1)}, NOW)).toBe("stale");
  });
  it("reads a date that does not parse, or one in the future, as recent and never as a fault", () => {
    expect(contactState({last_heartbeat_at: "not a date"}, NOW)).toBe("recent");
    expect(contactState({last_heartbeat_at: new Date(NOW + 60_000).toISOString()}, NOW)).toBe("recent");
  });
});

describe("nodeHealth (T-339)", () => {
  const fresh = {last_heartbeat_at: ago(10_000)};
  it("puts a revoked or pending node first, whatever else it reports", () => {
    expect(nodeHealth(nodeFixture({status: "revoked", ...fresh}), NOW)).toBe("revoked");
    expect(nodeHealth(nodeFixture({status: "pending", ...fresh}), NOW)).toBe("pending");
  });
  it("then the contact, then the failover flags in the order isolated, held, withdrawn", () => {
    const silent = nodeFixture();
    delete (silent as {last_heartbeat_at?: string}).last_heartbeat_at;
    expect(nodeHealth(silent, NOW)).toBe("no_contact");
    expect(nodeHealth(nodeFixture({last_heartbeat_at: ago(999_999)}), NOW)).toBe("out_of_touch");
    expect(nodeHealth(nodeFixture({...fresh, isolated: true, dns_hold: true, dns_withdrawn: true}), NOW)).toBe("isolated");
    expect(nodeHealth(nodeFixture({...fresh, dns_hold: true, dns_withdrawn: true}), NOW)).toBe("held");
    expect(nodeHealth(nodeFixture({...fresh, dns_withdrawn: true}), NOW)).toBe("withdrawn");
    expect(nodeHealth(nodeFixture(fresh), NOW)).toBe("serving");
  });
});

describe("hubParts", () => {
  it("returns nothing for a NodeView that carries none of the hub's fields, so the screen says it is not reported", () => {
    expect(hubParts(nodeFixture())).toEqual({});
  });
  it("returns what is there, and only well-formed values", () => {
    const node = {...nodeFixture(), f3_unmet: ["s_fit"], drain_state: "draining", revocation_pending: true, health: "degraded"};
    expect(hubParts(node)).toEqual({f3_unmet: ["s_fit"], drain_state: "draining", revocation_pending: true, health: "degraded"});
    expect(hubParts({...nodeFixture(), health: "great", f3_unmet: "x"} as never)).toEqual({});
  });
  it("keeps only the string names of f3_unmet, each once, and reads an unreadable list as not reported (PG-r3-5)", () => {
    const of = (f3_unmet: unknown) => hubParts({...nodeFixture(), f3_unmet} as never);
    expect(of(["a", "a", {condition: "b"}, 3, "", "c"])).toEqual({f3_unmet: ["a", "c"]});
    expect(of([{condition: "hub_fit"}])).toEqual({});
    expect(of([null, 1])).toEqual({});
    // An empty list is a statement: every condition is met.
    expect(of([])).toEqual({f3_unmet: []});
  });
});

// PG-r2-4. The hub-side parts of a node (F3 conditions, drain state, revocation pending) are in the memory of the hub only, so the
// OpenAPI document has none of them by design (p4-nodes 9.2 NodeView) and the pages say "not reported yet". This reads the NodeView of
// the merged document: it has none of the three, a field that looks like a hub-side part must be one `hubParts` reads, and one
// `hubParts` reads must have the type it expects. The day a document carries one under another name, it fails here and not silently in the pages.
describe("NodeView names the hub-side parts the way hubParts reads them (PG-r2-4)", () => {
  const source = readFileSync(new URL("../../generated/admin.d.ts", import.meta.url), "utf8");
  const start = source.indexOf("        NodeView: {");
  const block = source.slice(start, source.indexOf("\n        };", start));
  const props = new Map<string, string>();
  for (const m of block.matchAll(/^ {12}(\w+)\??: ([^;]+);$/gm)) props.set(m[1]!, m[2]!.trim());
  const READ = {f3_unmet: "string[]", drain_state: "string", revocation_pending: "boolean"} as const;
  // What the database already holds, and so is not a hub-side part whatever its name looks like.
  const DATABASE = new Set(["dns_withdrawn", "dns_hold", "dns_last_failback_at", "dns_flap_until", "applied_seq_lag", "isolated"]);

  it("finds the NodeView block", () => {
    expect(start).toBeGreaterThan(0);
    expect(props.has("dns_withdrawn")).toBe(true);
  });
  it("has none of the hub-memory parts, by design", () => {
    for (const name of Object.keys(READ)) expect(props.has(name), name).toBe(false);
  });
  it("has no field that looks like a hub-side part under a name hubParts does not read", () => {
    const looksHub = /(f3|drain|revoc|unmet|condition|health|verdict|peer_view)/i;
    const stray = [...props.keys()].filter((name) => looksHub.test(name) && !DATABASE.has(name) && !(name in READ) && name !== "health");
    expect(stray, "name these in hubParts (api-client nodes.ts) and in nodeParts.ts").toEqual([]);
  });
  it("gives a field hubParts reads the type it expects", () => {
    for (const [name, type] of Object.entries(READ)) {
      if (props.has(name)) expect(props.get(name), name).toBe(type);
    }
    if (props.has("health")) expect(props.get("health")).toMatch(/"healthy" \| "degraded" \| "down"/);
  });
});

describe("permilleToPercent", () => {
  it("keeps one decimal", () => expect(permilleToPercent(912)).toBe(91.2));
});

describe("globalPairAddresses (T-556)", () => {
  const a = nodeFixture({slot: 1});
  const b = nodeFixture({slot: 2});
  const c = nodeFixture({slot: 3});
  it("gives the primary first and the fallback second, each with its advertised DNS address", () => {
    const out = globalPairAddresses([pairFixture(c, a, {is_global: false}), pairFixture(b, a)], [a, b, c]);
    expect(out.map((x) => [x.role, x.ip])).toEqual([
      ["primary", b.dns_advertised_ip],
      ["fallback", a.dns_advertised_ip],
    ]);
  });
  it("gives nothing without a global pair, and leaves out a node that is pending or has no address", () => {
    expect(globalPairAddresses([pairFixture(a, b, {is_global: false})], [a, b])).toEqual([]);
    const revoked = {...b, status: "revoked" as const};
    // A revoked member stays, marked: the pair still advertises it (PG-r3-3).
    expect(globalPairAddresses([pairFixture(a, b)], [a, revoked]).map((x) => [x.role, x.revoked])).toEqual([
      ["primary", false],
      ["fallback", true],
    ]);
    const pending = {...b, status: "pending" as const};
    expect(globalPairAddresses([pairFixture(a, b)], [a, pending]).map((x) => x.role)).toEqual(["primary"]);
    const bare = {...a};
    delete (bare as {dns_advertised_ip?: string}).dns_advertised_ip;
    expect(globalPairAddresses([pairFixture(a, b)], [bare, b]).map((x) => x.role)).toEqual(["fallback"]);
  });
});

describe("groupCounters (T-339)", () => {
  const a = nodeFixture({slot: 1});
  const b = nodeFixture({slot: 2});
  it("sums the hourly rows by node, transport, outcome and rcode, and keeps only those fields", () => {
    const rows = [
      freeCounterFixture(a, {bucket_start: "2026-11-24T08:00:00Z", count: 10}),
      freeCounterFixture(a, {bucket_start: "2026-11-24T09:00:00Z", count: 5}),
      freeCounterFixture(a, {outcome: "rd0", rcode: 5, count: 7}),
      freeCounterFixture(b, {transport: "tcp", count: 1}),
    ];
    const groups = groupCounters(rows);
    expect(groups).toHaveLength(3);
    expect(groups.find((g) => g.node_id === a.id && g.outcome === "answered")?.count).toBe(15);
    for (const g of groups) expect(Object.keys(g).sort()).toEqual(["count", "node_id", "outcome", "rcode", "transport"]);
  });
  it("stops a sum at a safe integer", () => {
    const rows = [freeCounterFixture(a, {count: Number.MAX_SAFE_INTEGER}), freeCounterFixture(a, {count: 10})];
    expect(groupCounters(rows)[0]!.count).toBe(Number.MAX_SAFE_INTEGER);
  });
  it("orders by node and then by count, largest first", () => {
    const rows = [freeCounterFixture(a, {outcome: "rd0", count: 2}), freeCounterFixture(a, {outcome: "answered", count: 9})];
    expect(groupCounters(rows).map((g) => g.outcome)).toEqual(["answered", "rd0"]);
  });
});

describe("reportClaims (p4-nodes 4.5)", () => {
  it("shows a claim once when the route read its instant on two pages, and keeps the newest-first order", () => {
    const one = [claimFixture(1), claimFixture(2), claimFixture(3)];
    const two = [claimFixture(3), claimFixture(4)];
    const all = reportClaims([
      {claims: one, claims_truncated: true, kept_rows: [], kept_truncated: false},
      {claims: two, claims_truncated: false, kept_rows: [], kept_truncated: false},
    ]);
    expect(all.map((c) => c.claim_id)).toEqual([1, 2, 3, 4].map((n) => claimFixture(n).claim_id));
  });
});

describe("reportsStalled (PG-r1-15)", () => {
  const page = (claims: ReturnType<typeof claimFixture>[], truncated: boolean) => ({claims, claims_truncated: truncated, kept_rows: [], kept_truncated: false});
  it("is true when a page adds no new claim though the route says more exist: more than a page share one instant", () => {
    const burst = [claimFixture(1), claimFixture(2), claimFixture(3)];
    expect(reportsStalled([page(burst, true), page(burst, true)])).toBe(true);
  });
  it("is false for the first page, a page with something new, and a last page that is complete", () => {
    const burst = [claimFixture(1), claimFixture(2)];
    expect(reportsStalled([page(burst, true)])).toBe(false);
    expect(reportsStalled([page(burst, true), page([claimFixture(2), claimFixture(3)], true)])).toBe(false);
    expect(reportsStalled([page(burst, true), page(burst, false)])).toBe(false);
  });
});
