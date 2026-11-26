import {nodeFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import {describe, expect, it} from "vitest";

import {
  addressHolder,
  checkFingerprint,
  counterRange,
  drainKey,
  f3ConditionKey,
  FREE_OUTCOMES,
  groupFingerprint,
  HEALTH_LOOK,
  isSafeNow,
  lagState,
  looksLikeIp,
  nodeActions,
  normaliseFingerprint,
  outcomeKey,
  removeBlockedByPair,
  reportsFrom,
  servingCount,
} from "./nodeParts.ts";

// T-339 (the overview's rows), T-546 (the safe date of an address given up), T-556 (the free DNS counters' words).

describe("outcomeKey (T-339)", () => {
  it("knows every FreeOutcome of the shared contract and reads another as other", () => {
    for (const outcome of FREE_OUTCOMES) expect(outcomeKey(outcome)).toBe(outcome);
    expect(outcomeKey("a_new_outcome")).toBe("other");
    expect(outcomeKey("")).toBe("other");
  });
});

describe("HEALTH_LOOK", () => {
  it("gives every state an icon, and the problems a colour that differs from serving", () => {
    for (const [health, look] of Object.entries(HEALTH_LOOK)) expect(look.icon, health).toBeTruthy();
    expect(HEALTH_LOOK.serving.color).toBe("success");
    expect(HEALTH_LOOK.out_of_touch.color).toBe("danger");
    // The icon differs between a good state and a bad one, so the colour is never the only thing that says it.
    expect(HEALTH_LOOK.serving.icon).not.toBe(HEALTH_LOOK.out_of_touch.icon);
    expect(HEALTH_LOOK.serving.icon).not.toBe(HEALTH_LOOK.held.icon);
  });
});

describe("lagState (T-339)", () => {
  const base = {applied_seq: 118, config_head: 120};
  it("has no lag to show for a node that is not active", () => {
    expect(lagState({...base, status: "pending", applied_seq_lag: 2})).toEqual({kind: "none"});
    expect(lagState({...base, status: "revoked", applied_seq_lag: 2})).toEqual({kind: "none"});
  });
  it("is up to date at zero and below, and behind by the count otherwise", () => {
    expect(lagState({...base, status: "active", applied_seq_lag: 0})).toEqual({kind: "upToDate"});
    expect(lagState({...base, status: "active", applied_seq_lag: -1})).toEqual({kind: "upToDate"});
    expect(lagState({...base, status: "active", applied_seq_lag: 2})).toEqual({kind: "behind", count: 2, applied: 118, head: 120});
  });
});

describe("servingCount", () => {
  it("counts the active nodes that serve, out of the active nodes", () => {
    const nodes = [nodeFixture({slot: 1}), nodeFixture({slot: 2, dns_hold: true}), nodeFixture({slot: 3, status: "pending"})];
    expect(servingCount(nodes, (n) => (n.dns_hold ? "held" : "serving"))).toEqual({serving: 1, total: 2});
  });
});

describe("isSafeNow (T-546)", () => {
  const now = Date.parse("2026-12-01T00:00:00Z");
  it("is true on and after the date, false before it, and false for a date that does not parse", () => {
    expect(isSafeNow("2026-12-01T00:00:00Z", now)).toBe(true);
    expect(isSafeNow("2026-12-20T09:00:00Z", now)).toBe(false);
    expect(isSafeNow("2026-11-30T09:00:00Z", now)).toBe(true);
    expect(isSafeNow("soon", now)).toBe(false);
  });
});

describe("counterRange (T-339)", () => {
  const now = Date.parse("2026-11-24T10:20:30Z");
  it("ends with the current hour, in whole hours, so the hour in progress counts and the key stays the same", () => {
    expect(counterRange("day", now)).toEqual({from: "2026-11-23T11:00:00.000Z", to: "2026-11-24T11:00:00.000Z"});
    expect(counterRange("day", now + 1000)).toEqual(counterRange("day", now));
    expect(Date.parse(counterRange("week", now).to) - Date.parse(counterRange("week", now).from)).toBe(168 * 3_600_000);
  });
  it("stays inside the 31 days the route allows", () => {
    const week = counterRange("week", now);
    expect(Date.parse(week.to) - Date.parse(week.from)).toBeLessThanOrEqual(31 * 86_400_000);
  });
});

// T-340: the fingerprint of the host is typed and compared with the record before a node row is made (R19, p4-nodes 4.2 step 4).
const FP = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";

describe("the fingerprint comparison (T-340)", () => {
  it("compares the hex digits and nothing around them: case, colons, spaces and a SHA256 label are not part of it", () => {
    const withColons = FP.toUpperCase().match(/.{2}/g)!.join(":");
    expect(normaliseFingerprint(`SHA256:${withColons}`)).toBe(FP);
    expect(normaliseFingerprint(" ab12 cd34 ")).toBe("ab12cd34");
    expect(checkFingerprint(withColons, FP)).toBe("match");
    expect(checkFingerprint(`  ${FP.toUpperCase()}  `, FP)).toBe("match");
  });

  it("calls a correct beginning partial, a wrong digit a mismatch, and nothing typed empty", () => {
    expect(checkFingerprint("", FP)).toBe("empty");
    expect(checkFingerprint("   ", FP)).toBe("empty");
    expect(checkFingerprint(FP.slice(0, 20), FP)).toBe("partial");
    expect(checkFingerprint(`${FP.slice(0, 19)}0`, FP)).toBe("mismatch");
  });

  it("never matches the fingerprint with one more digit than the record, or a record that has none", () => {
    expect(checkFingerprint(`${FP}0`, FP)).toBe("mismatch");
    expect(checkFingerprint(FP, undefined)).toBe("mismatch");
    expect(checkFingerprint(FP, "")).toBe("mismatch");
  });

  it("groups 64 digits in eight groups of eight, and leaves any other text as it is", () => {
    expect(groupFingerprint(FP)).toHaveLength(8);
    expect(groupFingerprint(FP).join("")).toBe(FP);
    expect(groupFingerprint("SHA256:enrolfixture")).toEqual(["SHA256:enrolfixture"]);
  });
});

describe("looksLikeIp (T-340)", () => {
  it("takes an IPv4 and an IPv6 address and refuses what is neither", () => {
    for (const ok of ["203.0.113.5", "0.0.0.0", "255.255.255.255", "2001:db8::1", "::1", "2001:db8:0:0:0:0:0:1", "::ffff:203.0.113.5"]) expect(looksLikeIp(ok), ok).toBe(true);
    for (const bad of ["", "256.1.1.1", "1.2.3", "1.2.3.4.5", "example.com", "2001:db8::1::2", "2001:db8:::1", "12345::1", "1:2:3:4:5:6:7:8:9", "203.0.113.5/24", "::g"]) expect(looksLikeIp(bad), bad).toBe(false);
  });
});

describe("nodeActions (T-542)", () => {
  const node = (over: Partial<Parameters<typeof nodeActions>[0]> = {}) => ({status: "active" as const, dns_hold: false, dns_withdrawn: false, ...over});
  it("offers Hold to an active node that is not held, and Release only to one that is", () => {
    expect(nodeActions(node())).toMatchObject({hold: true, release: false, force_failback: false, revoke: true, approve: false});
    expect(nodeActions(node({dns_hold: true, dns_withdrawn: true}))).toMatchObject({hold: false, release: true, force_failback: true});
  });
  it("offers a pending node approval and nothing about its answer, and a revoked one removal, hold and release", () => {
    expect(nodeActions(node({status: "pending"}))).toMatchObject({approve: true, hold: false, release: false, force_failback: false, revoke: false, addresses: true});
    expect(nodeActions(node({status: "revoked"}))).toMatchObject({approve: false, revoke: false, hold: true, release: false, force_failback: false, addresses: false, remove: true});
    expect(nodeActions(node({status: "revoked", dns_hold: true, dns_withdrawn: true}))).toMatchObject({hold: false, release: true, force_failback: false});
  });
  it("keeps a paired node from removal, and says so from the pair peer", () => {
    expect(removeBlockedByPair(nodeFixture())).toBe(false);
    expect(removeBlockedByPair(nodeFixture({pair_peer_id: "00000000-0000-4000-8000-000000000099"}))).toBe(true);
  });
});

describe("the names the hub may send (T-542)", () => {
  it("reads a condition or a drain state it does not know as other, never as raw wording", () => {
    expect(f3ConditionKey("peer_view")).toBe("peer_view");
    expect(f3ConditionKey("something_new")).toBe("other");
    expect(drainKey("done")).toBe("done");
    expect(drainKey("")).toBe("other");
  });
});

describe("reportsFrom (p4-nodes 4.5)", () => {
  it("starts at a whole day, so the query is the same all day", () => {
    const noon = Date.parse("2026-11-24T12:34:56Z");
    expect(reportsFrom(7, noon)).toBe("2026-11-17T00:00:00.000Z");
    expect(reportsFrom(30, noon + 3_600_000)).toBe(reportsFrom(30, noon));
  });
});

describe("addressHolder (SC 8a.9, Replacement order)", () => {
  const old = nodeFixture({slot: 1, name: "old", dns_advertised_ip: "203.0.113.10"});
  const fresh = nodeFixture({slot: 2, name: "new", status: "pending", dns_advertised_ip: "203.0.113.10"});
  it("names the node that already holds the DNS address a pending host asks for, whatever the case or spaces", () => {
    expect(addressHolder(fresh, [old, fresh])).toBe("old");
    expect(addressHolder({...fresh, dns_advertised_ip: " 2001:DB8::1 "}, [{...old, dns_advertised_ip: "2001:db8::1"}, fresh])).toBe("old");
  });
  it("says nothing for another address, for the node itself, for another pending row, or while the list is not in", () => {
    expect(addressHolder({...fresh, dns_advertised_ip: "203.0.113.99"}, [old, fresh])).toBeUndefined();
    expect(addressHolder(old, [old])).toBeUndefined();
    expect(addressHolder(fresh, [{...old, status: "pending"}, fresh])).toBeUndefined();
    expect(addressHolder(fresh, undefined)).toBeUndefined();
  });
});
