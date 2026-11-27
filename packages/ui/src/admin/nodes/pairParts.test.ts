import {nodeFixture, pairFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import {describe, expect, it} from "vitest";

import {advertisedNode, answerState, byIdMap, changeKind, maybeBehind, noSlotFree, offers, pairWarnings, refusals, revokedMembers, switchWarnings} from "./pairParts.ts";

// T-341. The words the Pair page says before a change is sent: which node answers, who can be chosen, what each change does (every warning of
// SC 8a.9 "F0 reads no tracker"), and what the page refuses with its reason.

const NOW = Date.parse("2026-11-24T10:00:00Z");
const fresh = (over = {}) => nodeFixture({last_heartbeat_at: new Date(NOW - 20_000).toISOString(), ...over});
const a = fresh({slot: 1, name: "a"});
const b = fresh({slot: 2, name: "b"});
const c = fresh({slot: 3, name: "c"});
const d = fresh({slot: 4, name: "d"});

describe("advertisedNode", () => {
  const pair = pairFixture(a, b);
  it("is the primary while it is not withdrawn", () => {
    expect(advertisedNode(pair, byIdMap([a, b]))).toMatchObject({kind: "primary", node: {name: "a"}});
    expect(advertisedNode(pair, byIdMap([a, {...b, dns_withdrawn: true}]))).toMatchObject({kind: "primary"});
  });
  it("is the fallback when the primary is withdrawn or held and the fallback is not", () => {
    expect(advertisedNode(pair, byIdMap([{...a, dns_withdrawn: true}, b]))).toMatchObject({kind: "fallback", node: {name: "b"}});
    expect(advertisedNode(pair, byIdMap([{...a, dns_withdrawn: true, dns_hold: true}, b]))).toMatchObject({kind: "fallback"});
  });
  it("is nobody when both are withdrawn, and unknown when a node is not in the list", () => {
    expect(advertisedNode(pair, byIdMap([{...a, dns_withdrawn: true}, {...b, dns_withdrawn: true}])).kind).toBe("none");
    expect(advertisedNode(pair, byIdMap([a])).kind).toBe("unknown");
  });
});

describe("offers", () => {
  const pending = fresh({slot: 3, name: "p", status: "pending"});
  const revoked = fresh({slot: 4, name: "r", status: "revoked"});
  it("offers an active node in no pair, and says why not for the others", () => {
    const pairs = [pairFixture(a, b)];
    const got = offers([a, b, c, pending, revoked], pairs);
    expect(got.map((o) => [o.node.name, o.reason])).toEqual([
      ["a", "inPair"],
      ["b", "inPair"],
      ["c", null],
      ["p", "pending"],
      ["r", "revoked"],
    ]);
    expect(got[0]!.peerName).toBe("b");
  });
  it("does not count the pair being edited against its own two nodes", () => {
    const pair = pairFixture(a, b);
    expect(offers([a, b, c], [pair], pair).map((o) => o.reason)).toEqual([null, null, null]);
  });
});

describe("changeKind", () => {
  const pair = pairFixture(a, b);
  it("tells a new pair, a swap, a replacement and no change", () => {
    expect(changeKind({primaryId: a.id, fallbackId: b.id})).toBe("create");
    expect(changeKind({primaryId: a.id, fallbackId: b.id, editing: pair})).toBe("same");
    expect(changeKind({primaryId: b.id, fallbackId: a.id, editing: pair})).toBe("swap");
    expect(changeKind({primaryId: a.id, fallbackId: c.id, editing: pair})).toBe("replace");
  });
});

describe("answerState (PG-r1-3: one node of a pair is advertised)", () => {
  const pair = pairFixture(a, b);
  const paired = (n: typeof a) => ({...n, pair_peer_id: n.id === a.id ? b.id : a.id});
  it("calls only the advertised node advertised, and its healthy peer standby", () => {
    expect(answerState(paired(a), [pair], [a, b])).toBe("advertised");
    expect(answerState(paired(b), [pair], [a, b])).toBe("standby");
  });
  it("moves the word to the fallback when the primary is withdrawn or held", () => {
    const out = {...a, dns_withdrawn: true};
    expect(answerState(paired(b), [pair], [out, b])).toBe("advertised");
    expect(answerState(paired(out), [pair], [out, b])).toBe("withdrawn");
    expect(answerState(paired({...out, dns_hold: true}), [pair], [out, b])).toBe("held");
  });
  it("does not guess when the pairs or the nodes are not in, or a node is in no pair", () => {
    expect(answerState(paired(b), undefined, [a, b])).toBe("unknown");
    expect(answerState(paired(b), [pair], undefined)).toBe("unknown");
    expect(answerState(paired(b), [pair], [b])).toBe("unknown");
    expect(answerState(c, [pair], [a, b, c])).toBe("unpaired");
  });
});

describe("pairWarnings (SC 8a.9, F0 reads no tracker)", () => {
  const warn = (change: Parameters<typeof pairWarnings>[0], nodes: ReturnType<typeof fresh>[], pairs = [] as ReturnType<typeof pairFixture>[]) =>
    pairWarnings(change, nodes, pairs, NOW).map((w) => w.id);

  it("says nothing for a pair of two healthy nodes and nothing for no change", () => {
    expect(warn({primaryId: a.id, fallbackId: b.id}, [a, b])).toEqual(["twoNew"]);
    const pair = pairFixture(a, b);
    expect(warn({primaryId: a.id, fallbackId: b.id, editing: pair}, [a, b], [pair])).toEqual([]);
  });
  it("says that a withdrawn primary gives the answer to the fallback, and that a new fallback gets it with no check", () => {
    const dead = {...a, dns_withdrawn: true};
    expect(warn({primaryId: a.id, fallbackId: b.id}, [dead, b])).toEqual(["primaryWithdrawn", "fallbackNew", "twoNew"]);
  });
  it("says that a held primary hands the answer to its peer, and that a held fallback beside a withdrawn primary has its hold cleared", () => {
    const heldPrimary = {...a, dns_withdrawn: true, dns_hold: true};
    expect(warn({primaryId: a.id, fallbackId: b.id}, [heldPrimary, b])).toContain("primaryHeld");
    const heldFallback = {...b, dns_withdrawn: true, dns_hold: true};
    const got = warn({primaryId: a.id, fallbackId: b.id}, [{...a, dns_withdrawn: true}, heldFallback]);
    expect(got).toContain("fallbackHeld");
    // A held fallback is not also "both withdrawn": its own sentence says what happens to it.
    expect(got).not.toContain("bothWithdrawn");
  });
  it("says that two withdrawn nodes can give the answer to one that does not answer", () => {
    expect(warn({primaryId: a.id, fallbackId: b.id}, [{...a, dns_withdrawn: true}, {...b, dns_withdrawn: true}])).toContain("bothWithdrawn");
  });
  it("says to pair one new node at a time, and names only nodes that are new", () => {
    const pair = pairFixture(a, b);
    expect(warn({primaryId: c.id, fallbackId: d.id}, [a, b, c, d], [pair])).toEqual(["twoNew"]);
    // Replacing one node of a pair puts one new node in, which is the allowed way.
    expect(warn({primaryId: a.id, fallbackId: c.id, editing: pair}, [a, b, c], [pair])).toEqual([]);
  });
  it("says that a node that may be behind should be looked at first, and who", () => {
    const behind = {...c, applied_seq_lag: 3};
    const got = pairWarnings({primaryId: a.id, fallbackId: c.id}, [a, behind], [], NOW).find((w) => w.id === "behind");
    expect(got?.names).toEqual(["c"]);
    const silent = {...c, last_heartbeat_at: new Date(NOW - 3_600_000).toISOString()};
    expect(pairWarnings({primaryId: a.id, fallbackId: c.id}, [a, silent], [], NOW).some((w) => w.id === "behind")).toBe(true);
  });
  it("says that a new primary is withdrawn by the change, and that the answer goes at once to the fallback that stays (PG-r1-2)", () => {
    // The compromise runbook, step 2: the pair (a, b) becomes (c, b) with c a node in no pair.
    const pair = pairFixture(a, b);
    expect(warn({primaryId: c.id, fallbackId: b.id, editing: pair}, [a, b, c], [pair])).toEqual(["primaryWithdrawn"]);
    // The node that receives the answer may be behind: the old fallback is named, not only the new node.
    const behind = {...b, applied_seq_lag: 5};
    const got = pairWarnings({primaryId: c.id, fallbackId: b.id, editing: pair}, [a, behind, c], [pair], NOW);
    expect(got.map((w) => w.id)).toEqual(["primaryWithdrawn", "behind"]);
    expect(got[1]!.names).toEqual(["b"]);
    // A held fallback loses its hold, and a withdrawn one may get an answer it cannot give.
    const held = {...b, dns_hold: true, dns_withdrawn: true};
    expect(warn({primaryId: c.id, fallbackId: b.id, editing: pair}, [a, held, c], [pair])).toContain("fallbackHeld");
    const out = {...b, dns_withdrawn: true};
    expect(warn({primaryId: c.id, fallbackId: b.id, editing: pair}, [a, out, c], [pair])).toContain("bothWithdrawn");
    // Keeping the primary and bringing a new fallback does not withdraw anything.
    expect(warn({primaryId: a.id, fallbackId: c.id, editing: pair}, [a, b, c], [pair])).toEqual([]);
  });
  it("says that a role swap changes no peer and so nothing checks the nodes", () => {
    const pair = pairFixture(a, b);
    const got = warn({primaryId: b.id, fallbackId: a.id, editing: pair}, [a, b], [pair]);
    expect(got).toEqual(["swap"]);
    const behind = {...b, applied_seq_lag: 2};
    expect(warn({primaryId: b.id, fallbackId: a.id, editing: pair}, [a, behind], [pair])).toEqual(["swap", "behind"]);
  });
  it("says to release or replace a held fallback before changing the primary it stands behind", () => {
    const pair = pairFixture(a, b);
    const held = {...b, dns_hold: true, dns_withdrawn: true};
    expect(warn({primaryId: c.id, fallbackId: b.id, editing: pair}, [a, held, c], [pair])).toContain("heldFallbackFirst");
    // Changing only the fallback is not changing the primary.
    expect(warn({primaryId: a.id, fallbackId: c.id, editing: pair}, [a, held, c], [pair])).not.toContain("heldFallbackFirst");
  });
});

describe("switchWarnings (a switch of the global pair changes no peer)", () => {
  it("says no check runs, and names the nodes that may be behind or held", () => {
    const behind = {...b, applied_seq_lag: 4};
    const held = {...a, dns_hold: true};
    const got = switchWarnings(pairFixture(held, behind), [held, behind], NOW);
    expect(got.map((w) => w.id)).toEqual(["swap", "behind", "primaryHeld"]);
    expect(got[1]!.names).toEqual(["b"]);
    expect(switchWarnings(pairFixture(a, b), [a, b], NOW).map((w) => w.id)).toEqual(["swap"]);
  });
});

describe("refusals (what the page does not send)", () => {
  it("refuses an empty choice, the same node twice and no change", () => {
    expect(refusals({primaryId: null, fallbackId: b.id}, [a, b], []).map((r) => r.id)).toEqual(["missing"]);
    expect(refusals({primaryId: a.id, fallbackId: a.id}, [a, b], []).map((r) => r.id)).toEqual(["sameNode"]);
    const pair = pairFixture(a, b);
    expect(refusals({primaryId: a.id, fallbackId: b.id, editing: pair}, [a, b], [pair]).map((r) => r.id)).toEqual(["same"]);
  });
  it("refuses a repeated address among the two nodes and the nodes of other pairs, naming them", () => {
    const twin = fresh({slot: 3, name: "twin", dns_advertised_ip: a.dns_advertised_ip as string});
    const got = refusals({primaryId: a.id, fallbackId: twin.id}, [a, twin], []);
    expect(got.map((r) => r.id)).toEqual(["duplicateAddress"]);
    expect(got[0]!.names.sort()).toEqual(["a", "twin"]);
    // A node of another pair holds the address the new fallback advertises.
    const other = pairFixture(b, d);
    const clash = fresh({slot: 3, name: "clash", dns_advertised_ip: b.dns_advertised_ip as string});
    expect(refusals({primaryId: a.id, fallbackId: clash.id}, [a, b, d, clash], [other]).map((r) => r.id)).toEqual(["duplicateAddress"]);
  });
  it("refuses two DNS address families in one pair", () => {
    const v6 = fresh({slot: 3, name: "v6", dns_advertised_ip: "2001:db8::3", proxy_advertised_ip: "2001:db8::4"});
    expect(refusals({primaryId: a.id, fallbackId: v6.id}, [a, v6], []).map((r) => r.id)).toEqual(["mixedFamilies"]);
    const v6b = fresh({slot: 4, name: "v6b", dns_advertised_ip: "2001:db8::5", proxy_advertised_ip: "2001:db8::6"});
    expect(refusals({primaryId: v6.id, fallbackId: v6b.id}, [v6, v6b], [])).toEqual([]);
    // The proxy address is not judged: another family, a shared one or none does not stop the save (PG-r3-1).
    const px6 = fresh({slot: 5, name: "px6", proxy_advertised_ip: "2001:db8::7"});
    expect(refusals({primaryId: a.id, fallbackId: px6.id}, [a, px6], [])).toEqual([]);
    const pxShared = fresh({slot: 6, name: "pxs", proxy_advertised_ip: a.proxy_advertised_ip as string});
    expect(refusals({primaryId: a.id, fallbackId: pxShared.id}, [a, pxShared], [])).toEqual([]);
  });
  it("lets a clean change through", () => {
    expect(refusals({primaryId: a.id, fallbackId: b.id}, [a, b, c], [])).toEqual([]);
  });
});

describe("the small helpers", () => {
  it("maybeBehind: lag, no contact, or a stale contact", () => {
    expect(maybeBehind(a, NOW)).toBe(false);
    expect(maybeBehind({...a, applied_seq_lag: 1}, NOW)).toBe(true);
    expect(maybeBehind({...a, last_heartbeat_at: undefined}, NOW)).toBe(true);
    expect(maybeBehind({...a, last_heartbeat_at: new Date(NOW - 600_000).toISOString()}, NOW)).toBe(true);
  });
  it("noSlotFree is true at the limit", () => {
    expect(noSlotFree([a, b, c], 4)).toBe(false);
    expect(noSlotFree([a, b, c, d], 4)).toBe(true);
  });
});

describe("revokedMembers (PG-r2-6: a revoked node stays in its pair and stays advertised)", () => {
  const pair = {primary_node_id: a.id, fallback_node_id: b.id};
  it("names the revoked members, and none when both are active", () => {
    expect(revokedMembers(pair, byIdMap([a, b]))).toEqual([]);
    expect(revokedMembers(pair, byIdMap([{...a, status: "revoked"}, b])).map((n) => n.name)).toEqual(["a"]);
    expect(revokedMembers(pair, byIdMap([{...a, status: "revoked"}, {...b, status: "revoked"}])).map((n) => n.name)).toEqual(["a", "b"]);
  });
  it("still advertises a revoked primary, because the route changes only its status", () => {
    const out = {...a, status: "revoked" as const};
    expect(advertisedNode(pair, byIdMap([out, b]))).toMatchObject({kind: "primary", node: {status: "revoked"}});
  });
  it("skips a node the page does not have", () => {
    expect(revokedMembers(pair, byIdMap([b]))).toEqual([]);
  });
});
