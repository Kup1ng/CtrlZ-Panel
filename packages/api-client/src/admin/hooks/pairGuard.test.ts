import {describe, expect, it} from "vitest";

import {nodeFixture, pairFixture} from "../../testing/adminFixtures.ts";
import {pairGuardShape, samePairGuard} from "./pairGuard.ts";

// PG-r2-5, PG-r2-8. What a pair form compares before the write that follows the fresh code: the pairs that hold its nodes, whether a global
// pair exists, and the flags the SC 8a.9 warnings were made from.

const NOW = Date.parse("2026-11-24T10:00:00Z");
const fresh = (over = {}) => nodeFixture({last_heartbeat_at: new Date(NOW - 20_000).toISOString(), ...over});
const a = fresh({slot: 1, name: "a"});
const b = fresh({slot: 2, name: "b"});
const c = fresh({slot: 3, name: "c"});
const d = fresh({slot: 4, name: "d"});
const shape = (pairs: Parameters<typeof pairGuardShape>[0], nodes: Parameters<typeof pairGuardShape>[1], ids: string[], editing?: string) => pairGuardShape(pairs, nodes, ids, editing, NOW);

describe("pairGuardShape", () => {
  it("is the same for the same pairs and nodes, in any order", () => {
    const p1 = pairFixture(a, b);
    const p2 = pairFixture(c, d, {is_global: false});
    expect(samePairGuard(shape([p1, p2], [a, b, c, d], [a.id, b.id]), shape([p2, p1], [d, c, b, a], [b.id, a.id]))).toBe(true);
  });
  it("sees a global pair another admin made while the code was typed (a forced make_global)", () => {
    const before = shape([], [a, b, c, d], [c.id, d.id]);
    const after = shape([pairFixture(a, b)], [a, b, c, d], [c.id, d.id]);
    expect(after.global).toBe(true);
    expect(samePairGuard(before, after)).toBe(false);
  });
  it("sees a pair that holds one of the nodes change roles, or go away", () => {
    const p = pairFixture(a, b);
    const seen = shape([p], [a, b], [a.id, b.id], p.id);
    expect(samePairGuard(seen, shape([{...p, primary_node_id: b.id, fallback_node_id: a.id}], [a, b], [a.id, b.id], p.id))).toBe(false);
    expect(samePairGuard(seen, shape([], [a, b], [a.id, b.id], p.id))).toBe(false);
  });
  it("ignores a pair that holds none of the nodes", () => {
    const other = pairFixture(c, d, {is_global: false});
    expect(samePairGuard(shape([], [a, b, c, d], [a.id, b.id]), shape([other], [a, b, c, d], [a.id, b.id]))).toBe(true);
  });
  it("sees the hub withdraw, hold or fall behind a node of the change", () => {
    const seen = shape([], [a, b], [a.id, b.id]);
    expect(samePairGuard(seen, shape([], [{...a, dns_withdrawn: true}, b], [a.id, b.id]))).toBe(false);
    expect(samePairGuard(seen, shape([], [a, {...b, dns_hold: true}], [a.id, b.id]))).toBe(false);
    expect(samePairGuard(seen, shape([], [a, {...b, applied_seq_lag: 3}], [a.id, b.id]))).toBe(false);
    expect(samePairGuard(seen, shape([], [a, {...b, last_heartbeat_at: new Date(NOW - 600_000).toISOString()}], [a.id, b.id]))).toBe(false);
    expect(samePairGuard(seen, shape([], [a, {...b, status: "revoked"}], [a.id, b.id]))).toBe(false);
  });
  it("ignores the flags of a node that is not in the change", () => {
    expect(samePairGuard(shape([], [a, b, c], [a.id, b.id]), shape([], [a, b, {...c, dns_withdrawn: true}], [a.id, b.id]))).toBe(true);
  });
  it("reads a node the server no longer has as a change", () => {
    expect(samePairGuard(shape([], [a, b], [a.id, b.id]), shape([], [a], [a.id, b.id]))).toBe(false);
  });
});
