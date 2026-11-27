import type {Endpoint, Group} from "@ctrlz/api-client/hooks/endpoints.ts";
import type {Profile} from "@ctrlz/api-client/hooks/profiles.ts";
import {describe, expect, it} from "vitest";

import {adminStateOf, checkNames, heldIndexes, emptiesStack, isDisabling, lockCandidates, MAX_NAMES, parseNames, sectionsOf, slotsAreLocked, statusWord, turnsRequireOn, widenLockAsk} from "./endpointModel.ts";

const ep = (id: string, over: Partial<Endpoint> = {}) => ({id, name: id, profile_id: "p1", admin_state: "enabled", status: "active", ...over}) as Endpoint;
const group = (id: string, name: string) => ({id, name, endpoint_count: 0}) as Group;
const profile = (id: string, locked: boolean) => ({id, name: id, locked}) as Profile;
const compare = (a: string, b: string) => a.localeCompare(b);

describe("parseNames (T-220: several names on add)", () => {
  it("splits on lines, commas of both scripts and semicolons, trims, and drops what is empty", () => {
    expect(parseNames("Home\nLaptop, Phone،  TV ;\n\n  ")).toEqual(["Home", "Laptop", "Phone", "TV"]);
  });

  it("keeps the Persian half-space and drops a control character or a bidi mark", () => {
    expect(parseNames("می‌خواهم‏‮")).toEqual(["می‌خواهم"]);
  });

  it("does not make names unique: the server decides what a repeat means", () => {
    expect(parseNames("a,a")).toEqual(["a", "a"]);
  });
});

describe("checkNames", () => {
  it("asks for at least one, at most 50, and 64 characters each (3.8)", () => {
    expect(checkNames([])).toBe("required");
    expect(checkNames(Array.from({length: MAX_NAMES}, (_, i) => `n${i}`))).toBeNull();
    expect(checkNames(Array.from({length: MAX_NAMES + 1}, (_, i) => `n${i}`))).toBe("exceeded");
    expect(checkNames(["x".repeat(64)])).toBeNull();
    expect(checkNames(["x".repeat(65)])).toBe("too_long");
  });

  it("counts code points as the server does: 64 emoji are allowed", () => {
    expect(checkNames(["😀".repeat(64)])).toBeNull();
    expect(checkNames(["😀".repeat(65)])).toBe("too_long");
  });
});

describe("sectionsOf (T-229: collapsible group sections)", () => {
  const groups = [group("g2", "Work"), group("g1", "Home")];

  it("lists groups by name and the Endpoints with no group last", () => {
    const sections = sectionsOf([ep("a", {group_id: "g2"}), ep("b"), ep("c", {group_id: "g1"})], groups, compare, true);
    expect(sections.map((s) => [s.key, s.endpoints.map((e) => e.id)])).toEqual([
      ["g1", ["c"]],
      ["g2", ["a"]],
      ["ungrouped", ["b"]],
    ]);
  });

  it("keeps an empty group when nothing narrows the view, so it can be renamed, and hides it when something does", () => {
    expect(sectionsOf([ep("b")], groups, compare, true).map((s) => s.key)).toEqual(["g1", "g2", "ungrouped"]);
    expect(sectionsOf([ep("b")], groups, compare, false).map((s) => s.key)).toEqual(["ungrouped"]);
  });

  it("has one section with no group at all when the tenant has none, even with no Endpoint", () => {
    expect(sectionsOf([ep("a"), ep("b")], [], compare, true)).toHaveLength(1);
    expect(sectionsOf([], [], compare, true).map((s) => s.key)).toEqual(["ungrouped"]);
  });

  it("treats a group id the list does not know as no group", () => {
    expect(sectionsOf([ep("a", {group_id: "gone"})], groups, compare, false).map((s) => s.key)).toEqual(["ungrouped"]);
  });
});

describe("lockCandidates (T-142)", () => {
  const all = [profile("p1", false), profile("p2", true), profile("p3", true)];

  it("asks for the locked profiles in the Endpoint's two slots", () => {
    expect(lockCandidates([ep("a", {profile_id: "p2", profile2_id: "p1"})], all).map((p) => p.id)).toEqual(["p2"]);
  });

  it("asks for every locked profile when none of the slots is locked, since a window or a client may hold one", () => {
    expect(lockCandidates([ep("a", {profile_id: "p1"})], all).map((p) => p.id)).toEqual(["p2", "p3"]);
  });

  it("asks for nobody when the tenant has no locked profile", () => {
    expect(lockCandidates([ep("a")], [profile("p1", false)])).toEqual([]);
  });
});

describe("slotsAreLocked and widenLockAsk (T-142, S5-r1-1, S5-r1-10)", () => {
  const all = [profile("p1", false), profile("p2", true), profile("p3", true), profile("p4", true)];
  const locked = all.filter((p) => p.locked);

  it("tells an ask of the slots from a guess over the tenant", () => {
    expect(slotsAreLocked([ep("a", {profile_id: "p2"})], all)).toBe(true);
    expect(slotsAreLocked([ep("a", {profile_id: "p1"})], all)).toBe(false);
  });

  it("widens to the locked profiles never asked, keeping the given ones first", () => {
    const wide = widenLockAsk(locked, new Set(["p2"]), new Set(["p2"]), 8);
    expect(wide.map((p) => p.id)).toEqual(["p2", "p3", "p4"]);
  });

  it("puts the profiles asked and left empty last, and cuts at the limit", () => {
    expect(widenLockAsk(locked, new Set(["p2", "p3"]), new Set(["p3"]), 8).map((p) => p.id)).toEqual(["p3", "p4", "p2"]);
    expect(widenLockAsk(locked, new Set(["p2"]), new Set(["p2"]), 2).map((p) => p.id)).toEqual(["p2", "p3"]);
  });

  it("asks for nobody when every locked profile was asked already", () => {
    expect(widenLockAsk(locked, new Set(["p2", "p3", "p4"]), new Set(["p2"]), 8)).toEqual([]);
  });
});

describe("status words (T-222)", () => {
  it("an enabled Endpoint is Pending or Active by its first query, a disabled one is its state", () => {
    expect(statusWord({admin_state: "enabled", status: "pending"})).toBe("pending");
    expect(statusWord({admin_state: "enabled", status: "active"})).toBe("active");
    expect(statusWord({admin_state: "soft_disabled", status: "active"})).toBe("soft_disabled");
    expect(statusWord({admin_state: "hard_disabled", status: "pending"})).toBe("hard_disabled");
  });

  it("Pending and Active are both the enabled state, which only the server moves from one to the other", () => {
    expect(adminStateOf("pending")).toBe("enabled");
    expect(adminStateOf("active")).toBe("enabled");
    expect(adminStateOf("hard_disabled")).toBe("hard_disabled");
  });

  it("any move into a disabled state from another value is disabling, hard to soft included; staying or enabling is not", () => {
    expect(isDisabling("enabled", "soft_disabled")).toBe(true);
    expect(isDisabling("enabled", "hard_disabled")).toBe(true);
    expect(isDisabling("soft_disabled", "hard_disabled")).toBe(true);
    expect(isDisabling("hard_disabled", "soft_disabled")).toBe(true);
    expect(isDisabling("soft_disabled", "soft_disabled")).toBe(false);
    expect(isDisabling("hard_disabled", "enabled")).toBe(false);
  });

  it("Require Authorized IPs turned on empties the stack as well, and turning it off or leaving it on does not (S5-r3-10)", () => {
    expect(turnsRequireOn(false, true)).toBe(true);
    expect(turnsRequireOn(true, true)).toBe(false);
    expect(turnsRequireOn(true, false)).toBe(false);
    const was = {admin_state: "enabled" as const, require_authorized_ips: false};
    expect(emptiesStack(was, {admin_state: "enabled", require_authorized_ips: true})).toBe(true);
    expect(emptiesStack(was, {admin_state: "hard_disabled", require_authorized_ips: false})).toBe(true);
    expect(emptiesStack(was, {admin_state: "enabled", require_authorized_ips: false})).toBe(false);
  });
});

describe("heldIndexes", () => {
  it("reads the places of the held Endpoints from the answer's fields", () => {
    expect(heldIndexes([{name: "/ids/0"}, {name: "/ids/3"}, {name: "/other"}])).toEqual([0, 3]);
    expect(heldIndexes(undefined)).toEqual([]);
  });
});
