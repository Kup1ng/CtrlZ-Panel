import type {Folder, Rule} from "@ctrlz/api-client/hooks/rules.ts";
import {describe, expect, it} from "vitest";

import {
  addTags,
  editMembers,
  effectiveRuleAction,
  geoPattern,
  isEmptyPatch,
  KEEP_ALL,
  knownTotal,
  listQuery,
  NO_FILTER,
  parseAsn,
  parseGeo,
  patternIndex,
  recordsOf,
  rulePatch,
  ruleState,
  selectionMembers,
  selectorOf,
  splitTokens,
  toBase64,
  transferMembers,
  transferProblem,
} from "./rulesModel.ts";

const rule = (over: Partial<Rule> = {}): Rule => ({
  id: "r1",
  pattern: "example.com",
  key: "example.com",
  match_kind: "domain",
  negated: false,
  action: "block",
  enabled: true,
  location_unavailable: false,
  iranian_bypass: false,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  ...over,
});
const folder = (over: Partial<Folder> = {}): Folder => ({id: "f1", name: "Work", kind: "standard", location_unavailable: false, rule_count: 10, ...over});

describe("the list's query (T-196)", () => {
  it("asks for the top level when nothing narrows it, and for every folder when something does", () => {
    expect(listQuery(NO_FILTER)).toEqual({folder: "root", sort: "created"});
    expect(listQuery({...NO_FILTER, q: " exa "})).toEqual({q: "exa", sort: "created"});
    expect(listQuery({...NO_FILTER, status: "disabled", action: "redirect", sort: "pattern"})).toEqual({status: "disabled", action: "redirect", sort: "pattern"});
  });
  it("asks for its folder on a folder page whatever the filter", () => {
    expect(listQuery({...NO_FILTER, q: "x"}, "f1")).toEqual({folder: "f1", q: "x", sort: "created"});
  });
  it("makes the selector of Select All from the same filter, with no sort", () => {
    const q = listQuery({...NO_FILTER, q: "x", status: "enabled"});
    expect(selectorOf(q)).toEqual({q: "x", status: "enabled"});
    expect(selectorOf(listQuery(NO_FILTER))).toEqual({folder: "root"});
  });
  it("sends a selection as ids or as the selector, never both", () => {
    const q = listQuery(NO_FILTER);
    expect(selectionMembers({kind: "ids", ids: ["a"]}, q)).toEqual({ids: ["a"]});
    expect(selectionMembers({kind: "selector"}, q)).toEqual({selector: {folder: "root"}});
  });
});

describe("the number of rules a filter holds", () => {
  const folders = [folder({rule_count: 120}), folder({id: "f2", rule_count: 30})];
  it("is the loaded count once every page is in", () => {
    expect(knownTotal({filtered: true, profileRules: 500, folders, loaded: 42, hasNext: false})).toBe(42);
  });
  it("is the profile's rules less the folders' at the top level, and the folder's own count in a folder", () => {
    expect(knownTotal({filtered: false, profileRules: 500, folders, loaded: 100, hasNext: true})).toBe(350);
    expect(knownTotal({filtered: false, folder: folders[0], profileRules: 500, folders, loaded: 100, hasNext: true})).toBe(120);
  });
  it("is not known for a filter with more pages to come", () => {
    expect(knownTotal({filtered: true, profileRules: 500, folders, loaded: 100, hasNext: true})).toBeUndefined();
  });
});

describe("a rule on screen", () => {
  const now = new Date("2026-06-01T00:00:00Z");
  it("is expired past its expiry whatever its switch says", () => {
    expect(ruleState(rule({expires_at: "2026-05-01T00:00:00Z"}), now)).toBe("expired");
    expect(ruleState(rule({expires_at: "2026-07-01T00:00:00Z"}), now)).toBe("on");
    expect(ruleState(rule({enabled: false}), now)).toBe("off");
  });
  it("takes the folder's action when it inherits", () => {
    expect(effectiveRuleAction(rule({action: "inherit", folder_id: "f1"}), [folder({action: "block"})])).toBe("block");
    expect(effectiveRuleAction(rule({action: "inherit", folder_id: "gone"}), [folder()])).toBe("inherit");
    expect(effectiveRuleAction(rule({action: "bypass"}), [])).toBe("bypass");
  });
  it("shows the record capsules the answer covers", () => {
    expect(recordsOf(rule())).toEqual({a: true, aaaa: true});
    expect(recordsOf(rule({action: "redirect", target: {kind: "ip", ipv4: "203.0.113.7"}}))).toEqual({a: true, aaaa: false});
    expect(recordsOf(rule({action: "redirect", target: {kind: "ip", ipv6: "2001:db8::1"}}))).toEqual({a: false, aaaa: true});
    expect(recordsOf(rule({match_kind: "dest_cc"}))).toEqual({a: false, aaaa: false});
  });
});

describe("Geo Rule tokens (T-181)", () => {
  it("reads and writes the four country forms", () => {
    expect(parseGeo("@IR")).toEqual({side: "dest", negated: false, country: "IR"});
    expect(parseGeo("!#de")).toEqual({side: "src", negated: true, country: "DE"});
    expect(geoPattern({side: "src", negated: false, country: "us"})).toBe("#US");
    expect(geoPattern({side: "dest", negated: true, country: "IR"})).toBe("!@IR");
  });
  it("does not take an AS number or a domain for a country", () => {
    expect(parseGeo("@AS1234")).toBeNull();
    expect(parseGeo("example.com")).toBeNull();
    expect(parseAsn("!@AS1234")).toEqual({negated: true, number: "1234"});
    expect(parseAsn("@IR")).toBeNull();
  });
});

describe("domain tags (T-180)", () => {
  it("splits on spaces, commas, semicolons, the Persian comma and line breaks", () => {
    expect(splitTokens("a.com, b.com;c.com\nd.com  e.com،f.com")).toEqual(["a.com", "b.com", "c.com", "d.com", "e.com", "f.com"]);
    expect(splitTokens("   ")).toEqual([]);
  });
  it("leaves out a tag that is there and counts what does not fit", () => {
    expect(addTags(["a.com"], "A.com b.com c.com", 2)).toEqual({tags: ["a.com", "b.com"], added: 1, duplicates: 1, over: 1});
  });
  it("reads the index of a field that names a pattern", () => {
    expect(patternIndex("/patterns/3")).toBe(3);
    expect(patternIndex("/patterns/12/x")).toBe(12);
    expect(patternIndex("/comment")).toBeNull();
  });
});

describe("the PATCH of an edit", () => {
  const base = rule({comment: "note", folder_id: "f1", expires_at: "2026-12-01T00:00:00Z"});
  const same = {pattern: "example.com", action: "block" as const, target: null, folderId: "f1", comment: "note", expiry: {kind: "keep" as const}};
  it("sends nothing for a draft that changes nothing", () => {
    expect(isEmptyPatch(rulePatch(base, same))).toBe(true);
  });
  it("sends what changed, and clears what was emptied", () => {
    const p = rulePatch(base, {...same, pattern: "other.com", folderId: "", comment: "", expiry: {kind: "none"}});
    expect(p).toEqual({pattern: "other.com", clear: ["folder", "comment", "expires"]});
  });
  it("sends the destination with a Redirect, and a shortcut as expires_in", () => {
    const p = rulePatch(rule(), {pattern: "example.com", action: "redirect", target: {kind: "auto"}, folderId: "", comment: "", expiry: {kind: "shortcut", value: "1d"}});
    expect(p).toEqual({action: "redirect", target: {kind: "auto"}, expires_in: "1d"});
  });
});

describe("Copy, Move and group Edit (T-189, T-191)", () => {
  it("sends the other profile for a copy, and none for a move inside the profile", () => {
    expect(transferMembers({op: "copy", profileId: "p2", place: {kind: "root"}}, "p1")).toEqual({dest_profile_id: "p2", dest_root: true});
    expect(transferMembers({op: "move", profileId: "p1", place: {kind: "folder", folderId: "f9"}}, "p1")).toEqual({dest_folder_id: "f9"});
    expect(transferMembers({op: "move", profileId: "p2", place: {kind: "new", name: " Kids "}}, "p1")).toEqual({dest_profile_id: "p2", new_folder: {name: "Kids", kind: "standard"}});
  });
  it("refuses a copy inside the profile, an empty folder name and a name of 32 characters", () => {
    expect(transferProblem({op: "copy", profileId: "p1", place: {kind: "root"}}, "p1")).toBe("same_profile");
    expect(transferProblem({op: "move", profileId: "p1", place: {kind: "new", name: " "}}, "p1")).toBe("name_required");
    expect(transferProblem({op: "move", profileId: "p1", place: {kind: "new", name: "x".repeat(32)}}, "p1")).toBe("name_too_long");
    expect(transferProblem({op: "move", profileId: "p1", place: {kind: "new", name: "x".repeat(31)}}, "p1")).toBeNull();
    expect(transferProblem({op: "move", profileId: "p1", place: {kind: "folder", folderId: ""}}, "p1")).toBe("folder_required");
  });
  it("builds the set and clear of a group edit, and none for nothing chosen", () => {
    expect(editMembers(KEEP_ALL)).toBeNull();
    const m = editMembers({
      ...KEEP_ALL,
      action: {mode: "set", value: "redirect"},
      target: {kind: "random"},
      comment: {mode: "clear"},
      expiry: {mode: "set", value: {kind: "shortcut", value: "1w"}},
      folder: {mode: "clear"},
    });
    expect(m).toEqual({set: {action: "redirect", target: {kind: "random"}, expires_in: "1w"}, clear: ["comment", "folder"]});
  });
});

describe("toBase64", () => {
  it("encodes a large file without overflowing the call", () => {
    const bytes = new Uint8Array(200_000).fill(65);
    expect(atob(toBase64(bytes)).length).toBe(200_000);
    expect(toBase64(new TextEncoder().encode("hi"))).toBe("aGk=");
  });
});
