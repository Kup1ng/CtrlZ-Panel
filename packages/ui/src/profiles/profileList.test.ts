import {describe, expect, it} from "vitest";
import type {Profile} from "@ctrlz/api-client/hooks/profiles.ts";

import {matchesQuery, MAX_IMPORT_BYTES, toBase64, visibleProfiles} from "./profileList.ts";

// T-128 (sort by name and by last change, search), T-136 (a new profile first), spec p2 9.1 and 6.2.

const make = (id: string, name: string, updated_at: string): Profile => ({
  id,
  name,
  kind: "custom",
  created_at: "2026-01-01T00:00:00Z",
  updated_at,
  locked: false,
  counts: {endpoints: 0, filters: 0, services: 0, rules: 0, options: 0},
  endpoints: [],
});

const fa = new Intl.Collator("fa").compare;
const en = new Intl.Collator("en").compare;

const list = [
  make("a", "Home", "2026-03-01T00:00:00Z"),
  make("b", "Office", "2026-05-01T00:00:00Z"),
  make("c", "Gaming", "2026-04-01T00:00:00Z"),
];

describe("visibleProfiles", () => {
  it("sorts by the last change, newest first", () => {
    expect(visibleProfiles(list, {query: "", sort: "changed", compare: en}).map((p) => p.id)).toEqual(["b", "c", "a"]);
  });

  it("sorts by name with the collator of the locale", () => {
    expect(visibleProfiles(list, {query: "", sort: "name", compare: en}).map((p) => p.name)).toEqual(["Gaming", "Home", "Office"]);
    const persian = [make("1", "گیم", "2026-01-01T00:00:00Z"), make("2", "آفیس", "2026-01-01T00:00:00Z"), make("3", "پدر", "2026-01-01T00:00:00Z")];
    // Alef with madda sorts with alef, before be: a plain code point order would put it after yeh and kaf.
    expect(visibleProfiles(persian, {query: "", sort: "name", compare: fa}).map((p) => p.name)).toEqual(["آفیس", "پدر", "گیم"]);
  });

  it("keeps a new profile first whatever the sort, and only while it passes the search", () => {
    expect(visibleProfiles(list, {query: "", sort: "name", compare: en, newId: "b"}).map((p) => p.id)).toEqual(["b", "c", "a"]);
    expect(visibleProfiles(list, {query: "ho", sort: "name", compare: en, newId: "b"}).map((p) => p.id)).toEqual(["a"]);
  });

  it("does not change its input", () => {
    const copy = [...list];
    visibleProfiles(list, {query: "", sort: "name", compare: en, newId: "c"});
    expect(list).toEqual(copy);
  });
});

describe("matchesQuery", () => {
  it("ignores case and surrounding space", () => {
    expect(matchesQuery({name: "Home Router"}, "  hOME ")).toBe(true);
    expect(matchesQuery({name: "Home"}, "office")).toBe(false);
  });

  it("reads Arabic yeh and kaf as the Persian letters", () => {
    expect(matchesQuery({name: "کودک"}, "كودك")).toBe(true);
    expect(matchesQuery({name: "پروفایل"}, "پروفايل")).toBe(true);
  });

  it("an empty search matches everything", () => {
    expect(matchesQuery({name: "x"}, "")).toBe(true);
  });
});

describe("toBase64", () => {
  it("encodes like btoa for a small input", () => {
    expect(toBase64(new TextEncoder().encode("{\"format\":\"ctrlz-profile\"}"))).toBe(btoa("{\"format\":\"ctrlz-profile\"}"));
  });

  it("encodes a file over the chunk size without error", () => {
    const bytes = new Uint8Array(MAX_IMPORT_BYTES).fill(97);
    const encoded = toBase64(bytes);
    expect(encoded.length).toBe(Math.ceil(MAX_IMPORT_BYTES / 3) * 4);
    expect(atob(encoded.slice(0, 8))).toBe("aaaaaa");
  });
});
