import {catalogServicesFixture, CATEGORIES, profileServicesFixture} from "@ctrlz/api-client/testing/screenFixtures.ts";
import {describe, expect, it} from "vitest";

import {cardLimits, CARDS_PER_STEP, categoryCheck, chooseGroups, groupProfileServices, riskyOf, selectionNeverProxied, toggleCategory, UNKNOWN_CATEGORY} from "./servicesModel.ts";

const fold = (s: string) => s.toLowerCase();
const compare = (a: string, b: string) => a.localeCompare(b, "en");
const catalogue = catalogServicesFixture();

describe("the profile's services by category (T-163)", () => {
  const unknownCategory = {id: UNKNOWN_CATEGORY, name_fa: "؟", name_en: "?"};
  const args = {categories: CATEGORIES, catalogue, rows: profileServicesFixture(1), locale: "en", query: "", fold, compare, unknownCategory};

  it("groups in the catalogue's order of categories and drops the empty ones", () => {
    const groups = groupProfileServices(args);
    expect(groups.map((g) => g.category.id)).toEqual(["video", "social", "audio", "gaming"]);
    expect(groups[0]!.items.map((i) => i.row.slug).sort()).toEqual(["aparat", "video-004"]);
  });

  it("keeps a slug the catalogue no longer lists, in its own group, so it can still be removed", () => {
    const rows = [...args.rows, {slug: "gone-service", enabled: true, action: "block" as const, location_unavailable: false, iranian_bypass: false}];
    const groups = groupProfileServices({...args, rows});
    expect(groups.at(-1)!.category.id).toBe(UNKNOWN_CATEGORY);
    expect(groups.at(-1)!.items[0]).toMatchObject({name: "gone-service"});
  });

  it("searches by name or slug", () => {
    const groups = groupProfileServices({...args, query: "TELE"});
    expect(groups.flatMap((g) => g.items.map((i) => i.row.slug))).toEqual(["telegram"]);
  });
});

describe("Choose Service lists what the profile does not have (T-164, T-165)", () => {
  const inProfile = new Set(profileServicesFixture(1).map((r) => r.slug));
  const args = {categories: CATEGORIES, catalogue, inProfile, locale: "en", query: "", fold, compare};

  it("takes the profile's services out, so a category's count drops by them", () => {
    const video = chooseGroups(args).find((g) => g.category.id === "video")!;
    // 320 in Video, one of them (video-004) already in the profile, one (video-004 is the deprecated one, number 4) never offered anyway,
    // and Aparat is another Video service that the profile has.
    expect(catalogue.filter((s) => s.category_id === "video")).toHaveLength(321);
    expect(video.services.find((s) => s.slug === "video-004")).toBeUndefined();
    expect(video.services.find((s) => s.slug === "aparat")).toBeUndefined();
    expect(video.services).toHaveLength(319);
  });

  it("does not offer a deprecated service", () => {
    const deprecated = catalogue.find((s) => s.state === "deprecated")!;
    expect(chooseGroups({...args, inProfile: new Set()}).flatMap((g) => g.services).some((s) => s.slug === deprecated.slug)).toBe(false);
  });

  it("finds a service by name, and a whole category by its name", () => {
    expect(chooseGroups({...args, query: "bbc"}).flatMap((g) => g.services.map((s) => s.slug))).toEqual(["bbc"]);
    expect(chooseGroups({...args, query: "news"}).map((g) => g.category.id)).toEqual(["news"]);
  });
});

describe("selecting a category", () => {
  const slugs = ["a", "b", "c"];
  it("is none, some or all, and a press makes a part all and all none", () => {
    expect(categoryCheck(new Set(), slugs)).toBe("none");
    expect(categoryCheck(new Set(["a"]), slugs)).toBe("some");
    expect(categoryCheck(new Set(slugs), slugs)).toBe("all");
    expect([...toggleCategory(new Set(["a"]), slugs)].sort()).toEqual(slugs);
    expect([...toggleCategory(new Set([...slugs, "z"]), slugs)]).toEqual(["z"]);
  });

});

describe("what a selection allows (T-165, T-521)", () => {
  it("names the risk-flagged services of a selection", () => {
    expect(riskyOf(new Set(["bbc", "telegram"]), catalogue).map((s) => s.slug)).toEqual(["bbc"]);
    expect(riskyOf(new Set(["telegram"]), catalogue)).toEqual([]);
  });

  it("finds a service that is never proxied, which takes Redirect away from the group", () => {
    expect(selectionNeverProxied(new Set(["telegram", "aparat"]), catalogue)?.slug).toBe("aparat");
    expect(selectionNeverProxied(new Set(["telegram"]), catalogue)).toBeUndefined();
  });
});

describe("the cards the page draws (S3-r3-1)", () => {
  const group = (id: string, n: number) => ({category: {id}, items: Array.from({length: n}, (_, i) => i)});

  it("counts the budget over every category, so 900 services in 25 categories draw one step and not 900", () => {
    const groups = Array.from({length: 25}, (_, i) => group(`c${i}`, 36));
    const limits = cardLimits(groups, new Map());
    expect([...limits.values()].reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(CARDS_PER_STEP);
    // The first category is whole, the second takes the part that is a whole number of rows (12 of its 36), the rest only show their header.
    expect([...limits.values()].slice(0, 3)).toEqual([36, 12, 0]);
    expect([...limits.values()].slice(3).every((n) => n === 0)).toBe(true);
  });

  it("keeps what a person asked for, never more than the category holds, and never less than the budget gave", () => {
    const groups = [group("a", 100), group("b", 20)];
    expect(cardLimits(groups, new Map()).get("a")).toBe(48);
    expect(cardLimits(groups, new Map([["a", 96], ["b", 48]]))).toEqual(new Map([["a", 96], ["b", 20]]));
    expect(cardLimits(groups, new Map([["a", 12]])).get("a")).toBe(48);
  });
});
