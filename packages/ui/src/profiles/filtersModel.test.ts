import type {CatalogFilter, ProfileFilter} from "@ctrlz/api-client/hooks/filters.ts";
import {describe, expect, it} from "vitest";

import enProfiles from "../../../i18n/messages/en/profiles.json";
import faProfiles from "../../../i18n/messages/fa/profiles.json";
import {cardOf, choosableModes, manyListsOn, modeToSend, needsNewDomainsWarning, onCount} from "./filtersModel.ts";

const filter = (id: string, modes: string[], over: Partial<CatalogFilter> = {}): CatalogFilter => ({
  id,
  kind: "native",
  name_fa: id,
  name_en: id,
  state: "available",
  modes: modes.map((mode, i) => ({mode, default: i === 0})),
  ...over,
});

describe("filter modes (T-145, T-146)", () => {
  it("has a choice only for two or more real modes, and never offers the seed's standard", () => {
    expect(choosableModes(filter("a", ["relaxed", "balanced", "strict"]))).toEqual(["relaxed", "balanced", "strict"]);
    expect(choosableModes(filter("a", ["relaxed", "strict"]))).toEqual(["relaxed", "strict"]);
    expect(choosableModes(filter("a", ["standard"]))).toEqual([]);
    expect(choosableModes(filter("a", []))).toEqual([]);
  });

  it("switches on with the default mode, Relaxed, and with the remembered one afterwards (T-146)", () => {
    const ads = filter("ads-trackers", ["relaxed", "balanced", "strict"]);
    expect(modeToSend(ads, undefined)).toBe("relaxed");
    expect(modeToSend(ads, {mode: "strict"})).toBe("strict");
    // A remembered mode the catalogue dropped is not sent: the default takes over.
    expect(modeToSend(ads, {mode: "extreme"})).toBe("relaxed");
    expect(modeToSend(filter("phishing", ["standard"]), {mode: "standard"})).toBeUndefined();
  });
});

describe("the card of a filter (T-144)", () => {
  const rows: ProfileFilter[] = [
    {filter_id: "malware", enabled: true, mode: "strict"},
    {filter_id: "adult", enabled: false, mode: "strict"},
  ];
  it("says Blocked while it is on and Allowed while it is off, and hides the remembered mode of an off filter", () => {
    const malware = cardOf(filter("malware", ["relaxed", "balanced", "strict"]), rows);
    expect(malware).toMatchObject({enabled: true, status: "blocked", mode: "strict"});
    const adult = cardOf(filter("adult", ["relaxed", "strict"]), rows);
    expect(adult).toMatchObject({enabled: false, status: "allowed"});
    expect(adult.mode).toBeUndefined();
  });

  it("lets a deprecated or unavailable filter be turned off but not on", () => {
    expect(cardOf(filter("d", ["standard"], {state: "deprecated"}), []).canToggle).toBe(false);
    expect(cardOf(filter("d", ["standard"], {state: "deprecated"}), [{filter_id: "d", enabled: true}]).canToggle).toBe(true);
    expect(cardOf(filter("u", ["standard"], {state: "unavailable"}), []).canToggle).toBe(false);
    expect(cardOf(filter("n", ["standard"]), []).canToggle).toBe(true);
  });
});

describe("the warnings (T-150, T-537)", () => {
  it("warns about many lists from the second 3rd Party list on", () => {
    const lists = [filter("l1", ["standard"], {kind: "third_party"}), filter("l2", ["standard"], {kind: "third_party"})];
    expect(manyListsOn(onCount(lists, [{filter_id: "l1", enabled: true}]))).toBe(false);
    expect(manyListsOn(onCount(lists, [{filter_id: "l1", enabled: true}, {filter_id: "l2", enabled: true}]))).toBe(true);
  });

  it("warns about .ir when New Domains is switched on or changes mode, and says nothing otherwise", () => {
    const base = {filterId: "new-domains", enabled: true, wasEnabled: false};
    expect(needsNewDomainsWarning(base)).toBe(true);
    expect(needsNewDomainsWarning({...base, wasEnabled: true, mode: "last_month", wasMode: "last_week"})).toBe(true);
    expect(needsNewDomainsWarning({...base, wasEnabled: true, mode: "last_week", wasMode: "last_week"})).toBe(false);
    expect(needsNewDomainsWarning({...base, enabled: false, wasEnabled: true})).toBe(false);
    expect(needsNewDomainsWarning({filterId: "malware", enabled: true, wasEnabled: false})).toBe(false);
  });

  it("carries the same sentence in the dialog and in the explanation of the filter, in both languages (T-537)", () => {
    for (const messages of [faProfiles, enProfiles]) {
      expect(messages.filters.help["new-domains"].body).toContain(messages.filters.newDomains.warning);
    }
  });

  it("has an explanation for each of the 20 native filters and the 12 lists (T-149, T-150)", () => {
    for (const messages of [faProfiles, enProfiles]) {
      expect(Object.keys(messages.filters.help)).toHaveLength(32);
    }
  });
});
