import {describe, expect, it} from "vitest";
import type {Client} from "@ctrlz/api-client/hooks/clients.ts";

import {diffFields, fieldsOf, itemsOf, parseDays} from "./clientsModel.ts";

const c = (label: string, over: Partial<Client> = {}): Client => ({id: label, label, source: "auto", is_custom: false, first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-02T00:00:00Z", ...over});
const compare = (a: string, b: string) => a.localeCompare(b);

describe("clients grouped (T-257)", () => {
  it("puts the groups in order with their clients under a header and the clients with no group last", () => {
    const items = itemsOf([c("z"), c("b", {group_name: "Family"}), c("a", {group_name: "Family"}), c("m", {alias: "Alpha"}), c("k", {group_name: "Work"})], compare);
    expect(items.map((i) => (i.kind === "header" ? `#${i.name ?? "-"}:${i.count}` : i.client.label))).toEqual(["#Family:2", "a", "b", "#Work:1", "k", "#-:2", "m", "z"]);
  });
  it("has no headers when no client has a group", () => {
    expect(itemsOf([c("b"), c("a")], compare).map((i) => i.kind)).toEqual(["client", "client"]);
  });
});

describe("days of inactivity (T-259)", () => {
  it("takes 1 to 3650 whole days, in Persian digits too", () => {
    expect(parseDays("30")).toBe(30);
    expect(parseDays("۹۰")).toBe(90);
    expect(parseDays("3650")).toBe(3650);
    for (const bad of ["", "0", "3651", "1.5", "-1", "abc", "١٠٠٠٠"]) expect(parseDays(bad)).toBeNull();
  });
});

describe("a client's PATCH (T-258)", () => {
  it("sends what changed and clears what was emptied", () => {
    const was = fieldsOf(c("x", {alias: "Phone", group_name: "Family", profile_id: "p1", profile2_id: "p2", analytics_level: "full"}));
    expect(diffFields(was, {...was})).toBeNull();
    expect(diffFields(was, {...was, alias: "Tablet", group: ""})).toEqual({alias: "Tablet", clear: ["group_name"]});
    expect(diffFields(was, {...was, profileId: null, profile2Id: null, analytics: null})).toEqual({clear: ["profile_id", "profile2_id", "analytics_level"]});
  });
  it("emptying Profile 1 empties Profile 2 with it", () => {
    const was = fieldsOf(c("x", {profile_id: "p1", profile2_id: "p2"}));
    expect(diffFields(was, {...was, profileId: null})?.clear).toEqual(["profile_id", "profile2_id"]);
  });
});
