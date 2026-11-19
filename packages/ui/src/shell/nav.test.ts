import {describe, expect, it} from "vitest";

import {flattenLinks, groupsHolding, isCurrentPath} from "./nav.ts";
import {panelNav, type PanelNavLabels} from "./panelNav.ts";

const labels: PanelNavLabels = {
  profiles: "Profiles",
  endpoints: "Endpoints",
  analytics: "Analytics",
  statistics: "Statistics",
  activityLog: "Activity log",
  domainTest: "Domain test",
  preferences: "Preferences",
  account: "Account",
  api: "API",
  logout: "Log out",
};

describe("isCurrentPath", () => {
  it("matches the page and its children, not a lookalike", () => {
    expect(isCurrentPath("/profiles", "/profiles")).toBe(true);
    expect(isCurrentPath("/profiles/abc", "/profiles")).toBe(true);
    expect(isCurrentPath("/profiles-old", "/profiles")).toBe(false);
    expect(isCurrentPath("/", "/profiles")).toBe(false);
  });
});

describe("panelNav", () => {
  const nav = panelNav(labels);

  it("has the four entries of WF: Profiles, Endpoints, Analytics, Preferences", () => {
    expect(nav.map((i) => i.id)).toEqual(["profiles", "endpoints", "analytics", "preferences"]);
  });

  it("puts Log out in Preferences as an action, never a link", () => {
    const prefs = nav.find((i) => i.id === "preferences");
    expect(prefs?.kind).toBe("group");
    const logout = prefs?.kind === "group" ? prefs.items.find((i) => i.id === "logout") : undefined;
    expect(logout?.kind).toBe("action");
  });

  it("gives every link a locale-free absolute path", () => {
    for (const link of flattenLinks(nav)) expect(link.href).toMatch(/^\/[a-z-/]+$/);
  });

  it("matches the routes of spec 8.9", () => {
    expect(flattenLinks(nav).map((l) => l.href)).toEqual([
      "/profiles",
      "/endpoints",
      "/analytics/statistics",
      "/analytics/activity-log",
      "/analytics/domain-test",
      "/preferences/account",
      "/preferences/api",
    ]);
  });

  it("opens the group that holds the current page", () => {
    expect(groupsHolding(nav, "/analytics/activity-log")).toEqual(["analytics"]);
    expect(groupsHolding(nav, "/preferences/api")).toEqual(["preferences"]);
    expect(groupsHolding(nav, "/profiles")).toEqual([]);
  });
});
