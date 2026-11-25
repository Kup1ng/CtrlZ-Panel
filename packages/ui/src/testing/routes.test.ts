import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";

import {afterEach, describe, expect, it} from "vitest";

import {fatalProblems, gateProblems, listRoutes, strayRoutes, withoutLocale} from "./routes.ts";

let dir = "";
afterEach(() => {
  if (dir) rmSync(dir, {recursive: true, force: true});
});

function tree(files: string[]): string {
  dir = mkdtempSync(join(tmpdir(), "ctrlz-routes-"));
  for (const file of files) {
    mkdirSync(dirname(join(dir, file)), {recursive: true});
    writeFileSync(join(dir, file), "export default null;\n");
  }
  return dir;
}

describe("listRoutes", () => {
  it("drops route groups and slots, keeps the locale and the catch-all, and reads route handlers", () => {
    const root = tree([
      "[locale]/page.tsx",
      "[locale]/(shell)/profiles/page.tsx",
      "[locale]/(shell)/analytics/statistics/page.tsx",
      "[locale]/(lab)/virtual-lab/page.tsx",
      "[locale]/[...rest]/page.tsx",
      "[locale]/@modal/x/page.tsx",
      "health/route.ts",
      "[locale]/layout.tsx",
      "[locale]/(shell)/profiles/Panel.tsx",
    ]);
    expect(listRoutes(root)).toEqual([
      "/[locale]",
      "/[locale]/[...rest]",
      "/[locale]/analytics/statistics",
      "/[locale]/profiles",
      "/[locale]/virtual-lab",
      "/[locale]/x",
      "/health",
    ]);
  });
});

describe("withoutLocale and strayRoutes", () => {
  it("strips the locale, and the root of a locale is /", () => {
    expect(withoutLocale("/[locale]")).toBe("/");
    expect(withoutLocale("/[locale]/profiles")).toBe("/profiles");
    expect(withoutLocale("/health")).toBe("/health");
  });
  it("names a page that is not in the list, so a stray billing page fails the run", () => {
    const root = tree(["[locale]/page.tsx", "[locale]/(shell)/profiles/page.tsx", "[locale]/(shell)/billing/page.tsx", "[locale]/pricing/page.tsx"]);
    const found = listRoutes(root).map(withoutLocale);
    expect(strayRoutes(found, ["/", "/profiles"])).toEqual(["/billing", "/pricing"]);
    expect(strayRoutes(found, ["/", "/profiles", "/billing", "/pricing"])).toEqual([]);
  });
});

describe("gateProblems (gate-r2-10, gate-r2-15, gate-r2-19)", () => {
  const prefixes = ["/profiles", "/analytics"];
  const files = [
    "[locale]/page.tsx",
    "[locale]/(auth)/login/page.tsx",
    "[locale]/(shell)/profiles/page.tsx",
    "[locale]/(shell)/analytics/statistics/page.tsx",
    "[locale]/[...rest]/page.tsx",
  ];

  it("is empty when the group and the prefixes agree", () => {
    expect(gateProblems(files, prefixes)).toEqual([]);
  });
  it("names a page of the group that no prefix covers", () => {
    expect(gateProblems([...files, "[locale]/(shell)/devices/page.tsx"], prefixes)).toEqual([expect.stringContaining("/devices is a page of the (shell) group")]);
  });
  it("does not take a prefix that merely starts with the same letters", () => {
    expect(gateProblems([...files, "[locale]/(shell)/profiles-old/page.tsx"], prefixes)).toEqual([expect.stringContaining("/profiles-old")]);
  });
  it("names a public page under a protected prefix, unless it is an exception", () => {
    const extra = [...files, "[locale]/(auth)/profiles/share/page.tsx"];
    expect(gateProblems(extra, prefixes)).toEqual([expect.stringContaining("/profiles/share is under a protected prefix")]);
    expect(gateProblems(extra, prefixes, ["/profiles/share"])).toEqual([]);
  });
  it("names a prefix that has no page, but only once the group has pages", () => {
    expect(gateProblems(files, [...prefixes, "/endpoints"])).toEqual([expect.stringContaining("/endpoints is a protected prefix and has no page")]);
    expect(gateProblems(["[locale]/page.tsx", "[locale]/[...rest]/page.tsx"], prefixes)).toEqual([]);
  });
  it("counts the page of an exception as the page of its prefix", () => {
    expect(gateProblems([...files, "[locale]/(auth)/setup/page.tsx"], [...prefixes, "/setup"], ["/setup"])).toEqual([]);
  });
});

describe("fatalProblems (gate-r7-1)", () => {
  it("asks nothing of an app with no page", () => {
    expect(fatalProblems(false, null)).toEqual([]);
  });
  it("names an app with pages and no global-error.tsx", () => {
    expect(fatalProblems(true, null)).toEqual([expect.stringContaining("no global-error.tsx")]);
  });
  it("accepts a fatal page made of style attributes", () => {
    expect(fatalProblems(true, 'export default function E() { return <html><body style={{margin: 0}}>x</body></html>; }')).toEqual([]);
  });
  it("names a style element and an inner-HTML style", () => {
    expect(fatalProblems(true, "export default () => <html><head><style>{'a{}'}</style></head></html>")).toHaveLength(1);
    expect(fatalProblems(true, "export default () => <style dangerouslySetInnerHTML={{__html: 'a{}'}} />")).toHaveLength(2);
  });
});
