import {readdirSync, readFileSync, statSync} from "node:fs";
import {join} from "node:path";
import {describe, expect, it} from "vitest";

import {isOnOrUnder, isOnPage} from "./pathPrefix.ts";
import {isSignedInAuthPath} from "./signedInAuthPaths.ts";
import {isCurrentPath} from "./nav.ts";

describe("isOnOrUnder cuts at a segment (gate-r22-7)", () => {
  it("matches the path and what is below it, nothing that merely starts with the same letters", () => {
    expect(isOnOrUnder("/change-password", "/change-password")).toBe(true);
    expect(isOnOrUnder("/change-password/x", "/change-password")).toBe(true);
    for (const p of ["/change-password-x", "/change-passwordzzz", "/change-passwor", "/", "", "/x/change-password"]) {
      expect(isOnOrUnder(p, "/change-password")).toBe(false);
    }
    expect(isOnOrUnder("/suspended-x", "/suspended")).toBe(false);
    expect(isOnOrUnder("/setup-x", "/setup")).toBe(false);
  });

  it("is the rule of the signed-in auth pages and of the navigation too", () => {
    expect(isSignedInAuthPath("/change-password-x")).toBe(false);
    expect(isSignedInAuthPath("/suspended-x")).toBe(false);
    expect(isCurrentPath("/profiles-x", "/profiles")).toBe(false);
    expect(isCurrentPath("/profiles/a", "/profiles")).toBe(true);
  });
});

// The gate, the nav and the auth pages share one helper. A bare `pathname.startsWith("/word")` is the bug again, so the
// components of the shell and the screens may not write one; a prefix that ends in "/" is already cut at a segment.
describe("no component compares a pathname with a bare startsWith (gate-r22-7)", () => {
  const SRC = join(__dirname, "..");
  const SKIP = new Set(["proxy", "testing"]);
  const files = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) return SKIP.has(name) ? [] : files(full);
      return /\.(ts|tsx)$/.test(name) && !/\.test\./.test(name) && name !== "pathPrefix.ts" ? [full] : [];
    });
  const BARE = /\b(?:pathname|path)\w*\s*\.startsWith\(\s*["'`]\/[^"'`]*[^/"'`]["'`]\s*\)/;

  it("finds none in packages/ui/src outside the proxy and the harness", () => {
    const hits = files(SRC).filter((f) => BARE.test(readFileSync(f, "utf8")));
    expect(hits).toEqual([]);
  });

  it("the pattern does catch the old lines", () => {
    expect(BARE.test('x && !pathname.startsWith("/change-password")')).toBe(true);
    expect(BARE.test("pathname.startsWith('/suspended')")).toBe(true);
    expect(BARE.test('pathname.startsWith("/_next/static/")')).toBe(false);
    expect(BARE.test('href.startsWith("/")')).toBe(false);
  });
});

// gate-r23-6: a page with no child routes is matched exactly. A path below it has no page, falls to the catch-all inside the signed-in shell,
// and a gate that took it for "already there" left the skeleton on screen for good.
describe("isOnPage matches the page itself and nothing below it (gate-r23-6)", () => {
  it("is exact, a trailing slash is the same page", () => {
    for (const page of ["/change-password", "/suspended", "/setup"]) {
      expect(isOnPage(page, page)).toBe(true);
      expect(isOnPage(`${page}/`, page)).toBe(true);
      for (const stray of [`${page}/x`, `${page}/x/y`, `${page}-x`, `${page}//`, `/x${page}`, "/", ""]) {
        expect(isOnPage(stray, page)).toBe(false);
      }
    }
  });

  it("is what the gate's redirects use, and they never use the prefix rule", () => {
    const gate = readFileSync(join(__dirname, "SessionGate.tsx"), "utf8");
    for (const page of ["/change-password", "/suspended", "/setup"]) {
      expect(gate).toContain(`!isOnPage(pathname, "${page}")`);
    }
    expect(gate).not.toMatch(/isOnOrUnder/);
  });

  it("the signed-in auth pages are the pages themselves", () => {
    expect(isSignedInAuthPath("/change-password/x")).toBe(false);
    expect(isSignedInAuthPath("/suspended/")).toBe(true);
  });
});
