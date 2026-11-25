import {afterEach, describe, expect, it, vi} from "vitest";

import {ADMIN_PROTECTED_PREFIXES, PANEL_PROTECTED_PREFIXES} from "../proxy/prefixes.ts";
import {sanitizeNext} from "../proxy/safeNext.ts";
import {currentNext} from "./currentNext.ts";

// Gate round 15 (gate-r15-5). currentNext() builds the `next` of every client-side end of a session (SessionGate, SessionBinding, the
// admin guard, handleApiError), and until now each test either stubbed it or loaded a page at its bare path. A refactor that dropped the
// query, or cut the path at the wrong segment, would have left every test green and sent the visitor home. The browser case, with a real
// page, a real expiry and the sign-in that follows, is session.spec.ts; this one runs the function itself on the shapes that matter.

function at(pathname: string, search = "") {
  vi.stubGlobal("window", {location: {pathname, search}});
}

afterEach(() => vi.unstubAllGlobals());

describe("currentNext, panel", () => {
  it.each([
    ["/fa/profiles", "", "/profiles"],
    ["/en/profiles", "", "/profiles"],
    // The query of a URL dialog (useUrlDialog) is part of the page the visitor was on.
    ["/fa/profiles", "?helpPane=profiles", "/profiles?helpPane=profiles"],
    ["/en/profiles", "?notificationsDialog=1", "/profiles?notificationsDialog=1"],
    ["/fa/preferences/account", "?helpPane=account", "/preferences/account?helpPane=account"],
    ["/en/preferences/api", "", "/preferences/api"],
    ["/fa/analytics/statistics", "?range=7d&profile=abc", "/analytics/statistics?range=7d&profile=abc"],
    ["/fa/endpoints", "?sort=name&dir=asc", "/endpoints?sort=name&dir=asc"],
  ])("%s%s gives %s", (pathname, search, expected) => {
    at(pathname, search);
    expect(currentNext("panel")).toBe(expected);
  });

  it("keeps a path with Persian letters the way the browser writes it", () => {
    at("/fa/profiles/%D9%BE%D8%B1%D9%88%D9%81%D8%A7%DB%8C%D9%84", "?x=%D8%A7");
    expect(currentNext("panel")).toBe("/profiles/%D9%BE%D8%B1%D9%88%D9%81%D8%A7%DB%8C%D9%84?x=%D8%A7");
  });

  it("cuts exactly one segment, the locale, and never more", () => {
    at("/fa/preferences/account", "");
    expect(currentNext("panel")).toBe("/preferences/account");
    at("/fa/profiles/fa/profiles", "");
    expect(currentNext("panel")).toBe("/profiles/fa/profiles");
  });

  it("gives nothing for a page that is not gated, so the sign-in lands on the home page", () => {
    for (const path of ["/fa", "/fa/", "/fa/login", "/en/register", "/fa/invite", "/fa/suspended", "/fa/nothing-here"]) {
      at(path, "?x=1");
      expect(currentNext("panel"), path).toBeUndefined();
    }
  });

  it("gives nothing for a path that merely starts with the letters of a prefix", () => {
    at("/fa/profiles-old", "");
    expect(currentNext("panel")).toBeUndefined();
  });

  it("does not carry a path that another rule refuses (dot segments, a doubled slash)", () => {
    for (const [path, search] of [["/fa/profiles/../login", ""], ["/fa/profiles//x", ""], ["/fa/profiles", "?next=//evil.example"]] as const) {
      at(path, search);
      const got = currentNext("panel");
      // Whatever comes back has passed the same rule as the proxy and the login page use.
      expect(got === undefined || sanitizeNext(got, PANEL_PROTECTED_PREFIXES) === got, `${path}${search}`).toBe(true);
    }
  });
});

describe("currentNext, admin", () => {
  it.each(ADMIN_PROTECTED_PREFIXES)("keeps a page under %s, with its nested path and query", (prefix) => {
    at(`/fa${prefix}`, "");
    expect(currentNext("admin")).toBe(prefix);
    at(`/en${prefix}/details/42`, "?tab=audit&page=2");
    expect(currentNext("admin")).toBe(`${prefix}/details/42?tab=audit&page=2`);
  });

  it("uses the admin's prefixes and the panel's own are not known to it, and the other way round", () => {
    for (const prefix of PANEL_PROTECTED_PREFIXES) {
      at(`/fa${prefix}`, "");
      expect(currentNext("panel"), prefix).toBe(prefix);
      expect(currentNext("admin"), prefix).toBeUndefined();
    }
    for (const prefix of ADMIN_PROTECTED_PREFIXES) {
      at(`/fa${prefix}`, "");
      expect(currentNext("admin"), prefix).toBe(prefix);
      expect(currentNext("panel"), prefix).toBeUndefined();
    }
  });

  it("gives nothing for the admin's login page and for the home page", () => {
    for (const path of ["/fa", "/fa/login", "/en/login"]) {
      at(path, "?x=1");
      expect(currentNext("admin"), path).toBeUndefined();
    }
  });
});
