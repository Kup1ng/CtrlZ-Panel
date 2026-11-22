import {NextRequest} from "next/server";
import {describe, expect, it} from "vitest";

import {createProxy} from "./createProxy.ts";
import {splitLocale} from "./gate.ts";
import {ADMIN_PROTECTED_PREFIXES, ADMIN_SESSION_COOKIES, PANEL_PROTECTED_PREFIXES, PANEL_SESSION_COOKIES} from "./prefixes.ts";

const panel = createProxy({protectedPrefixes: PANEL_PROTECTED_PREFIXES, sessionCookies: PANEL_SESSION_COOKIES});
const admin = createProxy({protectedPrefixes: ADMIN_PROTECTED_PREFIXES, sessionCookies: ADMIN_SESSION_COOKIES});

const req = (path: string, cookie?: string) =>
  new NextRequest(`https://panel.localhost${path}`, {headers: cookie ? {cookie} : {}});

// Absolute in the unit test, relative on the wire: Next rewrites same-origin ones.
const location = (r: Response) => {
  const raw = r.headers.get("location");
  if (!raw) return raw;
  const url = new URL(raw);
  return url.pathname + url.search;
};

describe("locale routing", () => {
  it("sends / to /fa", () => {
    const r = panel(req("/"));
    expect(r.status).toBe(307);
    expect(location(r)).toBe("/fa");
  });
  it("prefixes an unprefixed path and keeps the query", () => {
    const r = panel(req("/invite?code=1"));
    expect(r.status).toBe(307);
    expect(location(r)).toBe("/fa/invite?code=1");
  });
  it("sends an unknown language to the default one under its own path", () => {
    expect(location(panel(req("/de")))).toBe("/fa/de");
  });
  it("lets a prefixed path through", () => {
    for (const p of ["/fa", "/en", "/fa/login", "/en/login"]) {
      const r = panel(req(p));
      expect(r.status, p).toBe(200);
      expect(location(r), p).toBeNull();
    }
  });
  it("ignores Accept-Language and sets no cookie", () => {
    const r = panel(new NextRequest("https://panel.localhost/", {headers: {"accept-language": "en-US,en;q=0.9"}}));
    expect(location(r)).toBe("/fa");
    expect(r.headers.get("set-cookie")).toBeNull();
  });
  it("adds no hreflang Link header", () => {
    expect(panel(req("/fa/login")).headers.get("link")).toBeNull();
  });
});

describe("CSP header", () => {
  it("is on every kind of response", () => {
    for (const path of ["/", "/fa", "/fa/login", "/fa/profiles", "/fa/profiles/x.y", "/de"]) {
      expect(panel(req(path)).headers.get("content-security-policy"), path).toContain("default-src 'none'");
    }
  });
  it("carries a fresh nonce per request", () => {
    const nonce = (r: Response) => /'nonce-([^']+)'/.exec(r.headers.get("content-security-policy")!)![1];
    const a = nonce(panel(req("/fa")));
    const b = nonce(panel(req("/fa")));
    expect(a).not.toBe(b);
  });
  it("forwards the nonce to the render in the request headers", () => {
    const r = panel(req("/fa/login"));
    const forwarded = r.headers.get("x-middleware-override-headers") ?? "";
    expect(forwarded.split(",")).toContain("x-nonce");
    expect(forwarded.split(",")).toContain("content-security-policy");
    const nonce = r.headers.get("x-middleware-request-x-nonce");
    expect(nonce).toBeTruthy();
    expect(r.headers.get("content-security-policy")).toContain(`'nonce-${nonce}'`);
    expect(r.headers.get("x-middleware-request-content-security-policy")).toBe(r.headers.get("content-security-policy"));
  });
  it("does not let a client set the nonce", () => {
    const r = panel(new NextRequest("https://panel.localhost/fa", {headers: {"x-nonce": "forged"}}));
    expect(r.headers.get("x-middleware-request-x-nonce")).not.toBe("forged");
  });
  it("adds the verify origin only where it is passed", () => {
    const origin = "https://*.verify.dns.example.ir";
    const withOrigin = createProxy({protectedPrefixes: [], sessionCookies: [], verifyOrigin: origin});
    expect(withOrigin(req("/fa")).headers.get("content-security-policy")).toContain(`connect-src 'self' ${origin}`);
    expect(admin(req("/fa")).headers.get("content-security-policy")).toContain("connect-src 'self';");
  });
});

describe("session gate", () => {
  it("sends a visitor without cookies to login, with a next value", () => {
    const r = panel(req("/fa/profiles/abc?tab=1"));
    expect(r.status).toBe(307);
    const loc = location(r)!;
    expect(loc.startsWith("/fa/login?")).toBe(true);
    expect(new URLSearchParams(loc.split("?")[1]).get("next")).toBe("/profiles/abc?tab=1");
  });
  it("keeps the language of the URL", () => {
    expect(location(panel(req("/en/preferences/account")))!.startsWith("/en/login?")).toBe(true);
  });
  it("gates an unprefixed protected path in one step", () => {
    expect(location(panel(req("/profiles")))!.startsWith("/fa/login?")).toBe(true);
  });
  it("lets a visitor with either panel cookie through", () => {
    expect(panel(req("/fa/profiles", "__Host-ctrlz_session=abc")).status).toBe(200);
    expect(panel(req("/fa/profiles", "__Host-ctrlz_refresh=abc")).status).toBe(200);
  });
  it("does not accept an empty cookie, or the admin cookie in the panel", () => {
    expect(panel(req("/fa/profiles", "__Host-ctrlz_session=")).status).toBe(307);
    expect(panel(req("/fa/profiles", "__Host-ctrlz_admin=abc")).status).toBe(307);
    expect(panel(req("/fa/profiles", "ctrlz_session=abc")).status).toBe(307);
  });
  it("leaves public pages alone", () => {
    for (const p of ["/fa/login", "/fa/register", "/fa/invite", "/fa/forgot-password", "/fa", "/fa/virtual-lab"]) {
      expect(panel(req(p)).status, p).toBe(200);
    }
  });
  it("is not fooled by encoding, slashes or a trailing slash", () => {
    for (const p of ["/fa/%70rofiles", "/fa//profiles", "/fa/profiles/", "/fa/profiles/../profiles"]) {
      const r = panel(req(p));
      expect(r.status, p).toBe(307);
    }
  });
  it("runs on a dotted path", () => {
    const r = panel(req("/fa/profiles/x.y"));
    expect(r.status).toBe(307);
    expect(r.headers.get("content-security-policy")).toBeTruthy();
  });
  it("does not match a lookalike prefix", () => {
    expect(panel(req("/fa/profilesx")).status).toBe(200);
  });
  it("gates the admin on its own cookie", () => {
    expect(admin(req("/fa/users")).status).toBe(307);
    expect(admin(req("/fa/users", "__Host-ctrlz_session=abc")).status).toBe(307);
    expect(admin(req("/fa/users", "__Host-ctrlz_admin=abc")).status).toBe(200);
    expect(admin(req("/fa/login")).status).toBe(200);
  });
  it("keeps the request origin in the redirect", () => {
    expect(new URL(panel(req("/fa/profiles")).headers.get("location")!).origin).toBe("https://panel.localhost");
  });
});

describe("splitLocale", () => {
  it("splits a prefixed path", () => expect(splitLocale("/en/profiles/x")).toEqual({locale: "en", rest: "/profiles/x"}));
  it("handles the bare locale", () => expect(splitLocale("/fa")).toEqual({locale: "fa", rest: "/"}));
  it("defaults an unprefixed path", () => expect(splitLocale("/profiles")).toEqual({locale: "fa", rest: "/profiles"}));
  it("survives a malformed escape", () => expect(splitLocale("/fa/%zz").locale).toBe("fa"));
});
