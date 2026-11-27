import {NextRequest} from "next/server";
import {describe, expect, it} from "vitest";

import {createProxy, redirectKind} from "./createProxy.ts";
import {expectedPolicy} from "./expectedCsp.ts";
import {splitLocale} from "./gate.ts";
import {sanitizeNext} from "./safeNext.ts";
import {ADMIN_ROUTES, PANEL_ROUTES} from "../testing/routes.ts";
import {ADMIN_PROTECTED_PREFIXES, ADMIN_SESSION_COOKIES, PANEL_PROTECTED_PREFIXES, PANEL_SESSION_COOKIES} from "./prefixes.ts";

const panel = createProxy({app: "panel", protectedPrefixes: PANEL_PROTECTED_PREFIXES, sessionCookies: PANEL_SESSION_COOKIES});
const admin = createProxy({app: "admin", protectedPrefixes: ADMIN_PROTECTED_PREFIXES, sessionCookies: ADMIN_SESSION_COOKIES});

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
    const withOrigin = createProxy({app: "panel", protectedPrefixes: [], sessionCookies: [], verifyOrigins: [origin]});
    expect(withOrigin(req("/fa")).headers.get("content-security-policy")).toContain(`connect-src 'self' ${origin}`);
    expect(admin(req("/fa")).headers.get("content-security-policy")).toContain("connect-src 'self';");
  });
});

// The whole header, not a word of it: a change to buildCsp or to createProxy for one app only (a wider style-src-attr, an origin in img-src, a
// dropped manifest-src) fails here for that app, before the browser specs, which cannot reach the admin's pages until WP10 (gate-r20-1).
describe("the CSP is exactly the policy of 15.2 on every kind of answer, on both apps (gate-r20-1)", () => {
  const nonceOf = (r: Response) => /'nonce-([^']+)'/.exec(r.headers.get("content-security-policy") ?? "")?.[1] ?? "";
  const kinds: Array<[string, string, Record<string, string>?, string?]> = [
    ["a page", "/fa/login"],
    ["the locale root", "/fa"],
    ["a locale redirect", "/"],
    ["a gated path with no cookie", "/fa/users"],
    ["a panel gated path with no cookie", "/fa/profiles"],
    ["a gated path with a cookie", "/fa/profiles", {cookie: "__Host-ctrlz_session=x"}],
    ["an unknown path", "/fa/nothing-here"],
    ["a path that is no page", "/fa/profiles%00"],
    ["a static file name", "/_next/static/chunks/x.js"],
    ["a data request", "/_next/data/x/fa/login.json", {"x-nextjs-data": "1"}],
    ["a refused Server Action call", "/fa/login", {"next-action": "x"}],
  ];
  for (const [app, proxy] of [["panel", panel], ["admin", admin]] as const) {
    for (const [label, path, headers] of kinds) {
      it(`${app}: ${label}`, () => {
        const r = proxy(new NextRequest(`https://panel.localhost${path}`, {headers: headers ?? {}}));
        const nonce = nonceOf(r);
        expect(nonce, "a nonce in the policy").toMatch(/^[A-Za-z0-9+/]{22}==$/);
        expect(r.headers.get("content-security-policy")).toBe(expectedPolicy(nonce));
        expect(r.headers.get("content-security-policy-report-only")).toBeNull();
      });
    }
  }
  it("gives the panel alone the verify origin, in connect-src and nowhere else", () => {
    const origin = "https://*.verify.dns.example.ir";
    const withOrigin = createProxy({app: "panel", protectedPrefixes: [], sessionCookies: [], verifyOrigins: [origin]});
    const r = withOrigin(req("/fa/login"));
    expect(r.headers.get("content-security-policy")).toBe(expectedPolicy(nonceOf(r), ["'self'", origin]));
  });
});

describe("a verify origin that is not the one shape (gate-r4-3)", () => {
  it("is refused when the proxy is made, so a caller that skips parseVerifyOrigins cannot widen the policy", () => {
    for (const bad of ["*", "https://*.verify.dns.example.ir; script-src *", "https://evil.example", "https://*.verify.dns.example.ir/"]) {
      expect(() => createProxy({app: "panel", protectedPrefixes: [], sessionCookies: [], verifyOrigins: [bad]}), bad).toThrow(/CTRLZ_VERIFY_ORIGIN/);
    }
  });
  it("is refused for the admin even in the right shape", () => {
    expect(() => createProxy({app: "admin", protectedPrefixes: [], sessionCookies: [], verifyOrigins: ["https://*.verify.dns.example.ir"]})).toThrow(/only the panel/);
  });
});

describe("COOP, CORP and Permissions-Policy", () => {
  it("are on a page, a redirect, a gate redirect and a dotted path", () => {
    for (const path of ["/fa", "/", "/fa/profiles", "/fa/profiles/x.y", "/de", "/invite?code=1"]) {
      const r = panel(req(path));
      expect(r.headers.get("cross-origin-opener-policy"), path).toBe("same-origin");
      expect(r.headers.get("cross-origin-resource-policy"), path).toBe("same-origin");
      expect(r.headers.get("permissions-policy"), path).toContain("publickey-credentials-get=(self)");
    }
  });
  it("are on the admin too, and the admin's Permissions-Policy has no passkey (gate-r2-18)", () => {
    const r = admin(req("/fa/users"));
    expect(r.headers.get("cross-origin-opener-policy")).toBe("same-origin");
    expect(r.headers.get("permissions-policy")).toContain("publickey-credentials-get=()");
    expect(r.headers.get("permissions-policy")).toContain("publickey-credentials-create=()");
    expect(r.headers.get("permissions-policy")).toContain("clipboard-write=(self)");
  });
  it("answer a path that names no page with a 404 that no cache may keep, whatever the method (gate-r2-6)", () => {
    for (const method of ["GET", "HEAD", "POST", "OPTIONS", "PUT", "DELETE"]) {
      for (const path of ["/fa/profiles%00", "/fa/%zz", "/_next/static/%zz"]) {
        for (const proxy of [panel, admin]) {
          const r = proxy(new NextRequest(`https://panel.localhost${path}`, {method}));
          const label = `${method} ${path}`;
          expect(r.status, label).toBe(404);
          expect(r.headers.get("cache-control"), label).toBe("no-store");
          expect(r.headers.get("content-security-policy"), label).toContain("default-src 'none'");
          expect(r.headers.get("cross-origin-opener-policy"), label).toBe("same-origin");
          expect(r.headers.get("permissions-policy"), label).toBeTruthy();
        }
      }
    }
  });
  it("carry the CSP and the three headers on a gate redirect whatever the method, which keeps its method (gate-r2-6)", () => {
    for (const method of ["GET", "HEAD", "POST", "OPTIONS"]) {
      const r = panel(new NextRequest("https://panel.localhost/fa/profiles", {method}));
      expect(r.status, method).toBe(307);
      expect(r.headers.get("content-security-policy"), method).toContain("default-src 'none'");
      expect(r.headers.get("cross-origin-resource-policy"), method).toBe("same-origin");
      expect(r.headers.get("permissions-policy"), method).toBeTruthy();
    }
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
  it("returns to the page that was asked for, not to its decoded spelling (wp5-r14-1)", () => {
    const next = (path: string) => {
      const loc = location(panel(req(path)))!;
      return new URLSearchParams(loc.split("?")[1]).get("next");
    };
    // The next value, once the login page decodes it, is the request path as it was written.
    expect(next("/fa/profiles/a%3Fb")).toBe("/profiles/a%3Fb");
    expect(next("/fa/profiles/a%2Fb")).toBe("/profiles/a%2Fb");
    expect(next("/fa/profiles/a%23b")).toBe("/profiles/a%23b");
    expect(next("/fa/profiles/a%3Fb?tab=1")).toBe("/profiles/a%3Fb?tab=1");
    expect(next("/profiles/a%3Fb")).toBe("/profiles/a%3Fb");
    expect(next("/%66a/profiles/a%3Fb")).toBe("/profiles/a%3Fb");
    // An escaped slash that made the locale: the page is the same, written again.
    expect(next("/fa%2Fprofiles/a%3Fb")).toBe("/profiles/a%3Fb");
    // A spelling that sanitizeNext refuses still drops next, and still redirects.
    expect(next("/fa/profiles/..%2F..%2Fx")).toBeNull();
    expect(panel(req("/fa/profiles/50%25")).status).toBe(307);
  });
  it("never builds a next that the proxy itself refuses after login (wp5-r17-2)", () => {
    const next = (path: string) => {
      const loc = location(panel(req(path)))!;
      return new URLSearchParams(loc.split("?")[1]).get("next");
    };
    // next-intl rewrites each of these to another spelling, so with a session they are a 404: next is dropped, login stays.
    for (const p of ["/fa/profiles/50%25", "/fa/profiles/%70x", "/fa/profiles/x%2e", "/fa/profiles/50%25?tab=1"]) {
      expect(panel(req(p)).status).toBe(307);
      expect(next(p)).toBeNull();
      expect(panel(req(p, "__Host-ctrlz_session=abc")).status).toBe(404);
    }
    // The class, both ways: whatever next the gate keeps is a path the proxy serves with a session.
    for (const p of ["/fa/profiles/a%3Fb", "/fa/profiles/a%2Fb", "/fa/profiles/a%23b?tab=1", "/fa/profiles/abc"]) {
      const n = next(p)!;
      expect(n).not.toBeNull();
      expect(panel(req(`/fa${n}`, "__Host-ctrlz_session=abc")).status).toBe(200);
    }
  });
  // gate-r8-2. The login page and the gate both keep a `next` through sanitizeNext, so the rule that decides whether the proxy serves the
  // path has to be inside it. Not each spelling: every value that sanitizeNext keeps, from a fuzz over the pieces that have mattered, must be
  // a path the proxy serves with a session.
  it("serves, with a session, every next that sanitizeNext keeps (gate-r8-2)", () => {
    const pieces = ["/", "profiles", "preferences", "endpoints", "x", "50", "%25", "%70", "%2e", "%2f", "%2F", "%28", "%5B", "%5b", "[", "]", "|", "%7C", "a.b", "%D8%B3", "س", "'", "~", "!", "*", "(", ")", "?", "#", "-", "_", "%3F", "%23", "%20", ".segments", ".segments/", ".segment.rsc", ".rsc"];
    let seed = 11;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
    let kept = 0;
    for (let i = 0; i < 6000; i += 1) {
      let value = "/profiles/";
      for (let n = rnd() % 5; n > 0; n -= 1) value += pieces[rnd() % pieces.length];
      const next = sanitizeNext(value, PANEL_PROTECTED_PREFIXES);
      if (next === undefined) continue;
      kept += 1;
      expect(panel(req(`/fa${next}`, "__Host-ctrlz_session=abc")).status, next).not.toBe(404);
    }
    expect(kept).toBeGreaterThan(100);
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
  // gate-r32-1. The admin cookie is SameSite=Strict, so a link from another site arrives with none although the admin is signed in.
  // The page is served and the shell asks /me from its own origin; the panel's cookies are Lax, so its gate stays.
  it("serves the admin's page to a cross-site navigation instead of sending a signed-in admin to login", () => {
    const link = (path: string, site: string, mode = "navigate") =>
      new NextRequest(`https://panel.localhost${path}`, {headers: {"sec-fetch-site": site, "sec-fetch-mode": mode}});
    expect(admin(link("/fa/users", "cross-site")).status).toBe(200);
    expect(admin(link("/fa/users", "cross-site")).headers.get("content-security-policy")).toBeTruthy();
    // Everything else without the cookie still goes to login: typed or bookmarked (none), a click inside the site, a subresource.
    for (const [site, mode] of [["none", "navigate"], ["same-origin", "navigate"], ["same-site", "navigate"], ["cross-site", "cors"], ["cross-site", "no-cors"]] as const) {
      expect(admin(link("/fa/users", site, mode)).status, `${site} ${mode}`).toBe(307);
    }
    expect(panel(link("/fa/profiles", "cross-site")).status).toBe(307);
  });
  it("gates the admin on its own cookie", () => {
    expect(admin(req("/fa/users")).status).toBe(307);
    expect(admin(req("/fa/users", "__Host-ctrlz_session=abc")).status).toBe(307);
    expect(admin(req("/fa/users", "__Host-ctrlz_admin=abc")).status).toBe(200);
    expect(admin(req("/fa/login")).status).toBe(200);
  });
  // gate-r12-4, the class: the hand lists of testing/routes.ts and the prefixes of prefixes.ts must agree, in both directions and for both apps,
  // so a prefix dropped from either list fails here and not only in the browser run (routesSpec's gateProblems needs the admin's WP10 pages for it).
  describe.each([
    {name: "panel", proxy: panel, routes: PANEL_ROUTES, prefixes: PANEL_PROTECTED_PREFIXES, open: ["/", "/login", "/register", "/invite", "/forgot-password", "/change-password", "/suspended", "/s/[token]", "/[...rest]"]},
    {name: "admin", proxy: admin, routes: ADMIN_ROUTES, prefixes: ADMIN_PROTECTED_PREFIXES, open: ["/", "/login", "/[...rest]"]},
  ] as const)("the $name gate and the page list agree (gate-r12-4)", ({proxy, routes, prefixes, open}) => {
    const behind = (routes as readonly string[]).filter((route) => !(open as readonly string[]).includes(route));
    it("sends every page that is not open to the login with no cookie, and keeps it as next", () => {
      expect(behind.length).toBeGreaterThan(0);
      // A dynamic route is asked with a value in its place: `[id]` is a UUID, `[folderId]` too.
      const concrete = (route: string) => route.replaceAll("[id]", "6f1c1b0e-8f35-4d57-9b8f-1d1c2a3b4c5d").replaceAll("[folderId]", "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d");
      for (const route of behind.map(concrete)) {
        for (const lang of ["fa", "en"]) {
          const r = proxy(req(`/${lang}${route}`));
          expect(r.status, `${lang}${route}`).toBe(307);
          expect(location(r), `${lang}${route}`).toBe(`/${lang}/login?next=${encodeURIComponent(route)}`);
        }
      }
    });
    it("leaves the open pages alone", () => {
      for (const route of open.filter((route) => route !== "/" && route !== "/[...rest]")) expect(proxy(req(`/fa${route}`)).status, route).toBe(200);
      expect(proxy(req("/fa/nothing-here")).status).toBe(200);
    });
    it("has a page under every protected prefix, and a prefix for every page that is behind the gate", () => {
      for (const prefix of prefixes) {
        expect(behind.some((route) => route === prefix || route.startsWith(`${prefix}/`)), `a page under ${prefix}`).toBe(true);
      }
      for (const route of behind) {
        expect(prefixes.some((prefix) => route === prefix || route.startsWith(`${prefix}/`)), `a prefix for ${route}`).toBe(true);
      }
    });
    it("gates a page below each prefix as well", () => {
      for (const prefix of prefixes) expect(proxy(req(`/fa${prefix}/x`)).status, prefix).toBe(307);
    });
  });
  it("keeps the request origin in the redirect", () => {
    expect(new URL(panel(req("/fa/profiles")).headers.get("location")!).origin).toBe("https://panel.localhost");
  });
});

describe("splitLocale", () => {
  it("splits a prefixed path", () => expect(splitLocale("/en/profiles/x")).toEqual({locale: "en", rest: "/profiles/x", rawRest: "/profiles/x"}));
  it("handles the bare locale", () => expect(splitLocale("/fa")).toEqual({locale: "fa", rest: "/", rawRest: "/"}));
  it("defaults an unprefixed path", () => expect(splitLocale("/profiles")).toEqual({locale: "fa", rest: "/profiles", rawRest: "/profiles"}));
  it("survives a malformed escape", () => expect(splitLocale("/fa/%zz").locale).toBe("fa"));
  it("keeps the raw text for rawRest and the decoded text for rest (wp5-r14-1)", () => {
    expect(splitLocale("/fa/profiles/a%3Fb")).toEqual({locale: "fa", rest: "/profiles/a?b", rawRest: "/profiles/a%3Fb"});
    expect(splitLocale("/%66a/profiles/a%23b")).toEqual({locale: "fa", rest: "/profiles/a#b", rawRest: "/profiles/a%23b"});
    expect(splitLocale("/fa//profiles/50%25").rawRest).toBe("/profiles/50%25");
    expect(splitLocale("/profiles/a%2Fb").rawRest).toBe("/profiles/a%2Fb");
  });
  it("encodes the rest again when an escaped slash is what made the locale", () => {
    expect(splitLocale("/fa%2Fprofiles/a%3Fb")).toMatchObject({locale: "fa", rest: "/profiles/a?b", rawRest: "/profiles/a%3Fb"});
  });
});

describe("Next's build output (wp5-r1-9)", () => {
  it("is let through, not redirected to a language, and has the CSP and the three headers", () => {
    for (const proxy of [panel, admin]) {
      for (const path of ["/_next/static/chunks/a.js", "/_next/static/media/x.woff2", "/_next/static/chunks/nothing-here.js?q=1"]) {
        const r = proxy(req(path));
        expect(r.status, path).toBe(200);
        expect(location(r), path).toBeNull();
        expect(r.headers.get("x-middleware-next"), path).toBe("1");
        expect(r.headers.get("content-security-policy"), path).toContain("default-src 'none'");
        expect(r.headers.get("cross-origin-opener-policy"), path).toBe("same-origin");
      }
    }
  });
  it("forwards the nonce and the policy of the proxy, not the ones the client sent", () => {
    const r = panel(new NextRequest("https://panel.localhost/_next/static/chunks/nothing.js", {headers: {"x-nonce": "attackerchosen", "content-security-policy": "default-src *"}}));
    const nonce = /'nonce-([^']+)'/.exec(r.headers.get("content-security-policy")!)![1];
    expect(nonce).not.toBe("attackerchosen");
    // What Next hands to the render: the request headers that the proxy set, listed in x-middleware-override-headers.
    expect(r.headers.get("x-middleware-override-headers")).toContain("x-nonce");
    expect(r.headers.get("x-middleware-request-x-nonce")).toBe(nonce);
    expect(r.headers.get("x-middleware-request-content-security-policy")).toBe(r.headers.get("content-security-policy"));
  });
  it("is not touched by the gate: a protected-looking path under it needs no session", () => {
    expect(panel(req("/_next/static/profiles")).status).toBe(200);
  });
  // gate-r16-5: Next answers a Range it cannot satisfy, and a failed If-Match or If-Unmodified-Since, with a 500 for a file here. The headers are left
  // out of what Next reads, and the rest stays, the conditional GET headers included (a 304 is the right answer to those).
  it("hands Next no Range, If-Range, If-Match or If-Unmodified-Since, and still the other request headers (gate-r16-5)", () => {
    for (const proxy of [panel, admin]) {
      for (const [name, value] of [["range", "bytes=x"], ["range", "bytes=5-2"], ["range", "bytes=0-9"], ["if-range", "\"x\""], ["if-match", "\"abc\""], ["if-unmodified-since", "Wed, 21 Oct 1990 07:28:00 GMT"]] as const) {
        const r = proxy(new NextRequest("https://panel.localhost/_next/static/chunks/a.js", {headers: {[name]: value, "accept-encoding": "gzip", "if-none-match": "\"e\"", "if-modified-since": "Wed, 21 Oct 2099 07:28:00 GMT"}}));
        const listed = (r.headers.get("x-middleware-override-headers") ?? "").split(",");
        for (const gone of ["range", "if-range", "if-match", "if-unmodified-since"]) expect(listed, `${name}: ${value}`).not.toContain(gone);
        expect(listed, name).toEqual(expect.arrayContaining(["x-nonce", "accept-encoding", "if-none-match", "if-modified-since"]));
      }
    }
  });
  // gate-r18-1: Next's static server answers any other method with a 405 that Next turns into a bare 500, so one POST to a public chunk would raise the
  // 5xx rate at will. The proxy answers its own 405 for them, with the full header set, and GET and HEAD still pass to Next.
  it("answers its own 405 for any method but GET and HEAD, with the headers, and never lets one reach Next (gate-r18-1)", () => {
    for (const proxy of [panel, admin]) {
      for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
        for (const path of ["/_next/static/chunks/a.js", "/_next/static/nothing-here.css", "/_next/static/media/f.woff2"]) {
          const label = `${method} ${path}`;
          const r = proxy(new NextRequest(`https://panel.localhost${path}`, {method}));
          expect(r.status, label).toBe(405);
          expect(r.headers.get("allow"), label).toBe("GET, HEAD");
          expect(r.headers.get("content-type"), label).toContain("text/plain");
          expect(r.headers.get("cache-control"), label).toBe("no-store");
          expect(r.headers.get("content-security-policy"), label).toContain("default-src 'none'");
          expect(r.headers.get("cross-origin-opener-policy"), label).toBe("same-origin");
          expect(r.headers.get("cross-origin-resource-policy"), label).toBe("same-origin");
          expect(r.headers.get("permissions-policy"), label).toBeTruthy();
          expect(r.headers.get("x-middleware-next"), label).toBeNull();
        }
      }
      for (const method of ["GET", "HEAD"]) {
        const r = proxy(new NextRequest("https://panel.localhost/_next/static/chunks/a.js", {method}));
        expect(r.status, method).toBe(200);
        expect(r.headers.get("x-middleware-next"), method).toBe("1");
      }
    }
  });
});

describe("paths the URL parser reads as another page (wp5-r15)", () => {
  const SESSION = "__Host-ctrlz_session=x";
  const ADMIN = "__Host-ctrlz_admin=x";
  const hex = (n: number) => n.toString(16).padStart(2, "0");
  // The spellings of every C0 control and the space, at the end, at the start and in the middle of a segment, and in the locale segment.
  const spellings: string[] = [];
  for (let c = 0; c <= 0x20; c++) {
    const e = `%${hex(c)}`;
    spellings.push(`/fa/profiles${e}`, `/fa/${e}profiles`, `/fa/prof${e}iles`, `/fa/profiles${e}/x`, `/f${e}a/profiles`, `/${e}fa/profiles`, `/fa${e}/profiles`);
  }
  spellings.push("/fa/profiles%7f", "/fa/profiles%7F", "/fa/profiles%09?x=1", "/fa/endpoints%20", "/en/profiles%20", "/fa/analytics%0d", "/fa/preferences%00");

  it("never serves a protected page without a cookie, whatever control character or space hides in its name", () => {
    for (const p of spellings) {
      const r = panel(req(p));
      expect(r.status, p).not.toBe(200);
      expect(r.headers.get("x-middleware-rewrite"), p).toBeNull();
    }
  });
  it("answers 404 with the CSP and the three headers, and a body that does not echo the path", async () => {
    for (const proxy of [panel, admin]) {
      for (const p of ["/fa/profiles%00", "/fa/%09profiles", "/fa/prof%0ailes", "/fa/profiles%20", "/fa/users%0d", "/f%09a/profiles"]) {
        const r = proxy(req(p));
        expect(r.status, p).toBe(404);
        expect(r.headers.get("content-security-policy"), p).toContain("default-src 'none'");
        expect(r.headers.get("cross-origin-opener-policy"), p).toBe("same-origin");
        expect(r.headers.get("cross-origin-resource-policy"), p).toBeTruthy();
        expect(r.headers.get("permissions-policy"), p).toBeTruthy();
        expect(await r.text(), p).toBe("Not Found");
      }
    }
  });
  it("refuses them with a cookie too, so no page is rendered for a name the gate did not judge", () => {
    for (const p of spellings) {
      expect(panel(req(p, SESSION)).status, p).toBe(404);
      expect(admin(req(p.replace("profiles", "users"), ADMIN)).status, p).toBe(404);
    }
  });
  it("sends no x-middleware-* header for a path that is rewritten to another spelling of itself", () => {
    // `%70` is `p`, `%2e` is a dot, `%252e` is the text `%2e`, `%25` a percent sign that next-intl decodes to a bare one: each is rewritten to a spelling that is not the request's.
    for (const p of ["/fa/%70rofiles", "/fa/profiles%2e", "/fa/profiles%252e", "/fa/pro%66iles?a=1", "/fa/profiles%2e?x=1", "/fa/profiles/50%25"]) {
      const r = panel(req(p, SESSION));
      expect(r.status, p).toBe(404);
      const names = [...r.headers.keys()].filter((n) => n.startsWith("x-middleware-") || n === "x-nonce");
      expect(names, p).toEqual([]);
      expect(r.headers.get("content-security-policy"), p).toContain("default-src 'none'");
    }
  });
  it("keeps serving the paths that were fine: the page, its query, a dotted name and an escaped reserved character", () => {
    for (const p of ["/fa/profiles", "/fa/profiles?x=1", "/en/profiles", "/fa/profiles/a%3Fb", "/fa/profiles/a%2Fb", "/fa/profiles/%D9%BE"]) {
      expect(panel(req(p, SESSION)).status, p).toBe(200);
    }
  });
  it("still sends a visitor without a cookie to login for the spellings that are not control characters", () => {
    for (const p of ["/fa/%70rofiles", "/fa//profiles", "/fa/profiles/"]) expect(panel(req(p)).status, p).toBe(307);
  });
});

describe("a path whose percent escape does not decode (wp5-r16-1, wp5-r16-3)", () => {
  const SESSION = "__Host-ctrlz_session=x";
  const ADMIN = "__Host-ctrlz_admin=x";
  // `%zz` and a lone `%` are not hex, `%E0%A4%A` is cut, `%C0` and `%FF` are never UTF-8. Each sits in a locale, a protected
  // page, a dynamic segment, an unprefixed path and the build output.
  const broken = [
    "/fa/%zz", "/fa/profiles%zz", "/fa/profiles/%E0%A4%A", "/fa/%C0", "/x%C0", "/en/%C0", "/fa/profiles%", "/fa/profiles/x%FF", "/fa/profiles/50%",
    "/%", "/%zz/profiles", "/fa%C0/profiles", "/fa/endpoints/%E0%A4%A/x", "/_next/static/%zz", "/_next/static/chunks/%zz.js", "/_next/static/%", "/api/v1/%zz",
  ];

  it("answers 404 with the CSP and the three headers, with a cookie, without one, in both apps", async () => {
    for (const [proxy, cookie] of [[panel, SESSION], [panel, undefined], [admin, ADMIN], [admin, undefined]] as const) {
      for (const p of broken) {
        const r = proxy(req(p, cookie));
        expect(r.status, `${p} ${cookie ?? ""}`).toBe(404);
        expect(r.headers.get("content-security-policy"), p).toContain("default-src 'none'");
        expect(r.headers.get("cross-origin-opener-policy"), p).toBe("same-origin");
        expect(r.headers.get("cross-origin-resource-policy"), p).toBeTruthy();
        expect(r.headers.get("permissions-policy"), p).toBeTruthy();
        expect(await r.text(), p).toBe("Not Found");
        expect([...r.headers.keys()].filter((n) => n.startsWith("x-middleware-") || n === "x-nonce"), p).toEqual([]);
      }
    }
  });
  it("gives the same answer to the same class on a protected prefix, whatever the cookie", () => {
    // Before the fix this was 307 without a cookie and a bare 500 with one.
    expect(panel(req("/fa/profiles/%E0%A4%A")).status).toBe(404);
    expect(panel(req("/fa/profiles/%E0%A4%A", SESSION)).status).toBe(404);
  });
  it("does not refuse a valid escape: multi-byte UTF-8, an escaped reserved character, a percent sign written as %25", () => {
    for (const p of ["/fa/profiles/%D9%BE", "/fa/profiles/a%3Fb", "/fa/profiles/a%2Fb"]) expect(panel(req(p, SESSION)).status, p).toBe(200);
  });
});

describe("the escapes that the proxy serves and the ones it refuses (wp5-r18-1)", () => {
  const SESSION = "__Host-ctrlz_session=x";
  // next-intl re-serialises the rewrite target, so some escapes come back in another spelling. The proxy serves a path
  // only when it is written the way `encodeURIComponent` writes it (what a link built from a name looks like) and the
  // target is the same page. Everything else that changes spelling is refused, because the gate did not judge it as written.
  const hex = (c: number) => `%${c.toString(16).toUpperCase().padStart(2, "0")}`;
  const status = (path: string, cookie?: string) => panel(req(path, cookie)).status;
  const next = (path: string) => new URLSearchParams(location(panel(req(path)))!.split("?")[1]).get("next");

  it("serves what encodeURIComponent writes, including the characters that next-intl re-serialises", () => {
    // The names that P2 pages will build from user text: brackets and a bar come back from next-intl as `[`, `]`, `|`.
    for (const name of ["a[b]", "a|b", "a^b", "a{b}", "a`b", 'a"b', "a<b>", "a\\b", "a:b", "a@b", "a$b", "a&b", "a+b", "a,b", "a;b", "a=b", "a?b", "a/b", "a#b", "پ", "a[پ]b|c"]) {
      const p = `/fa/profiles/${encodeURIComponent(name)}`;
      const r = panel(req(p, SESSION));
      expect(r.status, p).toBe(200);
      // No rewrite header may be left to reach the client (Next sends it, with the internal target, on a 404), and the
      // answer is a plain continue. The old assertion fell back to `p` and so passed whether the header was there or not.
      expect(r.headers.get("x-middleware-rewrite"), p).toBeNull();
      expect(r.headers.get("x-middleware-next"), p).toBe("1");
    }
  });
  it("keeps next for such a path when the visitor has no session, and it is a path that is served after login", () => {
    for (const name of ["a[b]", "a|b", "a[b]|c"]) {
      const p = `/fa/profiles/${encodeURIComponent(name)}`;
      expect(status(p), p).toBe(307);
      expect(next(p), p).toBe(`/profiles/${encodeURIComponent(name)}`);
      expect(status(`/fa${next(p)}`, SESSION), p).toBe(200);
    }
  });
  it("refuses every other escape that next-intl re-serialises, and pins the set (exactly these)", () => {
    // For each printable ASCII character: the proxy serves `a%XXb` only if encodeURIComponent writes that very escape.
    // A percent sign is the one exception: its target holds a bare `%`.
    const refused: string[] = [];
    for (let c = 0x21; c < 0x7f; c++) {
      const escape = hex(c);
      const p = `/fa/profiles/a${escape}b`;
      const writtenByLink = encodeURIComponent(String.fromCharCode(c)) === escape && escape !== "%25";
      expect(status(p, SESSION), p).toBe(writtenByLink ? 200 : 404);
      if (!writtenByLink) refused.push(escape);
    }
    // Digits, letters, - . _ ~, the five marks ! ' ( ) * that encodeURIComponent leaves alone, and the percent sign.
    expect(refused).toHaveLength(10 + 26 + 26 + 4 + 5 + 1);
    for (const e of ["%21", "%27", "%28", "%29", "%2A", "%2D", "%2E", "%5F", "%7E", "%41", "%7A", "%30", "%25", "%70"]) expect(refused).toContain(e);
    for (const e of ["%5B", "%5D", "%7C", "%2F", "%3F", "%23", "%2B", "%26"]) expect(refused).not.toContain(e);
  });
  it("refuses a lower case hex digit, an escaped letter and a dot, with a cookie and without, and drops next", () => {
    for (const p of ["/fa/profiles/a%5bb%5d", "/fa/profiles/%70x", "/fa/profiles/x%2e", "/fa/profiles/50%25", "/fa/profiles/a%7cb"]) {
      expect(status(p, SESSION), p).toBe(404);
      expect(status(p), p).toBe(307);
      expect(next(p), p).toBeNull();
    }
  });
  it("answers the same for the admin", () => {
    for (const [p, expected] of [["/fa/users/a%5Bb%5D", 200], ["/fa/users/a%7Cb", 200], ["/fa/users/%70x", 404]] as const) {
      expect(admin(req(p, "__Host-ctrlz_admin=x")).status, p).toBe(expected);
    }
  });
  it("turns the rewrite of a respelled path into a plain continue, so no x-middleware-rewrite is left to leak", () => {
    // On next start the header reached the client of a 404 with its target `/fa/profiles/a[b]` (measured). next-intl sends no
    // rewrite for a path that it leaves alone, and a respelled path now looks the same, nonce and policy on the request included.
    for (const p of ["/fa/profiles/a%5Bb%5D", "/fa/profiles/a%7Cb?x=1", "/fa/profiles/%5B%D9%BE%5D"]) {
      const r = panel(req(p, SESSION));
      expect(r.headers.get("x-middleware-rewrite"), p).toBeNull();
      expect(r.headers.get("x-middleware-next"), p).toBe("1");
      expect(r.headers.get("x-middleware-override-headers"), p).toContain("x-nonce");
      expect(r.headers.get("x-middleware-request-content-security-policy"), p).toBe(r.headers.get("content-security-policy"));
    }
  });
});

// gate-r3-6. Next strips `/_next/data/<id>/` and `.json` before the proxy runs and marks the request with x-nextjs-data, so the
// proxy sees an ordinary page path. Neither app has a data route: the answer must be the proxy's plain 404, never a page or
// Next's prerendered 404 document (whose inline scripts carry no nonce) under this request's CSP.
describe("a data request of the Pages Router (gate-r3-6)", () => {
  const data = (path: string, cookie?: string) => new NextRequest(`https://panel.localhost${path}`, {headers: {"x-nextjs-data": "1", ...(cookie ? {cookie} : {})}});

  it("is the proxy's plain 404 with the CSP and the three headers, whatever page it names and whatever the cookie", async () => {
    for (const [name, proxy] of [["panel", panel], ["admin", admin]] as const) {
      for (const path of ["/fa/login", "/fa/profiles", "/fa/users", "/fa/nothing", "/", "/fa"]) {
        for (const cookie of [undefined, "__Host-ctrlz_session=x", "__Host-ctrlz_admin=x"]) {
          const r = proxy(data(path, cookie));
          const label = `${name} ${path} ${cookie ?? "no cookie"}`;
          expect(r.status, label).toBe(404);
          expect(r.headers.get("content-type"), label).toContain("text/plain");
          expect(await r.text(), label).toBe("Not Found");
          expect(r.headers.get("content-security-policy"), label).toContain("default-src 'none'");
          expect(r.headers.get("cross-origin-opener-policy"), label).toBe("same-origin");
          expect(r.headers.get("cache-control"), label).toBe("no-store");
          expect(r.headers.get("location"), label).toBeNull();
          expect([...r.headers.keys()].filter((n) => n.startsWith("x-middleware-")), label).toEqual([]);
        }
      }
    }
  });
  it("leaves the same page alone when the header is absent", () => {
    expect(panel(req("/fa/login")).status).toBe(200);
  });
});

// gate-r23-4: next-intl decodes one level of percent escapes (decodeURI) before it builds its locale redirect, so the Location is not always the
// path that was asked for. It is safe only because `/<locale>` always stands in front. The proxy now answers a locale redirect whose Location is not
// `/<locale>` plus the asked path with its plain 404, the rule `rewriteKind` already applies to rewrites.
describe("a locale redirect that leaves the asked path, or the origin (gate-r23-4)", () => {
  const HOSTILE = [
    "/%2F%2Fevil.example", "/%252F%252Fevil.example", "/%5C%5Cevil.example", "/%255C%255Cevil.example", "/FA/%2F%2Fevil.example",
    "/FA/%252F%252Fevil.example", "/Fa/%5C%5Cevil.example", "/EN/%252F%252Fevil.example?x=1", "/%E2%80%AE%2F%2Fevil.example",
    "/FA/%250D%250ASet-Cookie:x=1", "/FA/%25zz", "/FA/profiles%252F", "//evil.example", "/\\evil.example", "/fa//evil.example", "/FA//evil.example",
  ];

  it("never gives a Location other than /<locale> and the path that was asked for, with or without a session", () => {
    for (const path of HOSTILE) {
      for (const proxy of [panel, admin]) {
        for (const cookie of [undefined, `${PANEL_SESSION_COOKIES[0]}=x`, `${ADMIN_SESSION_COOKIES[0]}=x`]) {
          const r = proxy(req(path, cookie));
          const raw = r.headers.get("location");
          if (raw === null) continue;
          const url = new URL(raw);
          expect(url.origin, `${path} stays on the origin`).toBe("https://panel.localhost");
          expect(`${url.pathname}${url.search}`, `${path} is /<locale> and then a name`).toMatch(/^\/(fa|en)(?:\/(?![/\\])|$|\?)/);
        }
      }
    }
  });

  it("answers the proxy's plain 404 where next-intl decodes %25, and redirects an ordinary path as before", () => {
    for (const path of ["/%252F%252Fevil.example", "/FA/%252F%252Fevil.example", "/FA/%250D%250ASet-Cookie:x=1", "/FA/profiles%252F"]) {
      const r = panel(req(path));
      expect(r.status, path).toBe(404);
      expect(r.headers.get("location"), path).toBeNull();
      expect(r.headers.get("content-security-policy"), path).toContain("default-src 'none'");
    }
    expect(location(panel(req("/FA/profiles?x=1")))).toBe("/fa/profiles?x=1");
    expect(location(panel(req("/EN/invite")))).toBe("/en/invite");
    expect(location(panel(req("/%D9%BE")))).toBe("/fa/%D9%BE");
    expect(location(panel(req("/a%5Bb%5D")))).not.toBeNull();
    expect(location(panel(req("/")))).toBe("/fa");
    expect(location(panel(req("/profiles/")))).not.toBeNull();
  });

  it("redirectKind accepts only /<locale> and the asked path", () => {
    const ask = (path: string) => new NextRequest(`https://panel.localhost${path}`);
    expect(redirectKind("/fa/profiles", ask("/profiles"))).toBe("same");
    expect(redirectKind("/fa", ask("/"))).toBe("same");
    expect(redirectKind("/en/profiles", ask("/EN/profiles"))).toBe("same");
    expect(redirectKind("/fa/en/x", ask("/FA/en/x"))).toBe("same");
    expect(redirectKind("/fa/a[b]", ask("/a%5Bb%5D"))).toBe("respelled");
    for (const [loc, path] of [
      ["//evil.example", "/x"], ["/evil.example", "/x"], ["https://evil.example/fa/x", "/x"], ["/fa/%2F%2Fevil.example", "/%252F%252Fevil.example"],
      ["/de/x", "/x"], ["/fa//evil.example", "/x"], ["/fa/x?y=1", "/x"], ["/fa/x#h", "/x"], ["/fa/y", "/x"], ["/fa", "/x"],
    ] as const) {
      expect(redirectKind(loc, ask(path)), `${loc} for ${path}`).toBe("other");
    }
  });
});
