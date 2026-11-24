import {existsSync, readFileSync} from "node:fs";
import {resolve} from "node:path";

import type {APIRequestContext, APIResponse} from "@playwright/test";

import {expect, test} from "../testing/guard.ts";
import {rawGet, rawStalledPost} from "../testing/rawRequest.ts";
import {permissionsPolicy} from "./headers.ts";
import {expectedPolicy} from "./expectedCsp.ts";
import {hasLoginPage} from "./loginPage.ts";
import {checkCompiledMatcher, staticPaths} from "./matcher.ts";
import {readNextHeaders} from "./nextHeaders.ts";
import {INTERNAL_ROUTING_HEADERS} from "./nextRequests.ts";

// The body of `apps/*/e2e/headers.spec.ts` (spec 17.3, section 15), in mock mode against `next start`.
// The two apps share it, with their own page and cookie. What it proves is what the browser and Caddy
// rely on: the CSP is the exact policy of 15.2 with a nonce that is fresh per request and the one the
// rendered tags carry, the three other headers are on every answer of the proxy, and the matcher of 15.4
// neither skips a page nor runs on a file.
//
// The policy is written out in expectedCsp.ts, apart from `buildCsp`, so a change to csp.ts has to change that file too.

const NONCE_IN_CSP = /'nonce-([^']+)'/;
const SCRIPT_TAG = /<script\b[^>]*>/g;
const STYLE_TAG = /<style\b[^>]*>/g;
const NONCE_ATTR = /\snonce="([^"]*)"/;

type Options = {
  app: "panel" | "admin";
  /** `apps/<app>`, from the spec file's directory. */
  appDir: string;
};

const PAGES = {
  // A page that renders the root document with a session cookie: the shell stub answers 200 and its gate asks the API later.
  panel: {path: "/fa/profiles", cookie: "__Host-ctrlz_session=x", gated: "/fa/profiles", dotted: "/fa/profiles/x.y", browser: "/fa/nothing-here", linked: "/fa/nothing-here"},
  // The admin's login page is public, so it is the page that renders the root document with no session. It has no <Link>, so a Link prefetch needs
  // the admin's own 404 for a visitor with no session (NotFoundView, standalone), which has the one link back to the root: `linked` (merge of WP10).
  admin: {path: "/fa/login", cookie: undefined, gated: "/fa/users", dotted: "/fa/users/x.y", browser: "/fa/login", linked: "/fa/nothing-here"},
} as const;

/** The CSP of this server, as the test process expects it: only the panel may have the verify origin, and only from the same variable. */
function expectedConnect(app: Options["app"]): string[] {
  const origin = process.env.CTRLZ_VERIFY_ORIGIN;
  return app === "panel" && origin ? ["'self'", origin] : ["'self'"];
}

function expectedCsp(app: Options["app"], nonce: string): string {
  return expectedPolicy(nonce, expectedConnect(app));
}

/**
 * True when the run goes through Caddy: the base URL is https (E2E_BASE_URL=https://panel.localhost over the mock projects, ci-web.sh step 10d,
 * spec 15.5). Not E2E_MODE=stack: that mode builds one project that matches only *.stack.spec.ts (testing/config.ts), so this file is not
 * part of it at all, and a check on that variable would be a branch that never runs, while a skip reason that names it sends the next reader
 * to a run that shows no failure and no skip (gate-r13-1).
 */
function servedThroughCaddy(baseURL: string | undefined): boolean {
  return (baseURL ?? "").startsWith("https:");
}

export function declareHeadersSpec({app, appDir}: Options): void {
  const page = PAGES[app];
  const htmlBuilt = app === "panel" || hasLoginPage(appDir);
  const headers = (cookie?: string): Record<string, string> => (cookie ? {cookie} : {});

  test.describe(`headers of ${app}`, () => {
    test("the CSP on a page is exactly the policy of 15.2, and there is no other CSP header", async ({request}) => {
      // The policy does not depend on the body, so the admin, which has no page that renders the root document until WP10, is held to the
      // same text on the gate's own 307 of a protected path with no cookie (gate-r20-1). "Same policy on both apps" is a 15.2 rule.
      const url = htmlBuilt ? page.path : page.gated;
      const response = await request.get(url, {headers: htmlBuilt ? headers(page.cookie) : {}, maxRedirects: 0});
      if (htmlBuilt) {
        expect(response.status()).toBe(200);
        expect(response.headers()["content-type"]).toContain("text/html");
      } else {
        expect(response.status(), "the gated path with no cookie is the proxy's redirect").toBe(307);
      }
      const csp = response.headers()["content-security-policy"] ?? "";
      const nonce = NONCE_IN_CSP.exec(csp)?.[1] ?? "";
      expect(nonce, "a nonce in the policy").toMatch(/^[A-Za-z0-9+/]{22}==$/);
      expect(csp).toBe(expectedCsp(app, nonce));
      expect(response.headers()["content-security-policy-report-only"]).toBeUndefined();
    });

    test("the gate's redirect carries the exact policy of 15.2 too, on both apps (gate-r20-1)", async ({request}) => {
      const response = await request.get(page.gated, {maxRedirects: 0});
      expect(response.status()).toBe(307);
      const csp = response.headers()["content-security-policy"] ?? "";
      const nonce = NONCE_IN_CSP.exec(csp)?.[1] ?? "";
      expect(nonce, "a nonce in the policy").toMatch(/^[A-Za-z0-9+/]{22}==$/);
      expect(csp).toBe(expectedCsp(app, nonce));
    });

    test("connect-src has the verify origin only on the panel, and only when the variable is set (15.3)", async ({request}) => {
      const response = await request.get(page.gated, {headers: headers(page.cookie), maxRedirects: 0});
      const connect = /connect-src ([^;]*)/.exec(response.headers()["content-security-policy"] ?? "")?.[1];
      expect(connect?.split(" ")).toEqual(expectedConnect(app));
      if (app === "admin") expect(connect).toBe("'self'");
    });

    test("the nonce is new for every request, and every script and style tag of the page carries it", async ({request}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      const seen = new Set<string>();
      for (let i = 0; i < 5; i++) {
        const response = await request.get(page.path, {headers: headers(page.cookie), maxRedirects: 0});
        const nonce = NONCE_IN_CSP.exec(response.headers()["content-security-policy"] ?? "")![1]!;
        expect(seen.has(nonce), "a nonce was used twice").toBe(false);
        seen.add(nonce);

        const html = await response.text();
        // `<noscript>` is not parsed by a browser that runs scripts, so a tag in it can neither run nor be refused by the CSP. input-otp
        // writes one `<style>` there (its no-JS fallback for the code boxes) with no nonce, and the admin login has a code field on its
        // first paint (the panel's code fields come on later steps, so the panel page never showed it, wp10). A visitor without scripts
        // cannot use either app, so what the fallback would style is not a page anyone sees.
        const live = html.replace(/<noscript\b[\s\S]*?<\/noscript>/g, "");
        const scripts = live.match(SCRIPT_TAG) ?? [];
        expect(scripts.length, "the page has script tags").toBeGreaterThan(0);
        for (const tag of scripts) expect(NONCE_ATTR.exec(tag)?.[1], `script tag without the nonce: ${tag.slice(0, 80)}`).toBe(nonce);
        for (const tag of live.match(STYLE_TAG) ?? []) expect(NONCE_ATTR.exec(tag)?.[1], `style tag without the nonce: ${tag.slice(0, 80)}`).toBe(nonce);
        // React Aria reads its own nonce from here (spec 15.2).
        expect(html).toContain(`<meta name="csp-nonce" nonce="${nonce}"`);
        expect(html, "the nonce is not in a content attribute, which a selector could read (gate-r30-1)").not.toMatch(/<meta name="csp-nonce"[^>]*\bcontent=/);
      }
      expect(seen.size).toBe(5);
    });

    test("in a browser the script tags carry the nonce of the response, and the page raises no violation", async ({page: tab, guard}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      // The page opened here is the panel's 404, which needs no session and no API. Chrome may log the failed navigation.
      if (app === "panel") guard.allowConsole(/status of 404/);
      const response = await tab.goto(page.browser);
      const nonce = NONCE_IN_CSP.exec(response!.headers()["content-security-policy"] ?? "")![1]!;
      await tab.waitForLoadState("networkidle");
      const scripts = await tab.evaluate(() => [...document.scripts].map((s) => ({nonce: s.nonce, inline: s.src === ""})));
      // The scripts that came in the HTML carry the nonce. Next's chunk loader later adds `<script src>` tags without one,
      // which `'self'` lets through because they come from /_next/static. Without 'strict-dynamic' a script from another origin would be refused and reported, and the guard would fail the test (wp5-r18-3).
      const withNonce = scripts.filter((s) => s.nonce !== "");
      expect(withNonce.length).toBeGreaterThan(0);
      expect(new Set(withNonce.map((s) => s.nonce))).toEqual(new Set([nonce]));
      expect(scripts.filter((s) => s.inline && s.nonce === ""), "an inline script without the nonce would have been blocked").toEqual([]);
      // What the browser does with the headers, not only what they say (gate-r2-18): the policy of the document itself.
      const allowed = await tab.evaluate(() => {
        // Chrome names it `featurePolicy` (the older name of the same object), `permissionsPolicy` where it is shipped.
        const doc = document as unknown as Record<"permissionsPolicy" | "featurePolicy", {allowsFeature(name: string): boolean} | undefined>;
        const policy = (doc.permissionsPolicy ?? doc.featurePolicy)!;
        return Object.fromEntries(["camera", "microphone", "geolocation", "publickey-credentials-get", "publickey-credentials-create", "clipboard-write"].map((f) => [f, policy.allowsFeature(f)]));
      });
      expect(allowed).toEqual({
        camera: false,
        microphone: false,
        geolocation: false,
        "publickey-credentials-get": app === "panel",
        "publickey-credentials-create": app === "panel",
        "clipboard-write": true,
      });
      // Once the client has rendered the document that the 404 shell leaves empty (gate-r2-1), it has the language, the direction and the nonce for React Aria.
      expect(await tab.evaluate(() => [document.documentElement.lang, document.documentElement.dir])).toEqual(["fa", "rtl"]);
      // gate-r30-1: Chrome hides the nonce attribute of the tag like that of every script, so CSS and the serialised DOM cannot read it; only the property holds it.
      expect(await tab.evaluate(() => {
        const meta = document.querySelector('meta[name="csp-nonce"]') as HTMLMetaElement;
        const first = meta.nonce.slice(0, 1);
        return {
          attribute: meta.getAttribute("nonce"),
          property: meta.nonce,
          hasContent: meta.hasAttribute("content"),
          selectable: document.querySelectorAll(`meta[name="csp-nonce"][nonce^="${first}"]`).length,
          // The tag's own markup. (The flight payload in an inline script also carries the prop; no selector reaches script text.)
          inMarkup: meta.outerHTML.includes(meta.nonce),
        };
      })).toEqual({attribute: "", property: nonce, hasContent: false, selectable: 0, inMarkup: false});
      // The admin's own page was visited above; its 404 for an unknown path must raise no violation either (gate-r3-2). The panel's
      // page above is that 404 already.
      if (app === "admin") {
        guard.allowConsole(/status of 404/);
        await tab.goto("/fa/nothing-here");
        await tab.waitForLoadState("networkidle");
        const bare = await tab.evaluate(() => [...document.scripts].filter((s) => s.src === "" && s.nonce === "").length);
        expect(bare, "an inline script without the nonce on the admin's 404 would have been blocked").toBe(0);
      }
      // The guard fails the test at the end on any violation, console error or external request.
    });

    test("a client cannot choose the nonce or the policy", async ({request}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      const response = await request.get(page.path, {
        headers: {...headers(page.cookie), "x-nonce": "forged", "content-security-policy": "default-src *"},
        maxRedirects: 0,
      });
      const csp = response.headers()["content-security-policy"] ?? "";
      expect(csp).not.toContain("forged");
      expect(csp).not.toContain("default-src *");
      const nonce = NONCE_IN_CSP.exec(csp)![1]!;
      const html = await response.text();
      expect(html).not.toContain("forged");
      expect(html).toContain(`nonce="${nonce}"`);
    });

    // The header that made Next skip middleware (CVE-2025-29927) is a client's header like any other. Every guarantee of 15 (the CSP, the three
    // headers, a nonce the server chose, the gate) rests on the proxy running for every request, so the known spellings of the name of the file,
    // repeated until the old recursion limit, are sent to a gated path and to a page, and the answers must be the usual ones (gate-r5-4). It passes on
    // Next 16.4.5 by design: it is here to fail on the day a bump honours the header for proxy.ts.
    test("x-middleware-subrequest does not make Next skip the proxy", async ({request}) => {
      const names = ["middleware", "src/middleware", "proxy", "src/proxy", "pages/_middleware", "pages/_proxy", "src/pages/_middleware"];
      const forged = [...names.map((name) => Array(5).fill(name).join(":")), names.join(":")];
      for (const value of forged) {
        const attack = {"x-middleware-subrequest": value, "x-nonce": "forged", "content-security-policy": "default-src *"};
        // No cookie on a gated path: the gate's redirect, with the policy and a nonce the server chose.
        const gated = await request.get(page.gated, {headers: attack, maxRedirects: 0});
        expect(gated.status(), value).toBe(307);
        expect(gated.headers()["location"], value).toMatch(/\/login\?next=/);
        const csp = gated.headers()["content-security-policy"] ?? "";
        const nonce = NONCE_IN_CSP.exec(csp)?.[1] ?? "";
        expect(nonce, value).toMatch(/^[A-Za-z0-9+/]{22}==$/);
        expect(csp, value).toBe(expectedCsp(app, nonce));
        expect(Object.keys(gated.headers()).filter((n) => n.startsWith("x-middleware-") || n === "x-nonce"), value).toEqual([]);
        // A page: the same policy, and the HTML carries the nonce that the server chose and not the forged one.
        if (!htmlBuilt) continue;
        const served = await request.get(page.path, {headers: {...attack, ...headers(page.cookie)}, maxRedirects: 0});
        expect(served.status(), value).toBe(200);
        const pageCsp = served.headers()["content-security-policy"] ?? "";
        const pageNonce = NONCE_IN_CSP.exec(pageCsp)?.[1] ?? "";
        expect(pageCsp, value).toBe(expectedCsp(app, pageNonce));
        const html = await served.text();
        expect(html, value).toContain(`nonce="${pageNonce}"`);
        expect(html, value).not.toContain("forged");
      }
    });

    // Spellings that the URL parser or next-intl read as another page (wp5-r15): a control character or a space at the
    // end, the start or the middle of a segment or of the locale, an escaped dot, an escaped letter, an escaped percent sign.
    const odd = [
      `${page.gated}%00`, `${page.gated}%09?x=1`, `${page.gated}%0a`, `${page.gated}%0d`, `${page.gated}%20`, `${page.gated}%7f`,
      `${page.gated.replace("/fa/", "/fa/%09")}`, `${page.gated.slice(0, -4)}%0a${page.gated.slice(-4)}`, `${page.gated}%09/x`,
      `${page.gated}%2e`, `${page.gated}%252e`, page.gated.replace(/.$/, "%73"), `${page.gated}/50%25`,
      "/f%09a/profiles", "/%09fa/profiles", "/en%0a/profiles", "/fa/endpoints%20", "/fa/analytics%0d",
    ];

    // Every name that is not path-safe, written as encodeURIComponent writes it (wp5-r19-1): the served kind must carry no
    // x-middleware-* header either, not only the brackets and the bar. The unit test checks the same list on the proxy.
    const notPathSafe = ["a[b]", "a|b", "a^b", "a{b}", "a`b", 'a"b', "a<b>", "a\\b", "a:b", "a@b", "a$b", "a&b", "a+b", "a,b", "a;b", "a=b", "a?b", "a/b", "a#b", "پ", "a[پ]b|c"]
      .map((name) => `${page.gated}/${encodeURIComponent(name)}`);

    // An escape that does not decode (wp5-r16): Next would answer a bare 500 without our headers, so the proxy refuses it.
    const broken = ["/fa/%zz", `${page.gated}%zz`, `${page.gated}/%E0%A4%A`, "/fa/%C0", "/x%C0", `${page.gated}%`, "/_next/static/%zz", "/_next/static/chunks/%zz.js"];

    test("the headers that carry the nonce to the render are not sent to the client", async ({request}) => {
      // "/_next/static/chunks/nothing-here.js" and a real chunk (below) are the one answer built with NextResponse.next(), so they are listed
      // on their own: a Next bump that stopped stripping the override headers there would leak the nonce on every chunk request (gate-r1-10).
      for (const path of ["/fa", page.gated, "/fa/profiles/x.y", "/_next/static/chunks/nothing-here.js", `${page.gated}/a%5Bb%5D`, `${page.gated}/a%7Cb?x=1`, ...notPathSafe, ...odd, ...broken]) {
        for (const cookie of [undefined, page.cookie]) {
          const response = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
          const names = Object.keys(response.headers());
          expect(names.filter((n) => n.startsWith("x-middleware-") || n === "x-nonce"), path).toEqual([]);
        }
      }
    });

    test("a path with a control character or a space in its name never serves a page, with a cookie or without one", async ({request}) => {
      for (const path of odd.filter((p) => /%(?:[01][0-9a-f]|20|7f)/i.test(p))) {
        for (const cookie of [undefined, page.cookie]) {
          const response = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
          const label = `${path} ${cookie ?? "without a cookie"}`;
          // The rule runs before the gate and before next-intl, so it is the proxy's own plain 404 whatever the cookie:
          // Next's HTML 404 would mean that the rule no longer caught the path and the page merely does not exist.
          expect(response.status(), label).toBe(404);
          expect(response.headers()["content-type"], label).toContain("text/plain");
          expect(await response.text(), label).toBe("Not Found");
          expect(response.headers()["content-security-policy"], label).toContain("default-src 'none'");
          // A 404 is cacheable unless told otherwise, and this one is for a path that never names a page (gate-r2-6).
          expect(response.headers()["cache-control"], label).toBe("no-store");
        }
      }
      // The one that spells the protected page once the URL parser drops the line feed: `/fa/prof%0ailes`.
      const hidden = `${page.gated.slice(0, -4)}%0a${page.gated.slice(-4)}`;
      expect(decodeURIComponent(hidden).replaceAll(String.fromCharCode(10), ""), "the case really spells the page").toBe(page.gated);
    });

    // What next-intl re-serialises (wp5-r18-1): a link built with encodeURIComponent from a name with a bracket or a bar
    // must reach the app, and what a link never writes must not. The unit test pins the whole set.
    const session = app === "panel" ? "__Host-ctrlz_session=x" : "__Host-ctrlz_admin=x";
    test("an escape that encodeURIComponent writes is served, and one that it does not is the proxy's 404, with no rewrite header", async ({request}) => {
      for (const [escaped, served] of [["a%5Bb%5D", true], ["a%7Cb", true], ["%D9%BE", true], ["a%3Fb", true], ["a%28b", false], ["%70x", false], ["x%2e", false], ["a%5bb", false]] as const) {
        const path = `${page.gated}/${escaped}`;
        const response = await request.get(path, {headers: headers(session), maxRedirects: 0});
        // The page of that name does not exist yet, so a served path is Next's HTML 404 and a refused one is the proxy's plain one.
        expect(response.headers()["content-type"]?.includes("text/plain") ?? false, path).toBe(!served);
        expect(Object.keys(response.headers()).filter((n) => n.startsWith("x-middleware-")), path).toEqual([]);
        expect(response.headers()["content-security-policy"], path).toContain("default-src 'none'");
      }
    });

    test("a path whose percent escape does not decode is a 404 with the CSP and the three headers, not Next's bare 500", async ({request, baseURL}) => {
      for (const path of broken) {
        for (const cookie of [undefined, page.cookie]) {
          const response = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
          const label = `${path} ${cookie ?? "without a cookie"}`;
          if (servedThroughCaddy(baseURL) && /%(?![0-9A-Fa-f]{2})/.test(path)) {
            // Measured on caddy:2.10 (merge item A16): Go's HTTP parser refuses an escape that is not two hex digits while it reads the request
            // line (`%C0` is two hex digits, so Go passes it on and the proxy answers it as before), so the request never reaches a Caddy handler or
            // Next. The answer is Go's plain `400 Bad Request`, which no Caddyfile line can
            // give a header (the same class as a method that the parser cannot read, gate-r19-2), and Next's bare 500 cannot happen at all.
            expect(response.status(), label).toBe(400);
            expect(response.headers()["content-type"] ?? "", label).toContain("text/plain");
            expect(Object.keys(response.headers()).filter((n) => n.startsWith("x-middleware-")), label).toEqual([]);
            continue;
          }
          expect(response.status(), label).toBe(404);
          expect(response.headers()["content-security-policy"], label).toContain("default-src 'none'");
          expect(response.headers()["cross-origin-opener-policy"], label).toBe("same-origin");
          expect(response.headers()["cross-origin-resource-policy"], label).toBeTruthy();
          expect(response.headers()["permissions-policy"], label).toBeTruthy();
          expect(response.headers()["cache-control"], label).toBe("no-store");
        }
      }
    });

    // gate-r2-6: "on every answer" holds for every method, not only for GET. A script can send any of them, and an answer
    // that the proxy builds (the gate's 307, its plain 404) must carry the CSP and the three headers whatever was asked.
    test("the answers that the proxy builds have the CSP and the three headers for every method, and no x-middleware header", async ({request, baseURL}) => {
      const caddy = servedThroughCaddy(baseURL);
      for (const method of ["HEAD", "POST", "OPTIONS", "PUT", "DELETE"]) {
        for (const [path, status, cookie] of [[page.gated, 307, undefined], [odd[0]!, 404, undefined], [odd[0]!, 404, page.cookie], [broken[0]!, 404, undefined]] as const) {
          // Through Caddy two things change before the proxy is asked (merge items A5 and A16, measured on caddy:2.10). A method outside GET, HEAD and
          // POST is Caddy's own 405, which has the default CSP and the three headers of the site block, and an escape that does not decode is Go's plain
          // 400 that never reaches a handler (a HEAD gets a body there, which the request context cannot parse, so that one is left out).
          if (caddy && path === broken[0]) {
            if (method === "HEAD") continue;
            expect((await request.fetch(path, {method, headers: headers(cookie), maxRedirects: 0})).status(), `${method} ${path}`).toBe(400);
            continue;
          }
          const response = await request.fetch(path, {method, headers: headers(cookie), maxRedirects: 0});
          const label = `${method} ${path} ${cookie ?? "without a cookie"}`;
          const h = response.headers();
          expect(response.status(), label).toBe(caddy && !["HEAD", "POST"].includes(method) ? 405 : status);
          expect(h["content-security-policy"], label).toContain("default-src 'none'");
          expect(h["cross-origin-opener-policy"], label).toBe("same-origin");
          expect(h["cross-origin-resource-policy"], label).toBe("same-origin");
          expect(h["permissions-policy"], label).toBe(permissionsPolicy(app));
          expect(Object.keys(h).filter((n) => n.startsWith("x-middleware-") || n === "x-nonce"), label).toEqual([]);
        }
      }
    });

    test("a dotted path runs the proxy: a visitor without a session is redirected, and the answer has the CSP", async ({request}) => {
      const response = await request.get(page.dotted, {maxRedirects: 0});
      expect(response.status()).toBe(307);
      expect(response.headers()["location"]).toContain("/fa/login");
      expect(response.headers()["content-security-policy"]).toContain("default-src 'none'");
    });

    test("a dotted path with a session cookie is a page that does not exist, and its 404 has the CSP too", async ({request}) => {
      const cookie = app === "panel" ? "__Host-ctrlz_session=x" : "__Host-ctrlz_admin=x";
      const response = await request.get(page.dotted, {headers: {cookie}, maxRedirects: 0});
      expect(response.status()).toBe(404);
      expect(response.headers()["content-security-policy"]).toContain("default-src 'none'");
    });

    test("a prefetch and a Server Component request go through the same proxy", async ({request}) => {
      for (const extra of [{"next-router-prefetch": "1", rsc: "1"}, {rsc: "1"}] as Record<string, string>[]) {
        const response = await request.get(page.gated, {headers: {...headers(page.cookie), ...extra}, maxRedirects: 0});
        expect(response.headers()["content-security-policy"], JSON.stringify(extra)).toContain("default-src 'none'");
      }
    });

    for (const [label, path, cookie] of [
      ["a page", page.path, page.cookie],
      ["the locale root", "/fa", undefined],
      ["a redirect to the default language", "/", undefined],
      ["a redirect to the login page", page.gated, undefined],
      ["an unknown language", "/de", undefined],
    ] as const) {
      test(`COOP, CORP and Permissions-Policy are on ${label}`, async ({request}) => {
        test.skip(path === page.path && !htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
        const response = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
        const h = response.headers();
        expect(h["cross-origin-opener-policy"]).toBe("same-origin");
        expect(h["cross-origin-resource-policy"]).toBe("same-origin");
        // Written out here and not read from headers.ts, so a change there has to change both (gate-r2-18).
        expect(h["permissions-policy"]).toBe(
          app === "panel"
            ? "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self), clipboard-write=(self)"
            : "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(), publickey-credentials-create=(), clipboard-write=(self)",
        );
        expect(h["permissions-policy"]).toBe(permissionsPolicy(app));
        expect(h["content-security-policy"]).toContain("frame-ancestors 'none'");
        expect(h["x-powered-by"], "poweredByHeader is off").toBeUndefined();
      });
    }

    test("a page is not cached by a shared cache, since its nonce is single use", async ({request}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      const response = await request.get(page.path, {headers: headers(page.cookie), maxRedirects: 0});
      const cache = response.headers()["cache-control"] ?? "";
      expect(cache, "Cache-Control of an HTML page").toMatch(/no-store|private/);
      expect(cache).not.toMatch(/s-maxage|public/);
    });

    test("every file in public/ and every root metadata file answers 200 with no redirect (open question 23)", async ({request}) => {
      const paths = staticPaths(appDir);
      expect(paths.length, "the app has at least its logo").toBeGreaterThan(0);
      for (const path of paths) {
        const response = await request.get(path, {maxRedirects: 0});
        expect(response.status(), path).toBe(200);
        expect(response.headers()["location"], path).toBeUndefined();
        expect(response.headers()["content-type"] ?? "", path).not.toContain("text/html");
        const disk = path.startsWith("/icon") || path.startsWith("/favicon") ? undefined : resolve(appDir, `public${path}`);
        if (disk && existsSync(disk)) expect((await response.body()).equals(readFileSync(disk)), `${path} is served byte for byte`).toBe(true);
      }
    });

    // gate-r6-2. The unit checks of matcher.ts run on a model of Next's compile (`^source$`). This one reads the regular expression that the
    // build wrote into .next/server/functions-config-manifest.json, the one `next start` really runs, and holds it to the same paths: every
    // file skipped, every page, folder-shaped name and Next suffix run. It also needs the build to be made from the literal in proxy.ts,
    // so a literal changed without a build, or a Next that compiles it differently, fails here and not in production.
    test("the matcher that Next compiled from the literal skips the files and only the files (gate-r6-2)", () => {
      expect(checkCompiledMatcher(appDir)).toEqual([]);
    });

    test("a name that only looks like a file still goes through the language rules", async ({request}) => {
      for (const path of ["/logoXpng", "/logo.pngx"]) {
        const response = await request.get(path, {maxRedirects: 0});
        expect(response.status(), path).toBe(307);
        expect(response.headers()["location"], path).toContain("/fa/");
        expect(response.headers()["content-security-policy"], path).toContain("default-src 'none'");
      }
    });

    // wp5-r1-9: the matcher once excluded the folders api/, _next/ and logos/. A path under one that is not a file
    // went to the App Router without the proxy: HTML with no CSP and with the nonce that the client's own x-nonce
    // header named. Every hop of these paths has the proxy's headers now, whatever the client sends.
    test("a path under a folder that is no longer excluded has the full CSP on every hop, and ignores a forged nonce", async ({request, baseURL}) => {
      for (const start of ["/logos/nothing", "/logos/nothing.svg", "/_next/nothing", "/_next/image", "/_next/data/x.json", "/api/v1/me", "/api/x", "/favicon.ico", "/_next/static/chunks/nothing-here.js"]) {
        // Through Caddy /api/* is the API handle and never reaches Next. Go sets no policy, so those answers have Caddy's default CSP; the Caddy case
        // of gate-r2-8 asks for them and for the other three headers.
        if (servedThroughCaddy(baseURL) && start.startsWith("/api/")) continue;
        let path = start;
        for (let hop = 0; hop < 4; hop++) {
          const response = await request.get(path, {headers: {"x-nonce": "attackerchosen", "content-security-policy": "default-src *", ...headers(page.cookie)}, maxRedirects: 0});
          const label = `${start} hop ${hop} (${path}) answered ${response.status()}`;
          const csp = response.headers()["content-security-policy"] ?? "";
          expect(csp, label).toBe(expectedCsp(app, NONCE_IN_CSP.exec(csp)?.[1] ?? "x"));
          expect(csp, label).not.toContain("attackerchosen");
          expect(response.headers()["cross-origin-opener-policy"], label).toBe("same-origin");
          expect(response.headers()["cross-origin-resource-policy"], label).toBe("same-origin");
          expect(response.headers()["permissions-policy"], label).toBeDefined();
          if (response.headers()["content-type"]?.includes("text/html")) expect(await response.text(), label).not.toContain("attackerchosen");
          const location = response.headers()["location"];
          if (response.status() < 300 || response.status() >= 400 || location === undefined) break;
          path = new URL(location, response.url()).pathname;
        }
      }
    });

    // The proxy lets `_next/static/` through without the language rules, and with the headers (createProxy). A name
    // there that is not a file is Next's own 404, which echoed the path and query into its payload when the proxy did not
    // run on it, and still has to carry the CSP.
    test("a name under _next/static that is not a file has the CSP and the proxy's headers, and no forged nonce", async ({request}) => {
      const response = await request.get("/_next/static/chunks/nothing-here.js?x=reflected", {headers: {"x-nonce": "attackerchosen", "content-security-policy": "default-src *"}, maxRedirects: 0});
      expect(response.status()).toBe(404);
      const csp = response.headers()["content-security-policy"] ?? "";
      expect(csp).toBe(expectedCsp(app, NONCE_IN_CSP.exec(csp)?.[1] ?? "x"));
      expect(csp).not.toContain("attackerchosen");
      expect(response.headers()["cross-origin-opener-policy"]).toBe("same-origin");
      expect(response.headers()["location"], "no redirect to /fa/_next/...").toBeUndefined();
      expect(await response.text()).not.toContain("attackerchosen");
    });

    // gate-r9-2. A browser that opens a name under /_next/static/ (a stale link, a typed address) used to get Next's built-in English 404: its inline
    // <style> has no nonce and the CSP refused it, and the page had no lang, dir or csp-nonce meta. A navigation (Sec-Fetch-Dest document, iframe, frame,
    // embed, object) now gets the proxy's plain 404 with the headers; chunk, style and font loads keep the pass-through. Real Chrome below, then
    // the header on its own, which is also what the request context can say. (A `%2e%2e` hop is not listed: Chrome resolves it to /_next/x before it asks, which the
    // locale redirect takes to the ordinary /fa/_next/x 404.)
    test("a browser that opens a name under _next/static gets the proxy's plain 404, and no CSP violation (gate-r9-2)", async ({page: tab, guard, baseURL}) => {
      guard.allowConsole(/status of 404/);
      for (const path of ["/_next/static/chunks/nothing-here.js", "/_next/static/x", "/_next/static/a%2fb", "/_next/static/a%5Cb"]) {
        const response = await tab.goto(path);
        expect(response!.status(), path).toBe(404);
        expect(response!.headers()["content-type"], path).not.toMatch(/html/);
        const csp = response!.headers()["content-security-policy"] ?? "";
        // Behind Caddy the escaped spellings are its own 404 (merge-r2-6), which carries the default policy of the site and no nonce.
        const byCaddy = servedThroughCaddy(baseURL) && /%2f|%5c/i.test(path);
        expect(csp, path).toBe(byCaddy ? "default-src 'none'; base-uri 'none'; frame-ancestors 'none'" : expectedCsp(app, NONCE_IN_CSP.exec(csp)?.[1] ?? "x"));
        expect(await tab.evaluate(() => document.querySelectorAll("style, script").length), `no markup of Next's built-in page at ${path}`).toBe(0);
        expect(guard.consume("csp"), `a CSP violation at ${path}`).toEqual([]);
      }
    });

    test("only a navigation under _next/static is answered by the proxy, an asset load passes (gate-r9-2)", async ({request}) => {
      for (const dest of ["document", "iframe", "frame", "embed", "object", "DOCUMENT"]) {
        const response = await request.get("/_next/static/chunks/nothing-here.js", {headers: {"sec-fetch-dest": dest}, maxRedirects: 0});
        expect(response.status(), dest).toBe(404);
        expect(response.headers()["content-type"], dest).not.toMatch(/html/);
        expect(response.headers()["content-security-policy"], dest).toBe(expectedCsp(app, NONCE_IN_CSP.exec(response.headers()["content-security-policy"] ?? "")?.[1] ?? "x"));
      }
      const script = await request.get("/_next/static/chunks/nothing-here.js", {headers: {"sec-fetch-dest": "script"}, maxRedirects: 0});
      expect(script.status()).toBe(404);
      expect(script.headers()["content-security-policy"]).toBeTruthy();
    });

    // gate-r20-2. Safari on macOS and iOS before 16.4 sends no Fetch Metadata. Its navigation names text/html in Accept, its script and font loads ask for
    // the wildcard alone; the proxy decides on that when Sec-Fetch-Dest is missing.
    test("a navigation under _next/static from a browser with no Sec-Fetch-Dest is the proxy's plain 404, an asset load passes (gate-r20-2)", async ({request}) => {
      const path = "/_next/static/chunks/nothing-here.js";
      for (const accept of ["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html"]) {
        const response = await request.get(path, {headers: {accept}, maxRedirects: 0});
        expect(response.status(), accept).toBe(404);
        expect(response.headers()["content-type"], accept).toContain("text/plain");
        expect(response.headers()["cache-control"], accept).toBe("no-store");
        expect(response.headers()["content-security-policy"], accept).toBe(expectedCsp(app, NONCE_IN_CSP.exec(response.headers()["content-security-policy"] ?? "")?.[1] ?? "x"));
        expect(await response.text(), accept).not.toContain("<");
      }
      for (const accept of ["*/*", "text/css,*/*;q=0.1", "image/*,*/*;q=0.8"]) {
        const response = await request.get(path, {headers: {accept}, maxRedirects: 0});
        // The file does not exist, so Next answers its own 404 with the CSP: the point is that the proxy's plain text answer was not given.
        expect(response.status(), accept).toBe(404);
        expect(response.headers()["content-security-policy"], accept).toBeTruthy();
        expect(response.headers()["cache-control"] ?? "", accept).not.toBe("no-store");
      }
    });

    test("a real file under _next/static is served as itself, with the headers and with no redirect", async ({request}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      const html = await (await request.get(page.path, {headers: headers(page.cookie), maxRedirects: 0})).text();
      const src = /<script src="(\/_next\/static\/chunks\/[^"]+\.js)"/.exec(html)?.[1];
      expect(src, "the page loads at least one chunk").toBeDefined();
      const response = await request.get(src!, {maxRedirects: 0});
      expect(response.status()).toBe(200);
      expect(response.headers()["content-type"]).toContain("javascript");
      expect(response.headers()["location"]).toBeUndefined();
      expect(response.headers()["cache-control"] ?? "").toContain("immutable");
      expect(response.headers()["content-security-policy"] ?? "").toContain("default-src 'none'");
      for (const method of ["get", "head"] as const) {
        const again = await request[method](src!, {maxRedirects: 0});
        expect(Object.keys(again.headers()).filter((n) => n.startsWith("x-middleware-") || n === "x-nonce"), `${method} ${src}`).toEqual([]);
      }
      // No asset is fetched by range, so the proxy drops the header (gate-r16-5): a satisfiable one gets the whole file, a 200, like any other.
      const ranged = await request.get(src!, {headers: {range: "bytes=0-9"}, maxRedirects: 0});
      expect(ranged.status()).toBe(200);
      expect(Object.keys(ranged.headers()).filter((n) => n.startsWith("x-middleware-") || n === "x-nonce")).toEqual([]);
      // gate-r18-1: Next's static server answers any other method with a 405 that it then turns into a bare 500 (measured on next start), so one POST to a
      // public chunk would raise the 5xx rate at will. The proxy answers its own 405 with the full header set. The same holds with and without a cookie.
      for (const method of ["post", "put", "patch", "delete", "fetch"] as const) {
        for (const cookie of [undefined, page.cookie]) {
          const response = method === "fetch"
            ? await request.fetch(src!, {method: "OPTIONS", headers: headers(cookie), maxRedirects: 0})
            : await request[method](src!, {headers: headers(cookie), maxRedirects: 0});
          const label = `${method === "fetch" ? "OPTIONS" : method.toUpperCase()} ${src} ${cookie ? "with" : "without"} a cookie`;
          expect(response.status(), label).toBe(405);
          expect(response.headers()["allow"], label).toBe("GET, HEAD");
          expect(response.headers()["content-type"] ?? "", label).toContain("text/plain");
          expect(response.headers()["content-security-policy"] ?? "", label).toContain("default-src 'none'");
          expect(response.headers()["cross-origin-opener-policy"], label).toBe("same-origin");
          expect(response.headers()["cross-origin-resource-policy"], label).toBe("same-origin");
          expect(response.headers()["permissions-policy"], label).toBeTruthy();
          expect(Object.keys(response.headers()).filter((n) => n.startsWith("x-middleware-") || n === "x-nonce"), label).toEqual([]);
        }
      }
    });

    // gate-r16-5. Next turns the 416 that its static server raises for a Range it cannot satisfy into a 500, so an outside client with no session
    // could raise the web tier's error rate with one header. The class is every spelling of the header (and If-Range with it), on a real chunk,
    // on a missing one and, through Caddy, on the files of public/ that skip this proxy.
    test("a Range or a failed precondition header never makes a file answer 5xx (gate-r16-5)", async ({request, baseURL}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      const html = await (await request.get(page.path, {headers: headers(page.cookie), maxRedirects: 0})).text();
      const src = /<script src="(\/_next\/static\/chunks\/[^"]+\.js)"/.exec(html)?.[1];
      expect(src, "the page loads at least one chunk").toBeDefined();
      const size = (await (await request.get(src!, {maxRedirects: 0})).body()).length;
      const ranges = ["bytes=x", "bytes=5-2", "bytes=-0", "bytes=999999999-", `bytes=${size}-`, "bytes=0-1,5-9", "items=0-1", "bytes=", "bytes=0-9"];
      const targets = [src!, "/_next/static/chunks/nothing-here.js"];
      // /logo.png is a file of public/: the matcher skips it, so only the edge can drop the header there.
      if (servedThroughCaddy(baseURL)) targets.push("/logo.png");
      for (const target of targets) {
        for (const range of ranges) {
          for (const extra of [{}, {"if-range": "\"x\""}] as Record<string, string>[]) {
            for (const method of ["get", "head"] as const) {
              const response = await request[method](target, {headers: {range, ...extra}, maxRedirects: 0});
              expect(response.status(), `${method} ${target} Range: ${range} ${JSON.stringify(extra)}`).toBeLessThan(500);
            }
          }
        }
        // The same class, one header each: a precondition that fails is a 412 in the static server, and Next makes that a 500 too.
        for (const [name, value] of [["if-match", "\"abc\""], ["if-unmodified-since", "Wed, 21 Oct 1990 07:28:00 GMT"]] as const) {
          for (const method of ["get", "head"] as const) {
            const response = await request[method](target, {headers: {[name]: value}, maxRedirects: 0});
            expect(response.status(), `${method} ${target} ${name}: ${value}`).toBeLessThan(500);
          }
        }
      }
    });

    // gate-r2-1. Next 16.4.5 answers a notFound() that a matched route throws (our catch-all `[...rest]`, which gives the
    // locale's not-found page) with its own error shell: `<html id="__next_error__">`, an empty hidden div, the bootstrap scripts
    // and the flight data, and the page is rendered by client recovery (app-render.js, errorRecovery). So the first response of a
    // 404 has no lang, dir, theme class, ThemeScript or csp-nonce meta; spec 5.2 and 8.7 accept that for the 404 alone. What must
    // hold anyway is pinned here: the status, the exact CSP, a nonce on every script, style and preloaded script, noindex, no
    // cache, and no markup from the path. If a later Next renders the document on the server, the shape that is accepted
    // is the one of 5.2 (lang, dir and the meta), and the test says so.
    test("the server's 404 for an unknown path is either Next's error shell or the full document, and both are safe (gate-r2-1)", async ({request}) => {
      // The admin is not excused for good (gate-r3-2): once WP10 gives it a login page this case runs against `/fa/nothing-here` and fails
      // until WP10 also supplies `[locale]/[...rest]/page.tsx`, because the prerendered `_not-found` that serves an unknown path without it
      // has no nonce on its inline scripts (15.5).
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      const hostile = "/fa/%3C%2Fscript%3E%3Cimg%2Fsrc%3Dx%3E";
      for (const [path, cookie] of [["/fa/nothing-here", undefined], ["/en/nothing-here", undefined], ["/fa/nothing-here", page.cookie], [hostile, undefined], [hostile, page.cookie]] as const) {
        const label = `${path} ${cookie ?? "without a cookie"}`;
        const response = await request.get(path, {headers: {cookie: [cookie, "ctrlz_theme=dark"].filter(Boolean).join("; ")}, maxRedirects: 0});
        expect(response.status(), label).toBe(404);
        expect(response.headers()["content-type"], label).toContain("text/html");
        expect(response.headers()["cache-control"] ?? "", label).toMatch(/no-store|private/);
        const csp = response.headers()["content-security-policy"] ?? "";
        const nonce = NONCE_IN_CSP.exec(csp)?.[1] ?? "";
        expect(csp, label).toBe(expectedCsp(app, nonce));
        const html = await response.text();
        for (const tag of html.match(SCRIPT_TAG) ?? []) expect(NONCE_ATTR.exec(tag)?.[1], `${label}: script tag without the nonce: ${tag.slice(0, 80)}`).toBe(nonce);
        for (const tag of html.match(STYLE_TAG) ?? []) expect(NONCE_ATTR.exec(tag)?.[1], `${label}: style tag without the nonce: ${tag.slice(0, 80)}`).toBe(nonce);
        for (const tag of html.match(/<link\b[^>]*\brel="preload"[^>]*>/g) ?? []) {
          if (/\bas="(script|style)"/.test(tag)) expect(NONCE_ATTR.exec(tag)?.[1], `${label}: preload without the nonce: ${tag.slice(0, 80)}`).toBe(nonce);
        }
        expect(html, label).toContain('<meta name="robots" content="noindex"/>');
        expect(html, label).not.toContain("<img/src=x>");
        expect(html, label).not.toContain("</script><img");
        if (/^<!DOCTYPE html><html id="__next_error__"/.test(html)) continue;
        // Not the shell: then it is the document of 5.2, whole.
        expect(html, label).toMatch(/<html lang="(fa|en)" dir="(rtl|ltr)"/);
        expect(html, label).toContain(`<meta name="csp-nonce" nonce="${nonce}"`);
        expect(html, label).toMatch(/data-theme="dark"|class="[^"]*\bdark\b/);
      }
    });

    // gate-r4-1. Next sets x-nextjs-data itself, for a real data URL only, and drops one that a client sends on any other URL. So a forged header
    // on an ordinary page is an ordinary answer with the full policy, and the proxy's 404 rule is reached only by Next's own rewritten data requests.
    // This pins that: if a Next version starts to pass the client's header on, the page below becomes a 404 and this fails.
    test("a forged x-nextjs-data header on an ordinary page changes nothing: the page, with the full CSP (gate-r4-1)", async ({request}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      for (const value of ["1", "0", ""]) {
        const plain = await request.get("/fa/login", {maxRedirects: 0});
        const forged = await request.get("/fa/login", {headers: {"x-nextjs-data": value}, maxRedirects: 0});
        const h = forged.headers();
        expect(forged.status(), value).toBe(plain.status());
        expect(forged.status(), value).toBe(200);
        expect(h["content-type"], value).toContain("text/html");
        expect(h["content-security-policy"], value).toBe(expectedCsp(app, NONCE_IN_CSP.exec(h["content-security-policy"] ?? "")?.[1] ?? "x"));
        expect(await forged.text(), value).toContain("<html");
      }
    });

    // gate-r4-11. A request that only a Server Action can make, or that no page answers, makes Next throw while it parses it, log a
    // stack trace (6 lines each) and answer a bare 400 or 409. The proxy answers them with its own 404 first. The status is the check: a
    // later change that lets one reach Next again turns the 404 into Next's 500, 400 or 409, and the answer loses the policy.
    test("a Server Action call and a multipart POST are the proxy's 404, never Next's error (gate-r4-11)", async ({request, baseURL}) => {
      type Send = (c: Record<string, string>) => Promise<APIResponse>;
      const refused: Array<[string, Send]> = [
        ["a Server Action call", (c) => request.post("/fa/login", {headers: {...c, "next-action": "a", "content-type": "text/plain;charset=UTF-8"}, data: "[]", maxRedirects: 0})],
        ["a Server Action header on a GET", (c) => request.get("/fa/login", {headers: {...c, "next-action": "a"}, maxRedirects: 0})],
        ["a multipart POST to a page", (c) => request.post("/fa/login", {headers: c, multipart: {a: "b"}, maxRedirects: 0})],
        ["a multipart POST to a path with no page", (c) => request.post("/fa/nothing-here", {headers: c, multipart: {a: "b"}, maxRedirects: 0})],
      ];
      const expectPlain404 = async (response: APIResponse, label: string) => {
        const h = response.headers();
        expect(response.status(), label).toBe(404);
        expect(h["content-type"], label).toContain("text/plain");
        expect(await response.text(), label).toBe("Not Found");
        expect(h["content-security-policy"], label).toBe(expectedCsp(app, NONCE_IN_CSP.exec(h["content-security-policy"] ?? "")?.[1] ?? "x"));
        expect(h["cross-origin-opener-policy"], label).toBe("same-origin");
        expect(h["cross-origin-resource-policy"], label).toBe("same-origin");
        expect(h["permissions-policy"], label).toBe(permissionsPolicy(app));
        expect(h["cache-control"], label).toBe("no-store");
      };
      for (const [what, send] of refused) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `${what} ${cookie ?? "without a cookie"}`;
          await expectPlain404(await send(headers(cookie)), label);
        }
      }

      // gate-r6-3. Next's segment-prefetch spelling of a page reached the [...rest] catch-all and answered 200 with the request path in its
      // payload, for a gated page with no cookie too. The class is refused by the proxy, so no later page can be read through it. Every one of
      // these ends in `.rsc`, so since gate-r7-2 the first answer is the 307 of next.config.ts that cuts it, and the proxy's 404 is the answer to
      // the path that is left (`.segments/...` is still refused by its folder, and the router never sees a `.segment.rsc` suffix any more).
      // The hop is followed with the same headers, so the check is on the end of it.
      const segments: Array<[string, string, Record<string, string>]> = [
        ["a segment prefetch of a public page", "/fa/login.segments/__PAGE__.segment.rsc", {}],
        ["a segment prefetch of the tree", "/fa/login.segments/_tree.segment.rsc", {}],
        ["a segment prefetch of a gated page", `${page.gated}.segments/_tree.segment.rsc`, {}],
        ["a segment prefetch of a path with no page", "/fa/nothing-here.segments/_tree.segment.rsc", {}],
        ["a segment prefetch with the router's own headers", "/en/login.segments/_tree.segment.rsc", {rsc: "1", "next-router-segment-prefetch": "/_tree"}],
      ];
      for (const [what, path, extra] of segments) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `${what} ${cookie ?? "without a cookie"}`;
          const first = await request.get(path, {headers: {...headers(cookie), ...extra}, maxRedirects: 0});
          expect(first.status(), `${label} loses its .rsc first`).toBe(307);
          const left = new URL(first.headers()["location"]!, baseURL);
          expect(left.pathname, label).toBe(path.replace(/\.rsc$/, ""));
          await expectPlain404(await request.get(left.pathname, {headers: {...headers(cookie), ...extra}, maxRedirects: 0}), `${label}, after the hop`);
        }
      }
    });

    // gate-r13-3. Next answers any request that carries `x-middleware-prefetch` on a route that is not prerendered with 200 `{}`, `x-middleware-skip: 1`
    // and `x-matched-path: <route pattern>`. A client can send the header, and the answer maps the route layout of the app and is a soft 200 for an
    // unknown path or a name under /_next/static/. The proxy runs first and refuses it with its own plain 404 (INTERNAL_ROUTING_HEADERS). Next strips
    // its other internal headers from an external request itself (x-now-route-matches, x-matched-path, x-middleware-skip), so a second case sends
    // them and requires the answer to be the one that the same request has without them: that is what stops being true when a Next update stops stripping one.
    test("a client's x-middleware-prefetch header gets the proxy's 404, no x-middleware-* and no x-matched-path header (gate-r13-3)", async ({request, baseURL}) => {
      const paths = [page.path, "/fa/nothing-here", page.gated, "/_next/static/chunks/x.js", "/_next/static/chunks/x.js.rsc", "/fa/virtual-lab"];
      for (const path of paths) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `x-middleware-prefetch on ${path} ${cookie ?? "without a cookie"}`;
          const response = await request.get(path, {headers: {...headers(cookie), "x-middleware-prefetch": "1"}, maxRedirects: 0});
          const h = response.headers();
          if (servedThroughCaddy(baseURL)) {
            // Caddy deletes the header before the request reaches Next (merge item A10), so the proxy never sees it and the answer is the one
            // that the same request has without it. The refusal asserted below is the proxy's half and runs in plain next start.
            const plain = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
            expect(response.status(), label).toBe(plain.status());
            expect(h["location"], label).toBe(plain.headers()["location"]);
            expect(Object.keys(h).filter((n) => n.startsWith("x-middleware-")), label).toEqual([]);
            expect(h["x-matched-path"], label).toBeUndefined();
            continue;
          }
          // A .rsc name first loses its suffix to a 307 (gate-r7-2); every other path is answered at once.
          if (response.status() === 307) {
            expect(path, label).toMatch(/\.rsc$/);
            continue;
          }
          expect(response.status(), label).toBe(404);
          expect(h["content-type"], label).toContain("text/plain");
          expect(await response.text(), label).toBe("Not Found");
          expect(Object.keys(h).filter((n) => n.startsWith("x-middleware-")), label).toEqual([]);
          expect(h["x-matched-path"], label).toBeUndefined();
          expect(h["content-security-policy"], label).toBe(expectedCsp(app, NONCE_IN_CSP.exec(h["content-security-policy"] ?? "")?.[1] ?? "x"));
          expect(h["permissions-policy"], label).toBe(permissionsPolicy(app));
        }
      }
      // The same paths without the header are not refused: the header is what is refused, not the path.
      if (htmlBuilt) expect((await request.get(page.path, {headers: headers(page.cookie), maxRedirects: 0})).status()).toBe(200);
    });

    test("the internal headers that Next strips from an external request change nothing, and none of them shows in the answer (gate-r13-3)", async ({request}) => {
      for (const path of [page.path, "/fa/nothing-here", page.gated, "/_next/static/chunks/x.js"]) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `${path} ${cookie ?? "without a cookie"}`;
          const plain = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
          const forged = await request.get(path, {
            headers: {...headers(cookie), "x-now-route-matches": "1=fa", "x-matched-path": "/[locale]/login", "x-middleware-skip": "1"},
            maxRedirects: 0,
          });
          expect(forged.status(), label).toBe(plain.status());
          expect(forged.headers()["location"], label).toBe(plain.headers()["location"]);
          expect(Object.keys(forged.headers()).filter((n) => n.startsWith("x-middleware-")), label).toEqual([]);
          expect(forged.headers()["x-matched-path"], label).toBeUndefined();
        }
      }
    });

    // gate-r22-3. Next removes the five flight headers before it calls the proxy and its renderer still reads `Next-Router-Segment-Prefetch`, so `rsc: 1`
    // with `Next-Router-Segment-Prefetch: /_tree` answers the route tree of any path as a flight payload: the names of every page under the locale layout,
    // the lab pages included. It is not an abuse of the header. Next 16's own client sends exactly that on every Link prefetch (incremental prefetching is
    // the default, and neither app turns it off), so the answer is public by design to anyone who asks and nothing here, in the proxy, next.config.ts or at
    // the edge, may refuse it: a refusal was built and broke every prefetch (a relative Location that upgrade-insecure-requests turns into https on an http
    // origin, and a failed prefetch for each Link). What stays closed is the path form (`.segments/` and `.segment.rsc`, nextRequests.ts) and what the tree
    // does not hold: it lists page names only, and every page behind them still goes through the gate (gate-r22-3).
    // This case pins both halves, so a later "refusal" fails here: the client does send the header, and the answer is the flight payload, not a redirect.
    test("a Link prefetch of our own client carries Next-Router-Segment-Prefetch and is answered with the flight payload, not refused (gate-r22-3)", async ({page: tab, guard}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      // Both apps open their 404 here (it holds the Link), and Chrome may log the failed navigation.
      guard.allowConsole(/status of 404/);
      const seen: Array<{url: string; status: number; type: string}> = [];
      tab.on("response", (response) => {
        const request = response.request();
        if (request.headers()["next-router-segment-prefetch"]) seen.push({url: response.url(), status: response.status(), type: response.headers()["content-type"] ?? ""});
      });
      await tab.goto(page.linked);
      await tab.waitForLoadState("networkidle");
      await expect.poll(() => seen.length, {message: "the client sent no segment prefetch: Next's default changed, and nextRequests.ts and this comment must be read again"}).toBeGreaterThan(0);
      for (const entry of seen) {
        expect(entry.status, entry.url).toBe(200);
        expect(entry.type, entry.url).toContain("text/x-component");
      }
    });

    // gate-r14-1. The class is every header that Next defines or reads (nextHeaders.ts reads them from the installed package, by constant as well as by
    // literal, with and without an x- prefix). The ones that are an address, the flight protocol, or refused by the proxy have their own cases; every
    // other one is sent here with a value, to a page, an unknown path and a gated page, and the answer must be the one that the request has without it:
    // same status, Location, media type, header names and body length. A Next update that starts to honour one of them for an external request
    // changes an answer and fails here, and the unit test of nextRequests.test.ts fails first when it starts to read one more.
    test("a header that only Next's router or a platform should set changes nothing when a client sends it (gate-r14-1)", async ({request}) => {
      const {read} = readNextHeaders();
      const skipped = new Set(["host", "user-agent", "sec-fetch-dest", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port", "x-forwarded-for",
        "rsc", "next-router-state-tree", "next-router-prefetch", "next-router-segment-prefetch", "x-nextjs-data", "next-action", ...INTERNAL_ROUTING_HEADERS]);
      const sent = [...read].filter((name) => !skipped.has(name));
      // The scan has to find the ones that a literal scan never saw, or this case would check a few names and call it a class.
      for (const name of ["next-resume", "x-matched-path", "x-prerender-revalidate", "x-next-revalidate-tag-token", "x-nextjs-rewritten-path", "next-url", "next-hmr-refresh"]) {
        expect(sent, name).toContain(name);
      }
      const forgedHeaders = Object.fromEntries(sent.map((name) => [name, "1"]));
      for (const path of [page.path, "/fa/nothing-here", page.gated]) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `${path} ${cookie ?? "without a cookie"}`;
          const plain = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
          const forged = await request.get(path, {headers: {...headers(cookie), ...forgedHeaders}, maxRedirects: 0});
          expect(forged.status(), label).toBe(plain.status());
          expect(forged.headers()["location"], label).toBe(plain.headers()["location"]);
          expect(forged.headers()["content-type"], label).toBe(plain.headers()["content-type"]);
          expect(Object.keys(forged.headers()).sort(), label).toEqual(Object.keys(plain.headers()).sort());
          expect((await forged.body()).length, label).toBe((await plain.body()).length);
        }
      }
    });

    // gate-r7-2. Next removes one trailing `.rsc` from the path before the proxy runs and the router renders the raw path, so for `<x>.rsc.rsc`
    // the gate judged `<x>.rsc` while the catch-all rendered the name, and any unknown name written with `.rsc` (or `.prefetch.rsc`, `.json.rsc`)
    // got a soft 200 `text/x-component` that echoed it. The proxy cannot see the raw path, so next.config.ts has a redirect (runs first, on the
    // raw path) that cuts one `.rsc` per hop. The check follows every hop by hand: each one is a 307 to the same path minus one `.rsc`, and
    // the end is what the plain path answers: the gate's redirect, the page, or a 404 that is not a flight payload.
    test("a path written with .rsc is redirected to the plain path one suffix at a time, and never answers a soft 200 flight payload (gate-r7-2)", async ({request, baseURL}) => {
      const names = [
        "/fa/hello-world.rsc", "/fa/hello-world.prefetch.rsc", "/fa/hello-world.rsc.rsc", "/fa/hello-world.json.rsc", "/fa/hello-world.RSC",
        "/fa/hello-world.rsc.rsc.rsc", `${page.gated}.rsc`, `${page.gated}.rsc.rsc`, `${page.gated}.json.rsc`, "/fa/login.rsc", "/en/login.rsc",
      ];
      for (const name of names) {
        for (const cookie of [undefined, page.cookie]) {
          let path = name;
          let hops = 0;
          let response = await request.get(`${path}?a=1`, {headers: headers(cookie), maxRedirects: 0});
          while (/\.rsc$/i.test(path)) {
            const label = `${path} ${cookie ?? "without a cookie"}`;
            expect(response.status(), `${label} is a redirect`).toBe(307);
            const next = new URL(response.headers()["location"]!, baseURL);
            expect(next.pathname, `${label} loses exactly one .rsc`).toBe(path.replace(/\.rsc$/i, ""));
            expect(next.search, `${label} keeps its query`).toBe("?a=1");
            path = next.pathname;
            hops += 1;
            response = await request.get(`${path}?a=1`, {headers: headers(cookie), maxRedirects: 0});
          }
          const label = `${name} ends at ${path} after ${hops} hops ${cookie ?? "without a cookie"}`;
          expect(hops, label).toBeGreaterThan(0);
          expect(response.headers()["content-type"] ?? "", `${label} is not a flight payload`).not.toContain("text/x-component");
          if (path.includes("hello-world")) expect(response.status(), label).toBe(404);
        }
      }
    });

    // gate-r8-6. The redirect above copies the raw path into Location, and it is safe only because Next's destination compiler keeps `%2F` and `%5C`
    // escaped (Next 16.4.5). A bump that decoded the parameter would turn `/%2F%2Fevil.example.rsc` into `Location: //evil.example`: an open redirect
    // from our own domain, and every other test here uses a name under /fa. So the hostile spellings are sent as written (rawGet: the request line is
    // not normalised) and each Location must stay on the origin and start with exactly one `/` that is followed by neither `/` nor a backslash.
    test("the .rsc redirect never builds a Location that leaves the origin, whatever the spelling of the path (gate-r8-6)", async ({baseURL}) => {
      const origin = baseURL!;
      const names = [
        "/%2F%2Fevil.example.rsc", "/%2f%2fevil.example.rsc", "/%5C%5Cevil.example.rsc", "/%5c%5cevil.example.rsc", "/%2F%5Cevil.example.rsc", "/%5C%2Fevil.example.rsc",
        "/%09/evil.example.rsc", "/.%2F%2Fevil.example.rsc", "/%2F%2Fevil.example.rsc.rsc", "/fa/%2F%2Fevil.example.rsc", "/fa/%5C%5Cevil.example.rsc",
        "/%2F%2Fevil.example/x.rsc", "/%E2%80%AE%2F%2Fevil.example.rsc",
      ];
      for (const name of names) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `${name} ${cookie ?? "without a cookie"}`;
          const response = await rawGet(origin, `${name}?a=1`, headers(cookie));
          const location = response.headersArray().filter((x) => x.name.toLowerCase() === "location").map((x) => x.value);
          expect([307, 308, 404], `${label} answered ${response.status}`).toContain(response.status);
          if (response.status === 404) {
            expect(location, label).toHaveLength(0);
            continue;
          }
          expect(location, `${label} has one Location`).toHaveLength(1);
          const value = location[0]!;
          expect(new URL(value, origin).origin, `${label} stays on the origin`).toBe(new URL(origin).origin);
          // Relative on the wire. If a Next version writes an absolute one, the origin check above still holds.
          if (value.startsWith("/")) expect(value, `${label} is one slash and then a name`).toMatch(/^\/(?![/\\])/);
        }
      }
    });

    // gate-r23-4. next-intl decodes one level of escapes (`%25` included) before it builds its locale redirect, so its Location is not always the path that
    // was asked for: GET /%252F%252Fevil.example gives Location /fa/%2F%2Fevil.example. That stays on the origin only because `/<locale>` always stands in
    // front, and the proxy now answers its plain 404 for a redirect that is not `/<locale>` and the asked path (redirectKind). This case sends the
    // hostile spellings as written and requires, for each, either that 404 or one Location that resolves to this origin, begins with a locale and a name,
    // and has no slash or backslash straight after it, before any further decoding. It fails the day a next-intl bump builds a target without the prefix.
    test("a locale redirect never leaves the origin, whatever the spelling of the path (gate-r23-4)", async ({baseURL}) => {
      const origin = baseURL!;
      const names = [
        "/%2F%2Fevil.example", "/%252F%252Fevil.example", "/%5C%5Cevil.example", "/%255C%255Cevil.example", "/FA/%2F%2Fevil.example",
        "/FA/%252F%252Fevil.example", "/Fa/%5C%5Cevil.example", "/EN/%252F%252Fevil.example?x=1", "/%E2%80%AE%2F%2Fevil.example",
        "/FA/%250D%250ASet-Cookie:x=1", "/FA/%25zz", "/FA/profiles%252F", "/%2F%2F%2Fevil.example", "/FA/%255C%255Cevil.example",
      ];
      for (const name of names) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `${name} ${cookie ?? "without a cookie"}`;
          const response = await rawGet(origin, name, headers(cookie));
          const location = response.headersArray().filter((x) => x.name.toLowerCase() === "location").map((x) => x.value);
          expect([307, 308, 404], `${label} answered ${response.status}`).toContain(response.status);
          if (response.status === 404) {
            expect(location, label).toHaveLength(0);
            continue;
          }
          expect(location, `${label} has one Location`).toHaveLength(1);
          const value = location[0]!;
          expect(new URL(value, origin).origin, `${label} stays on the origin`).toBe(new URL(origin).origin);
          expect(value, `${label} is a locale and then a name`).toMatch(/^\/(?:fa|en)(?:\/(?![/\\])|$|\?)/);
        }
      }
    });

    test("a form post and a navigation with a real router state tree still reach their page (gate-r4-11)", async ({request}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's)");
      const form = await request.post("/fa/login", {form: {a: "b"}, maxRedirects: 0});
      expect(form.status(), "an urlencoded POST is not a Server Action and is not refused by the proxy").not.toBe(404);
      const tree = encodeURIComponent(JSON.stringify(["", {children: ["fa", {children: ["login", {children: ["__PAGE__", {}]}]}]}]));
      const first = await request.get("/fa/login", {headers: {rsc: "1", "next-router-state-tree": tree}, maxRedirects: 0});
      const flight = first.status() === 307 ? await request.get(first.headers()["location"]!, {headers: {rsc: "1", "next-router-state-tree": tree}, maxRedirects: 0}) : first;
      expect(flight.status()).toBe(200);
    });

    // gate-r3-4 and gate-r3-6: Pages Router data URLs,`/_next/data/<build id>/<path>`. Neither app has a data route. A URL that ends in `.json`
    // reaches the proxy as the page `<path>` (Next strips the prefix and the suffix) and the proxy answers it with its own plain 404, whatever
    // the id and the page, because Next would otherwise serve its prerendered default 404 (inline scripts with no nonce) under this
    // request's CSP. Both the real build id and a made-up one are asked. The real one is read from the server under test, from the page source
    // (`"b":"<id>"` in the RSC payload), never from a .next folder of the test machine: through Caddy the server is an image that ran its own
    // `next build`, whose id is not the one on this disk, and a request with a wrong id is just an unknown path (gate-r4-6).
    const serverBuildId = async (request: APIRequestContext): Promise<string> => {
      const html = await (await request.get("/fa/login", {maxRedirects: 0})).text();
      const id = /\\"b\\":\\"([^"\\]+)\\"/.exec(html)?.[1];
      expect(id, "the build id is in the page source of /fa/login: this case cannot ask for the real one without it").toBeTruthy();
      return id!;
    };
    test("a data URL that ends in .json is the proxy's own plain 404, never a page and never Next's prerendered 404 (gate-r3-6)", async ({request}) => {
      const ids = ["x", ...(htmlBuilt ? [await serverBuildId(request)] : [])];
      for (const id of ids) {
        for (const page_ of ["/fa/login", "/fa/nothing", page.gated, "/en/nothing", "/", "/fa"]) {
          for (const cookie of [undefined, page.cookie]) {
            const path = `/_next/data/${id}${page_ === "/" ? "/index" : page_}.json`;
            const label = `${path} ${cookie ?? "without a cookie"}`;
            const response = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
            const h = response.headers();
            expect(response.status(), label).toBe(404);
            expect(h["content-type"], label).toContain("text/plain");
            expect(await response.text(), label).toBe("Not Found");
            expect(h["content-security-policy"], label).toBe(expectedCsp(app, NONCE_IN_CSP.exec(h["content-security-policy"] ?? "")?.[1] ?? "x"));
            expect(h["cross-origin-opener-policy"], label).toBe("same-origin");
            expect(h["cross-origin-resource-policy"], label).toBe("same-origin");
            expect(h["permissions-policy"], label).toBe(permissionsPolicy(app));
            expect(h["cache-control"], label).toBe("no-store");
            expect(h["location"], label).toBeUndefined();
            expect(Object.keys(h).filter((n) => n.startsWith("x-nextjs-") || n.startsWith("x-middleware-")), label).toEqual([]);
          }
        }
      }
    });

    // The one data URL that no proxy can answer: with the real build id and no `.json`, Next renders its prerendered 404 inside the middleware
    // invoke and ends the response; the proxy is asked after that and Next logs ERR_HTTP_HEADERS_SENT with a stack for each request (`handleNextDataRequest`,
    // next-server 16.4.5, gate-r7-3: the log is not visible to this process, so only the Caddy rule removes it and no case here can pin it). No `next.config` hook reaches it either
    // (a redirect source cannot start with /_next, and `headers()` is never applied to a response that Next finished). So in plain `next start`
    // the answer has no CSP, no COOP, no CORP and no Permissions-Policy, and the case below pins that as the known gap. If a later Next runs the
    // proxy first, this assertion fails: then drop the pin and the Caddy rule. Through Caddy the gap must be closed: Caddy answers `/_next/data/*`
    // itself (15.1), so there is no document at all, and whatever it answers carries one CSP, COOP, CORP and the Permissions-Policy.
    test("the real build id without .json is answered by Next before the proxy: pinned here, closed by Caddy (gate-r3-4)", async ({request, baseURL}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's), so the server shows no build id");
      const buildId = await serverBuildId(request);
      const throughCaddy = servedThroughCaddy(baseURL);
      for (const path of [`/_next/data/${buildId}/anything`, `/_next/data/${buildId}/fa/login`, `/_next/data/${buildId}`]) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `${path} ${cookie ?? "without a cookie"}`;
          const response = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
          const h = response.headers();
          expect(response.status(), label).toBe(404);
          if (!throughCaddy) {
            expect(h["content-security-policy"], `${label}: Next now runs the proxy for this path, so the gap and the Caddy rule can go`).toBeUndefined();
            continue;
          }
          const one = (name: string) => response.headersArray().filter((x) => x.name.toLowerCase() === name).map((x) => x.value);
          expect(one("content-security-policy"), `one CSP on ${label}`).toHaveLength(1);
          expect(one("cross-origin-opener-policy"), `COOP on ${label}`).toEqual(["same-origin"]);
          expect(one("cross-origin-resource-policy"), `CORP on ${label}`).toEqual(["same-origin"]);
          expect(one("permissions-policy"), `Permissions-Policy on ${label}`).toEqual([permissionsPolicy(app)]);
          // A document here would run Next's scripts, and an inert answer is the point of the rule.
          expect(await response.text(), `${label} has no document`).not.toContain("<script");
        }
      }
    });

    // gate-r8-1. A name under /_next/static/ that ends in `.rsc` is the one `.rsc` spelling that the redirect of next.config.ts (gate-r7-2)
    // cannot cut: Next compiles every redirect with a lookahead that skips /_next, and a rewrite does not help either, because Next has already
    // cut the suffix when it matches rewrites (a beforeFiles rewrite for it was tried and left the lowercase suffix at 200). The proxy passes
    // `/_next/static/` on, sees the stripped name and hands it to the catch-all, which answers a 4.7 KB `text/x-component` 200 with the path
    // and query echoed in it. It is not script (the body starts `1:"$Sreact.fragment"`, a syntax error), it has the full CSP, and 15.5's
    // nosniff from Caddy stops a sniffed run, so there is no exploit here; but 15.5 rests on that condition and this is same-origin text
    // with an attacker-chosen path. So, like gate-r3-4: plain `next start` is pinned at the known gap (and the case fails the day Next closes
    // it, so the Caddy rule can go), and through Caddy the answer must be a 404: the rule is `/_next/static/*` ending in `.rsc`, case-insensitive,
    // inside the web handle only.
    test("a name under _next/static that ends in .rsc: pinned here, closed by Caddy (gate-r8-1)", async ({request, baseURL}) => {
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's), so there is no chunk name to take");
      const throughCaddy = servedThroughCaddy(baseURL);
      const html = await (await request.get(page.path, {headers: headers(page.cookie), maxRedirects: 0})).text();
      const real = /<script src="(\/_next\/static\/chunks\/[^"]+\.js)"/.exec(html)?.[1];
      expect(real, "the page loads at least one chunk").toBeDefined();
      const names = ["/_next/static/chunks/nothing-here.rsc", "/_next/static/chunks/nothing-here.prefetch.rsc", `${real}.rsc`, "/_next/static/media/nothing-here.woff2.rsc", "/_next/static/chunks/nothing-here.RSC"];
      for (const name of names) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `${name} ${cookie ?? "without a cookie"}`;
          const response = await request.get(`${name}?x=reflected`, {headers: headers(cookie), maxRedirects: 0});
          const h = response.headers();
          const flight = (h["content-type"] ?? "").includes("text/x-component");
          if (throughCaddy) {
            expect(response.status(), `${label} is a 404 from Caddy`).toBe(404);
            expect(flight, `${label} is not a flight payload`).toBe(false);
            continue;
          }
          // The known gap, and what keeps it harmless: the full CSP, no nonce-less script, and a body that a script tag could not run.
          if (name.endsWith(".RSC")) {
            expect(flight, `${label}: the suffix in capitals is not cut by Next`).toBe(false);
            continue;
          }
          expect(flight && response.status() === 200, `${label}: Next now answers this itself, so the gap and the Caddy rule can go`).toBe(true);
          expect(h["content-security-policy"], label).toBe(expectedCsp(app, NONCE_IN_CSP.exec(h["content-security-policy"] ?? "")?.[1] ?? "x"));
          expect(h["cache-control"] ?? "", label).toContain("no-store");
          expect(await response.text(), `${label} starts as a flight payload, which is a syntax error as a script`).toMatch(/^1:"\$Sreact\.fragment"/);
        }
      }
    });

    // merge-r2-1, -2, -6 and -17. Caddy's path matchers read the decoded path with the dot segments resolved, and reverse_proxy forwards the
    // path as written, so a spelling that the rules of 15.1 judge as another name still reaches Next as the name they exist to keep out:
    // `login%2Ejson` is ".json" to a matcher and not to Next, `..%2f..%2fx` is "/x" to a matcher, and a decoded newline stops the dot of
    // the .rsc rule. Each is sent as written (rawGet) and must be Caddy's 404 with no document and no flight payload. In plain `next start`
    // these answers are Next's own and have no CSP (the gap that the two cases above pin), so this runs through Caddy only.
    test("spellings that Caddy's matchers read as another name than Next does are Caddy's 404 (merge-r2-1, merge-r2-2, merge-r2-6, merge-r2-17)", async ({request, baseURL}) => {
      test.skip(!servedThroughCaddy(baseURL), "needs the Caddy run: next start answers these itself, which the gate-r3-4 and gate-r8-1 cases pin");
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's), so the server shows no build id");
      const origin = (baseURL ?? "").replace(/\/$/, "");
      const id = await serverBuildId(request);
      const names = [
        `/_next/data/${id}/fa/login%2Ejson`,
        `/_next/data/${id}/fa/login%2ejson`,
        `/_next/data/${id}/fa/login.js%6Fn`,
        `/_next/data/${id}/..%2f..%2f..%2fx`,
        `/_next/data/${id}/..%2F..%2Fx`,
        `/_next/data/${id}/%2e%2e/x`,
        `/_next/data/${id}/../x`,
        "/_next/static/..%2f..%2f..%2fa.rsc",
        "/_next/static/..%2F..%2Fnope.rsc",
        "/_next/static/chunks/no%0Athing.rsc",
        "/_next/static/chunks/no%0Dthing.rsc",
        "/_next/static/chunks/a%5Cb.rsc",
      ];
      for (const name of names) {
        for (const cookie of [undefined, page.cookie]) {
          const label = `${name} ${cookie ?? "without a cookie"}`;
          const response = await rawGet(origin, `${name}?x=reflected`, headers(cookie));
          const one = (header: string) => response.headersArray().filter((x) => x.name.toLowerCase() === header).map((x) => x.value);
          expect(response.status, label).toBe(404);
          expect(one("content-type").join(), `${label} is not a flight payload`).not.toContain("text/x-component");
          expect(response.body, `${label} has no document`).not.toContain("<script");
          expect(one("content-security-policy"), `one CSP on ${label}`).toHaveLength(1);
          expect(one("cross-origin-opener-policy"), `COOP on ${label}`).toEqual(["same-origin"]);
          expect(one("x-content-type-options"), `nosniff on ${label}`).toEqual(["nosniff"]);
        }
      }
    });

    // merge-r2-4, merge-r2-5, merge-r3-5, merge-r3-6. No page takes a body larger than a sign-in form, and Next holds up to 10 MB of every open non-GET
    // request in memory and logs the request URI past that, so the edge refuses what cannot be a form, and does it on the header where it can, so Next
    // never meets an aborted body: an announced length of 10000 bytes or more is a 413 (the cap is 9999), and a POST with no Content-Length (chunked) is a 411.
    // The answers are Caddy's own, so they have the headers of the site, and a sign-in form of a few hundred bytes still reaches the page. What this cannot
    // see is the log of the web container: step 10d1 of ci-web.sh reads it after the run and fails on the canary of the query, Next's "Request body
    // exceeded" and an aborted or reset body.
    test("a body over the cap is Caddy's 413 on its header, an unsized POST is its 411, and a small form still reaches its page (merge-r2-4)", async ({request, baseURL}) => {
      test.skip(!servedThroughCaddy(baseURL), "needs the Caddy run: plain next start has no edge to refuse a body");
      const origin = (baseURL ?? "").replace(/\/$/, "");
      const big = Buffer.alloc(200 * 1024, 97);
      const justOver = Buffer.alloc(10_000, 97);
      const chunks = Array.from({length: 4}, () => justOver.subarray(0, 2_000));
      const form = {"content-type": "application/x-www-form-urlencoded"};
      for (const cookie of [undefined, page.cookie]) {
        const sent = [
          ["announced 200 KB", 413, await rawGet(origin, "/fa/login?next=CANARYTOKEN", {...headers(cookie), ...form, "content-length": String(big.length)}, "POST", 15000, big)],
          ["announced 10000 bytes", 413, await rawGet(origin, "/fa/login?next=CANARYTOKEN", {...headers(cookie), ...form, "content-length": String(justOver.length)}, "POST", 15000, justOver)],
          ["chunked", 411, await rawGet(origin, "/fa/login?next=CANARYTOKEN", {...headers(cookie), ...form}, "POST", 15000, chunks)],
        ] as const;
        for (const [how, status, response] of sent) {
          const label = `${how} ${cookie ?? "without a cookie"}`;
          const one = (name: string) => response.headersArray().filter((x) => x.name.toLowerCase() === name).map((x) => x.value);
          expect(response.status, label).toBe(status);
          expect(one("content-security-policy"), `one CSP on ${label}`).toHaveLength(1);
          expect(one("x-content-type-options"), `nosniff on ${label}`).toEqual(["nosniff"]);
          expect(one("strict-transport-security"), `HSTS on ${label}`).toHaveLength(1);
          expect(response.body, `${label}: Caddy's answer has no body of Next's`).not.toContain("<script");
        }
      }
      // Not the cap's edge: 9999 bytes, the largest announced length, is passed on, and what Next answers is not the edge's refusal.
      const edgeSize = await rawGet(origin, "/fa/login", {...headers(undefined), ...form, "content-length": "9999"}, "POST", 15000, Buffer.alloc(9999, 97));
      expect([413, 411], "the cap itself is not refused").not.toContain(edgeSize.status);
      test.skip(!htmlBuilt, "apps/admin has no page that renders the root document yet (login is WP10's), so there is no page for the small form");
      const small = await request.post("/fa/login", {form: {a: "b"}, maxRedirects: 0});
      expect([413, 411, 404], "a form of a few bytes is not refused by the body limit").not.toContain(small.status());
      expect(small.status()).toBeLessThan(500);
    });

    // merge-r3-5, merge-r3-12, merge-r4-1, merge-r4-6, merge-r4-7. A body that is announced and never finished must end at Caddy's read deadline (15 s), not stay
    // open for as long as the client keeps the stream: request_buffers holds it in the memory of the process that fronts both dashboards and the API. The request
    // announces 5000 bytes, sends 100 and waits. This is the one deliberate truncated body of the whole run, and `request_buffers` passes on what it read and then
    // aborts, so Next writes its aborted-body error block for it (15.1, 15.6). Step 10d1 of ci-web.sh reads the web logs for exactly that block after the main run,
    // so this case does not run in the main run: step 10d1b runs it alone, with E2E_STALLED_POST=1, after the scan (the same arrangement as E2E_UPSTREAM_STOPPED).
    // The ending is either a reset or an answer, and an answer is Caddy's own 408, 502 or 504 with the headers of the site (the read timeout of the body reaches
    // reverse_proxy as an error, which Caddy writes as 504, or 502 for a reset; handle_errors adds the headers), or the 200 of the page, which Next gives without
    // reading the body. A 4xx of the page would mean the body was read as finished, and "open" after 30 s is the failure.
    test("a POST body that is announced and never finished is ended by Caddy within its read deadline (merge-r3-5)", async ({baseURL}) => {
      test.skip(!servedThroughCaddy(baseURL), "needs the Caddy run: plain next start has no such deadline at an edge");
      test.skip(process.env.E2E_STALLED_POST !== "1", "makes Next log an aborted body, which step 10d1 of ci-web.sh rejects: set E2E_STALLED_POST=1 and run only this case, after that step (merge-r4-1)");
      test.setTimeout(60_000);
      const origin = (baseURL ?? "").replace(/\/$/, "");
      const response = await rawStalledPost(origin, "/fa/login", {...headers(undefined), "content-type": "application/x-www-form-urlencoded"}, 5000, 100, 30_000);
      expect(response.outcome, "a stalled body is ended by the edge, not held open").not.toBe("open");
      expect(response.ms, "within the deadline of 15 s, with a margin").toBeLessThan(30_000);
      if (response.status !== undefined) {
        // Measured on the first run: after 15 s Caddy gives up on the body, dials Next with what it read, and Next answers a POST to a page with the page
        // itself, without reading the body (there is no server action to run). So the answer is the edge's own error or that 200, with the headers of the site.
        expect([200, 408, 502, 504], "an answer of the edge or the page, within the deadline").toContain(response.status);
        const one = (name: string) => response.headersArray().filter((x) => x.name.toLowerCase() === name).map((x) => x.value);
        expect(one("x-content-type-options"), "nosniff on the answer").toEqual(["nosniff"]);
        expect(one("content-security-policy"), "one CSP on the answer").toHaveLength(1);
      }
    });

    // gate-r2-8. Some answers never run the proxy: the files of public/, Next's own 308s (`/fa/`, `//evil.example`) and the 307 for a path that ends in `.rsc` (gate-r7-2). They carry
    // COOP, CORP, Permissions-Policy and a default CSP from Caddy alone, so this is the one place that can see whether the single
    // (hardening) block does its job (15.1). The answers of the proxy have all of them already, so a case that asked only for those would
    // pass whatever Caddy did. One header of each, no list: a doubled COOP is a list, and browsers ignore it.
    test("Caddy gives COOP, CORP, Permissions-Policy and the default CSP to the answers that skip the proxy, and replaces nothing on the others (gate-r2-8)", async ({request, baseURL}) => {
      const throughCaddy = servedThroughCaddy(baseURL);
      test.skip(!throughCaddy, "needs the Caddy run: E2E_BASE_URL set to an https address (host name only) over the mock projects, not E2E_MODE=stack, which never selects this file: next start sets none of these on a 308 or a file of public/");
      // A relative "//evil.example" would be read as another host by the request context, so these are absolute, and the odd path is
      // built (the lint rule against a protocol-relative URL is right everywhere else). The backslash spelling cannot go through the
      // request context at all: its URL parser turns `/\x` into `//x`, so that request would be the double slash one twice (gate-r3-3).
      // It is sent as written with node:http, the one request that can tell a Caddy rule for one spelling from a rule for the other.
      const DOUBLE_SLASH = ["", "", "evil.example"].join("/");
      const BACKSLASH = `/${String.fromCharCode(92)}evil.example`;
      const origin = (baseURL ?? "").replace(/\/$/, "");
      // The 307 that next.config.ts answers for a path written with .rsc (gate-r7-2) is a fourth answer that skips the proxy.
      const skip = [`${origin}/fa/`, `${origin}${page.gated}/`, `${origin}${DOUBLE_SLASH}`, `${origin}/fa/nothing-here.rsc`, ...staticPaths(appDir).map((path) => `${origin}${path}`)];
      const DEFAULT_CSP = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'";
      const one = (response: {headersArray(): {name: string; value: string}[]}, name: string) =>
        response.headersArray().filter((h) => h.name.toLowerCase() === name).map((h) => h.value);
      const answers: [string, {headersArray(): {name: string; value: string}[]}][] = [];
      for (const url of skip) answers.push([url, await request.get(url, {headers: headers(page.cookie), maxRedirects: 0})]);
      const raw = await rawGet(origin, BACKSLASH, headers(page.cookie));
      expect(raw.status, "the raw backslash request was answered with a redirect, as Next does for the other spellings").toBeGreaterThanOrEqual(300);
      answers.push([`${origin} (raw) ${BACKSLASH}`, raw]);
      // gate-r14-5. The Go API sets none of these four (no CSP, CORP or Permissions-Policy anywhere in the Go tree), so on /api/* they can only come
      // from Caddy's site-level header block. A merge that writes the new lines inside the web `handle`, next to the per-site Permissions-Policy and
      // the method rules, would keep every case above green and leave every API answer bare: the cookie-authenticated JSON then has no CORP, and the
      // 301 that Go's mux gives for `/api/v1//me` (body text/html, on the panel origin) has no CSP at all. So the API answers are asked for here, the
      // one that is JSON with no session, the 404 of the mux, and the 301 (raw, because the request context would clean the path).
      const API_ODD = "/api/v1//me";
      for (const path of ["/api/v1/nothing-here", "/api/v1/me"]) answers.push([`${origin}${path}`, await request.get(`${origin}${path}`, {maxRedirects: 0})]);
      answers.push([`${origin} (raw) ${API_ODD}`, await rawGet(origin, API_ODD, {})]);
      for (const [url, response] of answers) {
        expect(one(response, "cross-origin-opener-policy"), `COOP on ${url}`).toEqual(["same-origin"]);
        expect(one(response, "cross-origin-resource-policy"), `CORP on ${url}`).toEqual(["same-origin"]);
        expect(one(response, "permissions-policy"), `Permissions-Policy on ${url}`).toEqual([permissionsPolicy(app)]);
        if (url.includes("(raw)") && url.endsWith(BACKSLASH)) {
          // Measured on caddy:2.10 (merge item A16): the reverse proxy writes the backslash as %5C, so Next sees `/%5Cevil.example`, an ordinary path
          // that the proxy answers (a 307 to /fa/%5Cevil.example, on the same origin) and not the normalisation 308 that `next start` gives for the raw
          // spelling. That answer has the proxy's own policy, once, which is the point of the case: exactly one CSP, never two.
          const csp = one(response, "content-security-policy");
          expect(csp, `one CSP on ${url}`).toHaveLength(1);
          expect(csp[0], `the default or the full policy on ${url}`).toMatch(/^default-src 'none'; (base-uri 'none'; frame-ancestors 'none'$|script-src )/);
        } else {
          expect(one(response, "content-security-policy"), `the default CSP on ${url}`).toEqual([DEFAULT_CSP]);
        }
      }
      // The ones that the proxy answered keep their own policy, once: Caddy's default is the `?` form and must never replace it.
      for (const [path, cookie] of [[page.gated, undefined], ["/", undefined], [odd[0]!, undefined], ...(htmlBuilt ? [[page.path, page.cookie] as const] : [])] as const) {
        const response = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
        const csp = one(response, "content-security-policy");
        expect(csp, `one CSP on ${path}`).toHaveLength(1);
        expect(csp[0], `the full policy on ${path}`).toBe(expectedCsp(app, NONCE_IN_CSP.exec(csp[0]!)?.[1] ?? "x"));
        expect(one(response, "cross-origin-opener-policy"), `COOP on ${path}`).toEqual(["same-origin"]);
        expect(one(response, "cross-origin-resource-policy"), `CORP on ${path}`).toEqual(["same-origin"]);
        expect(one(response, "permissions-policy"), `Permissions-Policy on ${path}`).toEqual([permissionsPolicy(app)]);
      }
      // gate-r7-6. The chunks are the other class: the proxy sets all four on them already (matcher lets `_next/static` through), so Caddy meets
      // the values already set and must replace them. 15.1 names this run as the proof. A (hardening) edit whose header lines are not
      // deferred, or whose block runs before reverse_proxy, makes Caddy add instead: two CORP lines are a list that the browser ignores, and a
      // site could then load the chunk with a no-cors script request. `one` reads headersArray, so a doubled value is a failure here, which
      // response.headers() (it joins duplicates) would hide. A real chunk is asked for as well as a name that is no file.
      const chunks = ["/_next/static/chunks/nothing-here.js"];
      if (htmlBuilt) {
        const html = await (await request.get(page.path, {headers: headers(page.cookie), maxRedirects: 0})).text();
        const real = /<script src="(\/_next\/static\/chunks\/[^"]+\.js)"/.exec(html)?.[1];
        expect(real, "the page loads at least one chunk").toBeDefined();
        chunks.push(real!);
      }
      for (const path of chunks) {
        const response = await request.get(path, {maxRedirects: 0});
        const csp = one(response, "content-security-policy");
        expect(csp, `one CSP on the chunk ${path}`).toHaveLength(1);
        expect(csp[0], `the full policy on the chunk ${path}`).toBe(expectedCsp(app, NONCE_IN_CSP.exec(csp[0]!)?.[1] ?? "x"));
        expect(one(response, "cross-origin-opener-policy"), `COOP on the chunk ${path}`).toEqual(["same-origin"]);
        expect(one(response, "cross-origin-resource-policy"), `CORP on the chunk ${path}`).toEqual(["same-origin"]);
        expect(one(response, "permissions-policy"), `Permissions-Policy on the chunk ${path}`).toEqual([permissionsPolicy(app)]);
      }
    });

    // Spec 15.5: script-src 'self' (no strict-dynamic) is safe only while Caddy sets nosniff on every response. Next sets none of
    // these four headers, so only a run through Caddy can see them, and it is the run that must fail when a Caddyfile edit drops
    // one (gate-r1-2). In plain `next start` mode the case is skipped, and the skip says why.
    test("Caddy adds nosniff, Referrer-Policy, X-Frame-Options and HSTS to every kind of answer (15.5)", async ({request, baseURL}) => {
      const throughCaddy = servedThroughCaddy(baseURL);
      test.skip(!throughCaddy, "needs the Caddy run: E2E_BASE_URL set to an https address (host name only) over the mock projects, not E2E_MODE=stack, which never selects this file: next start sets none of these four headers");
      // The API handle is the one that Go answers, and Go sets none of the four: on /api/* they come from Caddy alone, through the hardening
      // header block of the site. A header block that moved into the web handle (where the method rule and the per-site policy go) would
      // leave every API answer with nothing, and an answer with a text body that a script tag can run would then run under 'self' (gate-r5-6).
      // An unknown path (404) and an unauthenticated read (401) need no session, and neither is HTML.
      const api = ["/api/v1/nothing-here", "/api/v1/me"];
      const paths = [page.path, "/", page.gated, odd[0]!, "/_next/static/chunks/nothing-here.js", ...staticPaths(appDir).slice(0, 2), ...api];
      for (const path of api) {
        const response = await request.get(path, {maxRedirects: 0});
        expect([401, 404], `${path} is answered by the API and not by the web upstream`).toContain(response.status());
        // The web upstream answers HTML. Go answers its own 404 in plain text or JSON, so only the read that must be refused is asked for JSON.
        expect(response.headers()["content-type"] ?? "", path).not.toContain("text/html");
      }
      if (htmlBuilt) {
        const html = await (await request.get(page.path, {headers: headers(page.cookie), maxRedirects: 0})).text();
        const chunk = /<script src="(\/_next\/static\/chunks\/[^"]+\.js)"/.exec(html)?.[1];
        if (chunk) paths.push(chunk);
      }
      for (const path of paths) {
        const response = await request.get(path, {headers: headers(page.cookie), maxRedirects: 0});
        const h = response.headers();
        expect(h["x-content-type-options"], `nosniff on ${path}`).toBe("nosniff");
        expect(h["referrer-policy"], `Referrer-Policy on ${path}`).toBe("no-referrer");
        expect(h["x-frame-options"], `X-Frame-Options on ${path}`).toBe("DENY");
        expect(h["strict-transport-security"], `HSTS on ${path}`).toMatch(/^max-age=\d+/);
      }
    });

    // Next answers TRACE with a bare 500 before the proxy runs (no CSP, COOP, CORP or Permissions-Policy) and writes a stack trace to
    // its log for every request. No browser can send TRACE, but a script can, so the Caddyfile refuses the method before it reaches Next
    // and the 405 carries the hardening headers (gate-r1-14). Mock mode cannot see this: next start has nothing in front of it.
    // gate-r3-8: the same holds for every method the apps never use. Next answers PUT and DELETE on a page with 200 and an unknown method
    // with a bare 400 that has none of the headers, so Caddy lets only GET, HEAD and POST through (`@nomethod not method ...`, one rule before
    // reverse_proxy in both sites). A list of the bad ones (TRACE, TRACK, CONNECT) would miss the next one, and this case names three more.
    test("Caddy lets only GET, HEAD and POST reach Next, and answers any other method with a 405 that has the headers (gate-r3-8)", async ({request, baseURL}) => {
      const throughCaddy = servedThroughCaddy(baseURL);
      test.skip(!throughCaddy, "needs the Caddy run: E2E_BASE_URL set to an https address (host name only) over the mock projects, not E2E_MODE=stack, which never selects this file: next start answers these itself");
      for (const method of ["PUT", "DELETE", "PATCH", "PROPFIND", "FOO"]) {
        const response = await request.fetch(page.gated, {method, maxRedirects: 0});
        const h = response.headers();
        expect(response.status(), method).toBe(405);
        expect(h["content-security-policy"] ?? "", method).toContain("default-src 'none'");
        expect(h["cross-origin-opener-policy"], method).toBe("same-origin");
        expect(h["cross-origin-resource-policy"], method).toBe("same-origin");
        expect(h["x-content-type-options"], method).toBe("nosniff");
        // merge-r3-2: the answer says which methods the page takes. Two header lines write it, and the file rule is written after the page rule.
        expect(h["allow"], `Allow on the 405 of ${method}`).toBe("GET, HEAD, POST");
      }
      for (const method of ["GET", "HEAD"]) {
        expect((await request.fetch(page.gated, {method, maxRedirects: 0})).status(), method).not.toBe(405);
      }
      // gate-r18-1: the files that take GET and HEAD only. POST is in the site's allowlist (pages take it), so for these paths the rule is narrower:
      // /_next/static/* is answered by the proxy (a 405, tested in mock mode too), and /logo.png and /icon.png skip the proxy, so only Caddy can
      // keep Next's bare 500 away from a POST there (gate-r15-4).
      for (const path of ["/logo.png", "/icon.png", "/_next/static/chunks/nothing-here.js"]) {
        for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
          const response = await request.fetch(path, {method, maxRedirects: 0});
          expect(response.status(), `${method} ${path} is a 405, never Next's 500`).toBe(405);
          expect(response.headers()["x-content-type-options"], `${method} ${path}`).toBe("nosniff");
          expect(response.headers()["allow"], `${method} ${path} is told it takes GET and HEAD only, not the pages' list`).toBe("GET, HEAD");
        }
      }
      // gate-r4-7: the allowlist is for the web upstream only. The API uses PATCH, PUT and DELETE (account preferences, sessions, ...), and a rule
      // written at the top of the site block, or before `handle /api/*`, would answer every one of them with a 405 and break both apps. A path
      // that no route has is asked for as well as the real ones, because Go's mux answers 405 itself for a known path with a wrong method: only
      // a 404 or a 401 from the API proves that Caddy let the request through.
      const apiCalls: Array<[string, string]> = [["PATCH", "/api/v1/nothing-here"], ["PUT", "/api/v1/nothing-here"], ["DELETE", "/api/v1/nothing-here"]];
      if (app === "panel") apiCalls.push(["PATCH", "/api/v1/account/preferences"], ["DELETE", "/api/v1/account/sessions/x"]);
      for (const [method, path] of apiCalls) {
        const response = await request.fetch(path, {method, maxRedirects: 0});
        expect(response.status(), `${method} ${path} reaches the API`).not.toBe(405);
        expect([401, 403, 404, 400, 422], `${method} ${path} is not answered by Caddy's method rule`).toContain(response.status());
      }
    });

    // gate-r4-11, the third kind. A `Next-Router-State-Tree` that does not parse makes Next answer 500 and log 16 lines of stack trace, twice. The proxy
    // cannot refuse it: Next removes the five flight headers from the request before it hands it to the proxy (web/adapter.js FLIGHT_HEADERS), so
    // the header is invisible there (measured on next start). The edge sees it, so Caddy answers 404 for a value that is not the shape the router
    // writes: `encodeURIComponent` of a JSON array, so it starts with %5B and holds nothing but that function's output, at most 40,000 characters
    // (Next refuses a longer one itself), and ends with %5D. The rule reads the value Caddy joins from every line of the header, so a second line
    // cannot hide behind a real tree (merge-r1-4: a per-line match let one good line shield a junk one). It cannot parse JSON, so a value that has the
    // shape of an array and is not a tree (`%5B1%5D`) still reaches Next, which answers 500 and writes 16 lines of stack for it. That residual is
    // written down in spec 15.6 as what it is, an anonymous 500, and is the owner's to close with a patch of Next.
    test("Caddy answers 404 for a router state tree that is not the shape the router writes, and lets a real one through (gate-r4-11)", async ({request, baseURL}) => {
      const throughCaddy = servedThroughCaddy(baseURL);
      test.skip(!throughCaddy, "needs the Caddy run: E2E_BASE_URL set to an https address (host name only) over the mock projects, not E2E_MODE=stack, which never selects this file: next start answers these with its own 500");
      for (const bad of ["x", "%zz", "[1", "%5Bx", "%5B" + "a".repeat(40_001)]) {
        const response = await request.get(page.path, {headers: {...headers(page.cookie), rsc: "1", "next-router-state-tree": bad}, maxRedirects: 0});
        const h = response.headers();
        expect(response.status(), `tree ${bad.slice(0, 12)}`).toBe(404);
        expect(h["content-security-policy"] ?? "", `tree ${bad.slice(0, 12)}`).toContain("default-src 'none'");
        expect(h["x-content-type-options"]).toBe("nosniff");
      }
      const tree = encodeURIComponent(JSON.stringify(["", {children: ["__PAGE__", {}]}]));
      const real = await request.get(page.path, {headers: {...headers(page.cookie), rsc: "1", "next-router-state-tree": tree}, maxRedirects: 0});
      expect(real.status(), "a real tree reaches Next: a redirect that adds _rsc, or the flight answer").not.toBe(404);
      expect(real.status()).toBeLessThan(500);
      // merge-r1-4: a header written twice. Playwright's request context sends one line, so this is a raw request, with a real tree in one line and
      // junk in the other, in both orders. Next joins the lines with ", " and answers 500 with a stack for the joined text, so each must be Caddy's 404.
      for (const lines of [[tree, "zz"], ["zz", tree], [tree, tree]]) {
        const raw = await rawGet(baseURL!, page.path, {...headers(page.cookie), rsc: "1", "next-router-state-tree": lines});
        expect(raw.status, `two lines ${lines.map((l) => l.slice(0, 6)).join(" and ")}`).toBe(404);
        expect(raw.headersArray().filter((h) => h.name.toLowerCase() === "content-security-policy").map((h) => h.value).join()).toContain("default-src 'none'");
      }
    });

    // Merge item A10. Caddy deletes X-Middleware-Subrequest and X-Middleware-Prefetch from every request that goes to the web upstream. The proxy
    // refuses both too (the mock-mode cases of gate-r13-3 prove that half), so this is defence in depth, and the only way to see it work is to compare:
    // a page that is asked for with the two headers must answer exactly as it does without them, with the same status, the same Location and a body of
    // the same length. A Caddyfile that forwarded them would still pass the proxy's own refusal and fail here only if Next acted on them, so the
    // values are the ones that make Next skip its middleware (the subrequest list that names it) and treat the request as a prefetch.
    test("a page asked for with X-Middleware-Subrequest and X-Middleware-Prefetch answers as it does without them (A10)", async ({request, baseURL}) => {
      const throughCaddy = servedThroughCaddy(baseURL);
      test.skip(!throughCaddy, "needs the Caddy run: E2E_BASE_URL set to an https address (host name only) over the mock projects, not E2E_MODE=stack, which never selects this file: next start has no Caddy rule to compare");
      const hostile = {"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware", "x-middleware-prefetch": "1"};
      const targets: Array<[string, string | undefined]> = [[page.gated, undefined], ...(htmlBuilt ? [[page.path, page.cookie] as [string, string | undefined]] : [])];
      for (const [path, cookie] of targets) {
        const plain = await request.get(path, {headers: headers(cookie), maxRedirects: 0});
        const sent = await request.get(path, {headers: {...headers(cookie), ...hostile}, maxRedirects: 0});
        expect(sent.status(), `status of ${path}`).toBe(plain.status());
        expect(sent.headers()["location"], `Location of ${path}`).toBe(plain.headers()["location"]);
        expect((await sent.text()).length, `body length of ${path}`).toBe((await plain.text()).length);
      }
    });

    test("Caddy refuses TRACE and TRACK with a 405 that has the default CSP and the hardening headers (gate-r1-14)", async ({request, baseURL}) => {
      const throughCaddy = servedThroughCaddy(baseURL);
      test.skip(!throughCaddy, "needs the Caddy run: E2E_BASE_URL set to an https address (host name only) over the mock projects, not E2E_MODE=stack, which never selects this file: next start answers TRACE with its own 500");
      for (const method of ["TRACE", "TRACK"]) {
        const response = await request.fetch(page.gated, {method, maxRedirects: 0});
        const h = response.headers();
        expect(response.status(), method).toBe(405);
        expect(h["content-security-policy"] ?? "", method).toContain("default-src 'none'");
        expect(h["x-content-type-options"], method).toBe("nosniff");
        expect(h["cross-origin-opener-policy"], method).toBe("same-origin");
        expect(h["cross-origin-resource-policy"], method).toBe("same-origin");
      }
    });

    // gate-r19-2. Answers that Node, Go or Caddy make with no Next code in the path, which the other cases never ask for. Each must carry the four
    // headers of Caddy's site-level block and exactly one COOP, CORP, Permissions-Policy and (default) CSP, because nothing else can give them:
    // - a 20 KB header is Node's bare 431 (measured on next start: no header at all), the same for any request that Node's parser refuses;
    // - an absolute-form target (`GET http://evil.example/fa/profiles`) is a 308 to that other host from Next, with none of the four headers.
    //   Behind Caddy the target is probably rewritten to origin-form, but only this run can say. Any answer is accepted except one that sends
    //   the visitor to another origin: a Location that leaves the origin is the failure, a 400 from Caddy's refusal is the intended answer;
    // - `OPTIONS *` is Next's bare 500 plus a logged `TypeError: Invalid URL`, so it is asked for with the same rule (no 5xx from Next).
    // A method that Go's HTTP parser cannot read at all is a bare 400 that Caddy writes before any handler or header block, so no Caddyfile
    // edit can give it headers; it is not asserted here and the Caddy run should record it (plan_notes).
    test("Caddy puts the headers on Node's 431 and on an absolute-form or asterisk target, and never redirects off the origin (gate-r19-2)", async ({baseURL}) => {
      const throughCaddy = servedThroughCaddy(baseURL);
      test.skip(!throughCaddy, "needs the Caddy run: E2E_BASE_URL set to an https address (host name only) over the mock projects, not E2E_MODE=stack, which never selects this file: next start answers these with no header at all");
      const origin = (baseURL ?? "").replace(/\/$/, "");
      const DEFAULT_CSP = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'";
      type Answer = {headersArray(): {name: string; value: string}[]};
      const one = (response: Answer, name: string) => response.headersArray().filter((h) => h.name.toLowerCase() === name).map((h) => h.value);
      const edge = (label: string, response: Answer) => {
        expect(one(response, "x-content-type-options"), `nosniff on ${label}`).toEqual(["nosniff"]);
        expect(one(response, "x-frame-options"), `X-Frame-Options on ${label}`).toEqual(["DENY"]);
        expect(one(response, "referrer-policy"), `Referrer-Policy on ${label}`).toEqual(["no-referrer"]);
        expect(one(response, "strict-transport-security"), `HSTS on ${label}`).toHaveLength(1);
        expect(one(response, "cross-origin-opener-policy"), `COOP on ${label}`).toEqual(["same-origin"]);
        expect(one(response, "cross-origin-resource-policy"), `CORP on ${label}`).toEqual(["same-origin"]);
        expect(one(response, "permissions-policy"), `Permissions-Policy on ${label}`).toEqual([permissionsPolicy(app)]);
        expect(one(response, "content-security-policy"), `one CSP on ${label}`).toHaveLength(1);
      };

      // Built, not written: the lint rule against an http(s) URL in code is right everywhere else (fixed rule 9), and this is a name that is sent to the edge, never fetched.
      const absolute = (scheme: "http" | "https") => [`${scheme}:`, "", "evil.example", "fa", "profiles"].join("/");
      const big = await rawGet(origin, "/fa/login", {cookie: `a=${"x".repeat(20_000)}`});
      expect(big.status, "a 20 KB header is refused with 431 (Node's limit is 16 KB) and not passed on as a page").toBe(431);
      edge("the 431 of a 20 KB header", big);
      expect(one(big, "content-security-policy")[0], "the default CSP on the 431").toBe(DEFAULT_CSP);

      for (const [label, target, method] of [
        ["an absolute-form target", absolute("http"), "GET"],
        ["an absolute-form target with https", absolute("https"), "GET"],
        ["the asterisk target", "*", "OPTIONS"],
      ] as const) {
        const response = await rawGet(origin, target, {}, method);
        expect(response.status, `${label} is never a 5xx: Next answers a bare 500 for it`).toBeLessThan(500);
        const location = one(response, "location")[0];
        if (location) {
          expect(new URL(location, origin).origin, `${label} never redirects to another origin`).toBe(new URL(origin).origin);
        }
        // `OPTIONS *` is answered by Go's net/http before any Caddy handler runs (serverHandler hands it to a built-in options handler), so
        // no Caddyfile line can give that answer a header: measured on caddy:2.10, a 200 with a Date and a zero length and nothing else
        // (merge item A11). It is never a 5xx and never redirects, which is asserted above, and that is all it can be held to. The two
        // absolute-form spellings do reach Caddy, with the Host of the URL, and the catch-all site of the Caddyfile gives them the headers.
        if (target !== "*") edge(label, response);
      }

      // merge-r3-4. The two non-origin targets that Go does not answer itself and whose Host is the app's own: `GET *` (HEAD and POST too; only OPTIONS * is
      // Go's) and an opaque target (`x:` and something that does not start with a slash), which Go parses with an empty path, so no path rule sees it, while
      // Next gets the opaque text as its request target. Next answers a bare 500 with a logged TypeError for the first, writes the target with its query into
      // its log for the second, and a 308 to another origin for the third. Caddy's first web rule refuses all of them with a 400 that has the headers.
      const opaque = (rest: string) => `x:${rest}`;
      for (const [label, target, method] of [
        ["GET *", "*", "GET"],
        ["HEAD *", "*", "HEAD"],
        ["POST *", "*", "POST"],
        ["an opaque target with a query", opaque("*?t=CANARYTOKEN"), "GET"],
        ["an opaque target that looks like a URL", opaque(absolute("https")), "GET"],
      ] as const) {
        const response = await rawGet(origin, target, {}, method);
        expect(response.status, `${label} is Caddy's 400, never Next's 500 or a redirect`).toBe(400);
        expect(one(response, "location"), `${label} redirects nowhere`).toHaveLength(0);
        edge(label, response);
      }
    });

    // merge-r1-3. Port 80 is the `http://` site at the end of the Caddyfile (merge-r4-4; until then Caddy's automatic redirect, measured on caddy:2.10, covered it
    // through the catch-all `:443` site), so a plain-HTTP request for any name, in origin-form or as an absolute-form target, is a 308 to the https address of the same Host and path. That
    // is the whole answer: no page, no API call and no Next code is reached, and a client can only be sent to the name it wrote itself. HSTS, CSP and
    // the rest mean nothing on an answer with no body over plain HTTP, so none is asked for. The port is 80 unless E2E_HTTP_PORT says otherwise.
    test("plain HTTP answers any Host or absolute-form target with a redirect to the same name over https, never a page or a 5xx (merge-r1-3)", async ({baseURL}) => {
      test.skip(!servedThroughCaddy(baseURL), "needs the Caddy run: E2E_BASE_URL set to an https address (host name only)");
      const hostname = new URL(baseURL!).hostname;
      const port = process.env.E2E_HTTP_PORT ? `:${process.env.E2E_HTTP_PORT}` : "";
      // Built, not written, for the same reason as above: these are names sent to the edge, never fetched.
      const address = (scheme: "http" | "https", host: string, path: string) => [`${scheme}:`, "", host].join("/") + path;
      const origin = address("http", `${hostname}${port}`, "");
      for (const [label, target, host] of [
        ["an unknown Host", "/fa/profiles", "other.example"],
        ["the app's own Host", "/fa/profiles", hostname],
        ["an absolute-form target", address("http", "evil.example", "/fa/profiles"), "evil.example"],
      ] as const) {
        const response = await rawGet(origin, target, {host});
        expect(response.status, label).toBe(308);
        expect(response.headersArray().find((h) => h.name.toLowerCase() === "location")?.value, label).toBe(address("https", host, "/fa/profiles"));
        expect(response.body, `${label} has no body`).toBe("");
      }
      // merge-r4-4. An opaque target is not a place to redirect to: Go reads `x:@evil.example/` as scheme x and an opaque rest, and a redirect built from its
      // request URI would put the rest after the app's own name (`https://<host>@evil.example/`). Port 80 answers 400 and no Location, as the https handle does.
      for (const target of ["x:@evil.example/", "x:.evil.example/"]) {
        const response = await rawGet(origin, target, {host: hostname});
        expect(response.status, `the opaque target ${target} on port 80 is a 400, never a redirect`).toBe(400);
        expect(response.headersArray().filter((h) => h.name.toLowerCase() === "location"), `${target} redirects nowhere`).toHaveLength(0);
      }
    });

    // gate-r25-5. Next 16.4.5 sends every request that carries `Connection: Upgrade` to the upgrade handler of its router server, which resolves
    // the route and then ends the socket for any page, redirect or proxy answer: the client gets no status line at all, and the proxy cannot change
    // that whatever it returns. Neither app uses an Upgrade in production (HMR is dev only). Through Caddy, `reverse_proxy` forwards the request with
    // its Upgrade header, and an upstream that closes with no answer becomes Caddy's own 502 and an error-log line per request, which an anonymous
    // client can loop at will, with none of the headers. The edge rule (`@upgrade header Connection *Upgrade*` then `respond @upgrade 400` or 426,
    // inside each site's web handle only, before reverse_proxy) is a merge item. Here, in plain next start, the case pins what makes the rule
    // necessary, so it fails on the day Next answers an Upgrade itself and the rule can be reviewed.
    test("a request with Connection: Upgrade gets no answer from Next, and a 4xx with the headers from Caddy, never a 502 (gate-r25-5)", async ({baseURL}) => {
      const origin = (baseURL ?? "").replace(/\/$/, "");
      const upgrade = (protocol: string) => ({connection: "Upgrade", upgrade: protocol, "sec-websocket-version": "13", "sec-websocket-key": Buffer.from("ctrlz-gate-probe").toString("base64")});
      const paths = [page.gated, ...(htmlBuilt ? [page.path] : [])];
      if (!servedThroughCaddy(baseURL)) {
        for (const path of paths) {
          for (const protocol of ["websocket", "h2c"]) {
            const outcome = await rawGet(origin, path, upgrade(protocol), "GET", 5000).then(
              (response) => `answered ${response.status}`,
              () => "no answer",
            );
            expect(outcome, `Next ends the socket or never answers an Upgrade request to ${path} (${protocol}) with no status line, or never answers; if it answers now, the Caddy rule needs a second look`).toBe("no answer");
          }
        }
        return;
      }
      const one = (response: {headersArray(): {name: string; value: string}[]}, name: string) =>
        response.headersArray().filter((h) => h.name.toLowerCase() === name).map((h) => h.value);
      for (const path of [...paths, "/_next/static/chunks/nothing-here.js"]) {
        for (const protocol of ["websocket", "h2c"]) {
          const response = await rawGet(origin, path, upgrade(protocol), "GET", 20_000);
          expect(response.status, `Caddy answers an Upgrade request to ${path} (${protocol}) with a 4xx, never its own 502`).toBeGreaterThanOrEqual(400);
          expect(response.status).toBeLessThan(500);
          expect(one(response, "x-content-type-options"), `nosniff on the Upgrade answer for ${path}`).toEqual(["nosniff"]);
          expect(one(response, "content-security-policy"), `one CSP on the Upgrade answer for ${path}`).toHaveLength(1);
        }
      }
      // The API handle keeps its own behaviour: the rule is inside the web handle only, so the same request there is answered as it is without the header.
      const plain = await rawGet(origin, "/api/v1/nothing-here", {});
      const withUpgrade = await rawGet(origin, "/api/v1/nothing-here", upgrade("websocket"));
      expect(withUpgrade.status, "an Upgrade request to /api/* is not answered by the web rule").toBe(plain.status);
    });

    // gate-r19-2, the last of the list. Caddy makes a 502 or a 504 itself while the web upstream restarts or is down, with no Next code and no
    // handle: if the header block does not reach it, every deploy shows visitors an answer with none of the headers, and `handle_errors` has to
    // repeat them. Only the Caddy run can stop the upstream, so it says so with E2E_UPSTREAM_STOPPED=1 and runs only this case (the merge adds that
    // step; no script here sets it), and the case is then the only one of the file that expects an error status.
    test("Caddy's own 502 or 504, with the web upstream stopped, carries the headers (gate-r19-2)", async ({request, baseURL}) => {
      const throughCaddy = servedThroughCaddy(baseURL);
      test.skip(!throughCaddy, "needs the Caddy run: E2E_BASE_URL set to an https address (host name only) over the mock projects, not E2E_MODE=stack, which never selects this file");
      test.skip(process.env.E2E_UPSTREAM_STOPPED !== "1", "needs the web upstream stopped by the operator: set E2E_UPSTREAM_STOPPED=1 after `docker compose stop web-panel web-admin`, then run only this case");
      const response = await request.get("/fa/login", {maxRedirects: 0});
      expect([502, 503, 504], "Caddy's own error status").toContain(response.status());
      const h = response.headers();
      expect(h["x-content-type-options"]).toBe("nosniff");
      expect(h["x-frame-options"]).toBe("DENY");
      expect(h["referrer-policy"]).toBe("no-referrer");
      expect(h["strict-transport-security"]).toMatch(/^max-age=\d+/);
      expect(h["cross-origin-opener-policy"]).toBe("same-origin");
      expect(h["cross-origin-resource-policy"]).toBe("same-origin");
      expect(h["permissions-policy"]).toBe(permissionsPolicy(app));
      expect(h["content-security-policy"] ?? "").toContain("default-src 'none'");
    });
  });
}
