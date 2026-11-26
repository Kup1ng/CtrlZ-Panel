import {readdirSync, readFileSync} from "node:fs";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";

import {NextRequest} from "next/server";
import {describe, expect, it} from "vitest";

import {createProxy} from "./createProxy.ts";
import {DECIDED, readNextHeaders} from "./nextHeaders.ts";
import {INTERNAL_ROUTING_HEADERS, refusedByNext, SEGMENT_PREFETCH_PATH} from "./nextRequests.ts";
import {ADMIN_PROTECTED_PREFIXES, ADMIN_SESSION_COOKIES, PANEL_PROTECTED_PREFIXES, PANEL_SESSION_COOKIES} from "./prefixes.ts";

const panel = createProxy({app: "panel", protectedPrefixes: PANEL_PROTECTED_PREFIXES, sessionCookies: PANEL_SESSION_COOKIES});
const admin = createProxy({app: "admin", protectedPrefixes: ADMIN_PROTECTED_PREFIXES, sessionCookies: ADMIN_SESSION_COOKIES});
type Init = {method?: string; headers?: Record<string, string>};
const call = (path: string, init: Init) => new NextRequest(`https://panel.localhost${path}`, init);

describe("requests that Next would answer with a thrown error and a stack trace (gate-r4-11)", () => {
  const REFUSED: Array<[string, string, Init]> = [
    ["a Server Action call", "/fa/login", {method: "POST", headers: {"next-action": "a", "content-type": "text/plain;charset=UTF-8"}}],
    ["a Server Action header on a GET", "/fa/login", {headers: {"next-action": "a"}}],
    ["a Server Action header on a gated page", "/fa/profiles", {method: "POST", headers: {"next-action": "a", cookie: "__Host-ctrlz_session=x"}}],
    ["a multipart POST", "/fa/login", {method: "POST", headers: {"content-type": "multipart/form-data; boundary=x"}}],
    ["a multipart POST in capitals", "/fa/login", {method: "POST", headers: {"content-type": "Multipart/Form-Data; boundary=x"}}],
    ["a multipart POST to a path with no page", "/fa/nothing", {method: "POST", headers: {"content-type": "multipart/form-data; boundary=x"}}],
    ["a segment prefetch of a public page", "/fa/login.segments/__PAGE__.segment.rsc", {}],
    ["a segment prefetch of a gated page, with no cookie", "/fa/profiles.segments/_tree.segment.rsc", {}],
    ["a segment prefetch of a gated page, with a cookie", "/fa/profiles.segments/_tree.segment.rsc", {headers: {cookie: "__Host-ctrlz_session=x"}}],
    ["a segment prefetch of a path with no page", "/fa/nothing.segments/_tree.segment.rsc", {}],
    ["a segment file alone", "/fa/login.segment.rsc", {}],
    ["a segment prefetch in capitals", "/fa/login.SEGMENTS/_tree.SEGMENT.RSC", {}],
    ["a segment prefetch with a header that Next adds", "/en/login.segments/_tree.segment.rsc", {headers: {rsc: "1", "next-router-segment-prefetch": "/_tree"}}],
    ["a segment prefetch POST", "/fa/login.segments/_tree.segment.rsc", {method: "POST"}],
    ["a middleware-prefetch header on a page", "/fa/login", {headers: {"x-middleware-prefetch": "1"}}],
    ["a middleware-prefetch header with no value", "/fa/nothing-here", {headers: {"x-middleware-prefetch": ""}}],
    ["a middleware-prefetch header on a file name", "/_next/static/chunks/x.js", {headers: {"x-middleware-prefetch": "1"}}],
    ["a middleware-prefetch header on a gated page with a cookie", "/fa/profiles", {headers: {"x-middleware-prefetch": "1", cookie: "__Host-ctrlz_session=x"}}],
    ["a multipart POST to a gated page, with and before the gate", "/fa/profiles", {method: "POST", headers: {"content-type": "multipart/form-data; boundary=x"}}],
  ];

  it("is the proxy's plain 404 with the CSP and the three headers, in both apps", async () => {
    for (const [name, proxy] of [["panel", panel], ["admin", admin]] as const) {
      for (const [what, path, init] of REFUSED) {
        const r = proxy(call(path, init));
        const label = `${name}: ${what}`;
        expect(r.status, label).toBe(404);
        expect(await r.text(), label).toBe("Not Found");
        expect(r.headers.get("content-security-policy"), label).toContain("default-src 'none'");
        expect(r.headers.get("cross-origin-opener-policy"), label).toBe("same-origin");
        expect(r.headers.get("cross-origin-resource-policy"), label).toBe("same-origin");
        expect(r.headers.get("permissions-policy"), label).not.toBeNull();
        expect(r.headers.get("cache-control"), label).toBe("no-store");
        expect(r.headers.get("location"), label).toBeNull();
        expect([...r.headers.keys()].filter((n) => n.startsWith("x-middleware-")), label).toEqual([]);
      }
    }
  });

  it("leaves what a page of ours receives alone", () => {
    const ok: Array<[string, Init]> = [
      ["an urlencoded sign-in POST", {method: "POST", headers: {"content-type": "application/x-www-form-urlencoded"}}],
      ["a JSON POST", {method: "POST", headers: {"content-type": "application/json"}}],
      ["a flight request", {headers: {rsc: "1", "next-router-prefetch": "1"}}],
      ["a plain GET", {}],
    ];
    // Names that merely contain the letters are ordinary paths.
    for (const p of ["/fa/segments", "/fa/login.segmentsx", "/fa/my.segment", "/fa/segment.rsc.json"]) expect(SEGMENT_PREFETCH_PATH.test(p), p).toBe(false);
    for (const [what, init] of ok) expect(refusedByNext(call("/fa/login", init)), what).toBe(false);
    expect(panel(call("/fa/login", ok[0]![1])).status).toBe(200);
  });
});

// gate-r7-2. The proxy sees the path after Next cut one trailing `.rsc`, so the cut has to happen first, in next.config.ts (redirects run on the
// raw path). The rule is a literal in each app's config; one that is missing from an app, or differs, leaves that app with the soft 200.
describe("the .rsc redirect of next.config.ts (gate-r7-2)", () => {
  const RULE = '{source: "/:path(.+)\\\\.rsc", destination: "/:path", permanent: false}';
  for (const app of ["panel", "admin"]) {
    it(`is in ${app}, temporary, and the only redirect`, () => {
      const config = readFileSync(fileURLToPath(new URL(`../../../../apps/${app}/next.config.ts`, import.meta.url)), "utf8");
      expect(config).toContain(RULE);
      // The share page's `headers()` has its own `source`; only the redirects are counted here.
      const redirects = /async redirects\(\) \{[\s\S]*?\n {2}\},/.exec(config)?.[0] ?? "";
      expect(redirects.match(/source:/g)).toHaveLength(1);
    });
  }

  it("cuts one suffix, whatever the letter case, and nothing that merely contains the letters", () => {
    const re = /^\/(.+)\.rsc$/;
    expect(re.exec("/fa/x.rsc.rsc")?.[1]).toBe("fa/x.rsc");
    for (const p of ["/fa/rsc", "/fa/x.rscx", "/fa/x.rsc/y"]) expect(re.test(p), p).toBe(false);
  });
});

// gate-r9-2. A navigation under /_next/static/ is the proxy's plain 404; an asset load passes to Next untouched.
describe("a browser navigation under /_next/static/ (gate-r9-2)", () => {
  it("is the proxy's plain 404 in both apps, for every navigation destination and no other", async () => {
    for (const [name, proxy] of [["panel", panel], ["admin", admin]] as const) {
      for (const dest of ["document", "iframe", "frame", "embed", "object", "Document"]) {
        for (const path of ["/_next/static/x", "/_next/static/chunks/nothing-here.js", "/_next/static/a%2fb"]) {
          const r = proxy(call(path, {headers: {"sec-fetch-dest": dest}}));
          const label = `${name}: ${dest} ${path}`;
          expect(r.status, label).toBe(404);
          expect(await r.text(), label).toBe("Not Found");
          expect(r.headers.get("content-security-policy"), label).toContain("default-src 'none'");
          expect(r.headers.get("x-middleware-next"), label).toBeNull();
        }
      }
      for (const dest of ["script", "style", "font", "image", "worker", "empty", ""]) {
        const r = proxy(call("/_next/static/chunks/a.js", {headers: dest ? {"sec-fetch-dest": dest} : {}}));
        expect(r.status, `${name}: ${dest || "no header"}`).toBe(200);
        expect(r.headers.get("x-middleware-next"), `${name}: ${dest || "no header"}`).toBe("1");
      }
    }
  });
});

// gate-r20-2. Safari before 16.4 sends no Fetch Metadata, so the Accept header of the request decides.
describe("a navigation under /_next/static/ from a browser that sends no Sec-Fetch-Dest (gate-r20-2)", () => {
  const OLD_SAFARI_PAGE = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
  it("is the proxy's plain 404 when Accept names text/html before the wildcard, in both apps", async () => {
    for (const [name, proxy] of [["panel", panel], ["admin", admin]] as const) {
      for (const accept of [OLD_SAFARI_PAGE, "text/html", "TEXT/HTML;q=0.9", " text/html , */*", "application/xhtml+xml,text/html"]) {
        for (const path of ["/_next/static/x", "/_next/static/chunks/nothing-here.js"]) {
          const r = proxy(call(path, {headers: {accept}}));
          const label = `${name}: ${accept} ${path}`;
          expect(r.status, label).toBe(404);
          expect(await r.text(), label).toBe("Not Found");
          expect(r.headers.get("content-security-policy"), label).toContain("default-src 'none'");
          expect(r.headers.get("x-middleware-next"), label).toBeNull();
        }
      }
    }
  });
  it("passes the loads that an old Safari makes: script and font with the wildcard alone, style, image and no Accept at all", () => {
    for (const [name, proxy] of [["panel", panel], ["admin", admin]] as const) {
      for (const accept of ["*/*", "text/css,*/*;q=0.1", "image/png,image/svg+xml,image/*;q=0.8,video/*;q=0.8,*/*;q=0.5", "application/javascript, */*;q=0.8, text/html;q=0.1", ""]) {
        const r = proxy(call("/_next/static/chunks/a.js", {headers: accept ? {accept} : {}}));
        const label = `${name}: ${accept || "no Accept"}`;
        expect(r.status, label).toBe(200);
        expect(r.headers.get("x-middleware-next"), label).toBe("1");
      }
    }
  });
  it("lets Sec-Fetch-Dest decide alone when it is there, whatever Accept says", () => {
    for (const [name, proxy] of [["panel", panel], ["admin", admin]] as const) {
      const asScript = proxy(call("/_next/static/chunks/a.js", {headers: {"sec-fetch-dest": "script", accept: OLD_SAFARI_PAGE}}));
      expect(asScript.status, name).toBe(200);
      const asDocument = proxy(call("/_next/static/chunks/a.js", {headers: {"sec-fetch-dest": "document", accept: "*/*"}}));
      expect(asDocument.status, name).toBe(404);
    }
  });
});

// gate-r13-3, gate-r14-1. Next trusts a few request headers that only its own router or a hosting platform should set. The class is every header
// that this Next version defines or reads (nextHeaders.ts: its own *_HEADER constants, the literal reads of its request files, and the list that it
// strips from an external request): each one is stripped by Next, refused by the proxy, or decided in DECIDED with a reason, and a Next update that
// starts reading another fails here, so it is decided by a person and not found by a scanner. Reads through a constant and names without an `x-`
// prefix (next-resume, x-matched-path, next-url, rsc) are part of the class: a scan of `headers["x-..."]` literals alone sees only a few of them.
describe("the request headers that Next reads (gate-r13-3, gate-r14-1)", () => {
  const {read, stripped} = readNextHeaders();
  const refused = (name: string) => {
    const r = panel(call("/fa/login", {headers: {[name]: "1"}}));
    return r.status === 404 && r.headers.get("x-middleware-next") === null;
  };

  it("finds the headers that the scan is built on, so a moved file cannot turn it into a pass that checks nothing", () => {
    // One of each source: a literal read, a constant in lib/constants.js, a constant in app-router-headers.js, a name with no x- prefix.
    for (const name of ["x-middleware-prefetch", "x-matched-path", "x-nextjs-rewritten-path", "next-resume", "next-url", "rsc", "next-hmr-refresh", "x-prerender-revalidate", "x-next-revalidate-tag-token"]) {
      expect(read.has(name), name).toBe(true);
    }
    expect(stripped.has("x-now-route-matches"), "the list of headers that Next strips was found").toBe(true);
  });

  it("every header that Next defines or reads is stripped by Next, refused by the proxy, or decided with a reason", () => {
    const undecided = [...read].filter((name) => !stripped.has(name) && !(name in DECIDED) && !refused(name));
    expect(undecided, "a header that Next reads, does not strip, the proxy does not refuse, and nobody has decided about").toEqual([]);
  });

  it("keeps no line for a header that Next stopped reading, and none for one that Next strips or the proxy refuses", () => {
    const stale = Object.keys(DECIDED).filter((name) => !read.has(name) || stripped.has(name) || refused(name));
    expect(stale, "a DECIDED line that no longer decides anything").toEqual([]);
  });

  it("holds that Next does not strip the header the proxy refuses, so the refusal is not dead (gate-r13-3)", () => {
    expect(stripped.has("x-middleware-prefetch"), "if Next starts stripping it, the refusal can go").toBe(false);
    for (const name of INTERNAL_ROUTING_HEADERS) expect(refused(name), name).toBe(true);
  });

  // NEXT_PRIVATE_MINIMAL_MODE makes Next trust x-matched-path, next-resume and the revalidation headers as if a platform in front had set them
  // (base-server.js reads them only then). Next strips them from an external request, and that is the only reason this is safe, so nothing of ours
  // may switch the mode on. deploy/ is read here and not edited; the image and the compose file are the places it could appear.
  it("no file that builds or runs the web apps sets NEXT_PRIVATE_MINIMAL_MODE", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "../../../..");
    const files: string[] = [];
    const walk = (dir: string, depth: number) => {
      if (depth > 6) return;
      for (const entry of readdirSync(dir, {withFileTypes: true})) {
        if (entry.name === "node_modules" || entry.name === ".next" || entry.name === ".git") continue;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) walk(full, depth + 1);
        else if (/\.(ya?ml|json|ts|mjs|sh)$|Dockerfile|^\.e/.test(entry.name)) files.push(full);
      }
    };
    for (const dir of ["deploy", "scripts", "apps", "packages"]) {
      try {
        walk(join(root, dir), 0);
      } catch {
        // A folder that this checkout does not have is not a finding.
      }
    }
    expect(files.length, "the scan found the deploy files").toBeGreaterThan(10);
    const self = fileURLToPath(import.meta.url);
    const offenders = files.filter((f) => f !== self && !f.endsWith("nextHeaders.ts") && /NEXT_PRIVATE_MINIMAL_MODE/.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });

  it("refuses each internal routing header in both apps, on a page, an unknown path and a name under _next/static", async () => {
    for (const [name, proxy] of [["panel", panel], ["admin", admin]] as const) {
      for (const header of INTERNAL_ROUTING_HEADERS) {
        for (const path of ["/fa/login", "/fa/nothing-here", "/_next/static/chunks/x.js", "/fa/profiles"]) {
          const r = proxy(call(path, {headers: {[header]: "1"}}));
          const label = `${name}: ${header} on ${path}`;
          expect(r.status, label).toBe(404);
          expect(r.headers.get("x-middleware-next"), label).toBeNull();
          expect(r.headers.get("x-middleware-skip"), label).toBeNull();
          expect(r.headers.get("x-matched-path"), label).toBeNull();
        }
      }
    }
  });
});
