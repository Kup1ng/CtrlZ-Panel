import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

import {permissionsPolicy} from "./headers.ts";

// Merge item A1 (web-merge-items.md). The Caddyfile repeats the Permissions-Policy of each app as a literal,
// because Caddy cannot import a TypeScript function. `permissionsPolicy('panel')` and `permissionsPolicy('admin')`
// are the only source of the value (spec 15.1), so this test reads the file and compares, the way the scan for
// Next's minimal-mode switch reads deploy/. A shared string, or a copy that drifted, would give the admin host
// passkey ceremonies again (gate-r2-18) or take them from the panel, and no other test would see it until the Caddy run.
const text = readFileSync(fileURLToPath(new URL("../../../../deploy/compose/caddy/Caddyfile", import.meta.url)), "utf8");
const lines = text.split("\n").filter((line) => !/^\s*#/.test(line));

/** The top-level blocks of the file, by their first line (`{$CTRLZ_PANEL_HOST:panel.localhost} {`, `(hardening) {`, `:443 {`). */
function blocks(): Map<string, string[]> {
  const out = new Map<string, string[]>();
  let current: string[] | undefined;
  for (const line of lines) {
    if (/^\S.*\{$/.test(line)) {
      current = [];
      out.set(line.slice(0, -2).trim() || "{global}", current);
    } else if (line === "}") current = undefined;
    else if (current) current.push(line);
  }
  return out;
}

const imports = (body: string[]): string[] => body.flatMap((line) => /^\s*import hardening "([^"]*)"\s*$/.exec(line)?.[1] ?? []);

describe("the Permissions-Policy of the Caddyfile (merge item A1)", () => {
  const all = blocks();
  const site = (host: string): string[] => {
    const entry = [...all].find(([name]) => name.startsWith(`{$CTRLZ_${host}_HOST:`));
    expect(entry, `a site block for ${host}`).toBeDefined();
    return entry![1];
  };

  it("hardening takes the string as its argument and writes no policy of its own", () => {
    const body = all.get("(hardening)")!.join("\n");
    expect(body).toContain("Permissions-Policy {args[0]}");
    expect(body, "interest-cohort is obsolete (gate-r2-18)").not.toContain("interest-cohort");
    expect(body).not.toContain("publickey-credentials");
  });

  it("the panel site, and its error route, write exactly permissionsPolicy('panel')", () => {
    const found = imports(site("PANEL"));
    expect(found.length, "the site and its handle_errors both import it").toBeGreaterThanOrEqual(2);
    for (const value of found) expect(value).toBe(permissionsPolicy("panel"));
  });

  it("the admin site, and its error route, write exactly permissionsPolicy('admin')", () => {
    const found = imports(site("ADMIN"));
    expect(found.length).toBeGreaterThanOrEqual(2);
    for (const value of found) expect(value).toBe(permissionsPolicy("admin"));
  });

  it("the two strings differ in the passkey features and in nothing else", () => {
    expect(permissionsPolicy("panel")).toContain("publickey-credentials-get=(self)");
    expect(permissionsPolicy("admin")).toContain("publickey-credentials-get=()");
    expect(permissionsPolicy("admin")).not.toContain("publickey-credentials-create=(self)");
  });

  it("every other import of hardening (the catch-all site) is one of the two, and both are there", () => {
    const rest = [...all].filter(([name]) => name !== "(hardening)" && !name.startsWith("{$CTRLZ_")).flatMap(([, body]) => imports(body));
    expect(new Set(rest)).toEqual(new Set([permissionsPolicy("panel"), permissionsPolicy("admin")]));
  });

  it("no policy is written anywhere but in an import of hardening, so a shared value cannot come back", () => {
    const literal = lines.filter((line) => line.includes("publickey-credentials") && !/^\s*import hardening "/.test(line));
    expect(literal).toEqual([]);
  });
});

describe("where the web rules sit (merge item A5 to A12)", () => {
  it("web_rules is imported only inside the web handle of a site, never in the API handle or at site level", () => {
    const all = blocks();
    let seen = 0;
    for (const [name, body] of all) {
      if (!name.startsWith("{$CTRLZ_")) {
        expect(body.join("\n"), `${name} imports no web rule`).not.toContain("import web_rules");
        continue;
      }
      let handle = "";
      for (const line of body) {
        const open = /^\thandle(?: (\S+))? \{$/.exec(line);
        if (open) handle = open[1] ?? "(web)";
        else if (/^\t\}$/.test(line)) handle = "";
        if (/^\t\timport web_rules$/.test(line)) {
          expect(handle, `${name}: web_rules must be inside the unmatched handle`).toBe("(web)");
          seen++;
        }
        if (/^\timport web_rules/.test(line)) throw new Error(`${name}: web_rules at site level`);
      }
    }
    expect(seen, "both sites import it").toBe(2);
  });

  it("the web rules never name /api, which uses PATCH, PUT and DELETE", () => {
    const body = blocks().get("(web_rules)")!.join("\n");
    expect(body).not.toContain("/api");
    expect(body).toContain("not method GET HEAD POST");
  });

  it("the headers that Next's client sends on every Link prefetch are never deleted", () => {
    const body = blocks().get("(web_rules)")!.join("\n");
    for (const name of ["Next-Router-Prefetch", "Next-Router-Segment-Prefetch", "rsc"]) expect(body).not.toMatch(new RegExp(`request_header -${name}\\b`, "i"));
  });
});

// Review round 2 of the web merge (merge-r2-1, -2, -4, -5, -6, -17). The edge cases themselves need Caddy and run in step 10 of
// ci-web.sh; these read the file, so a rule that is edited away or loosened fails before that run.
describe("the body limit and the raw-target rules of the web handle (merge-r2)", () => {
  const rules = () => blocks().get("(web_rules)")!.join("\n");

  it("a body over 9999 bytes is refused at the edge, an unsized POST is a 411, and each web reverse_proxy buffers more than the cap (merge-r2-4, merge-r3-5, merge-r3-6)", () => {
    expect(rules()).toMatch(/request_body \{\n\t\tmax_size 9999B\n\t\}/);
    const sites = [...blocks()].filter(([name]) => name.startsWith("{$CTRLZ_"));
    expect(sites).toHaveLength(2);
    for (const [name, body] of sites) {
      const web = /reverse_proxy web-(?:panel|admin):3000 \{\n\t\t\trequest_buffers (\d+)KB\n\t\t\}/.exec(body.join("\n"));
      expect(web, `${name}: the web reverse_proxy sets request_buffers`).not.toBeNull();
      // KB is 1000 bytes in Caddy. Every open POST holds this much of Caddy's memory until the read deadline, so it is small (merge-r3-5): a sign-in form is a few hundred bytes.
      expect(Number(web![1]) * 1000, `${name}: request_buffers is more than max_size, or a body of exactly the buffer size is cut in the middle at Next`).toBeGreaterThan(9999);
      expect(Number(web![1]), `${name}: a larger buffer moves the slow-upload memory hold into Caddy`).toBeLessThanOrEqual(16);
      // The API keeps its own limits: a body cap here would break a real request.
      expect(body.join("\n")).not.toMatch(/reverse_proxy (?:api|admin):808\d \{[^}]*request_buffers/);
    }
    // The cap sits in the web rules only: it must not reach /api.
    expect(lines.join(String.fromCharCode(10)).match(/request_body/g)).toHaveLength(1);
    expect(rules()).toContain('@post_unsized {\n\t\tmethod POST\n\t\tnot header Content-Length *\n\t}\n\trespond @post_unsized "Length Required" 411');
    expect(rules()).toContain('respond @body_too_large "Payload Too Large" 413');
  });

  // Caddy has no read deadline unless one is set, and request_buffers holds a body in Caddy's heap while it is read (merge-r3-5, merge-r3-12).
  it("the global block sets a header and a body read deadline", () => {
    // The first block of the file has no name, so blocks() does not read it: it ends at the first closing brace in column 0.
    const global = text.slice(0, text.indexOf("\n}\n"));
    expect(global).toMatch(/servers \{\n\t\ttimeouts \{\n\t\t\tread_header 10s\n\t\t\tread_body 15s\n\t\t\}\n\t\}/);
  });

  // merge-r3-4. A target that is not origin-form never reaches Next. It is the first respond of the rules, so nothing is judged on it first.
  it("a request target that does not start with a slash is a 400 before every other rule", () => {
    const body = rules();
    expect(body).toContain("@bad_target not expression {http.request.uri}.matches('^/')");
    const first = body.split("\n").find((l) => l.trim().startsWith("respond "));
    expect(first?.trim()).toBe("respond @bad_target 400");
    const origin = /^\//;
    for (const target of ["*", "x:*?t=CANARYTOKEN", "x:https://evil.example/x", "", "x:/fa/login"]) expect(origin.test(target), target).toBe(false);
    for (const target of ["/", "/fa/login?next=%2Ffa", "/_next/static/a.js"]) expect(origin.test(target), target).toBe(true);
  });

  // merge-r4-4. Caddy's automatic redirect on port 80 writes `https://{host}{uri}` for any target, and Go gives an opaque target (`x:@evil.example/`)
  // a request URI with no scheme, so the Location became `https://panel.localhost@evil.example/`. The redirect is the Caddyfile's own, after the same
  // 400 for a target that is not origin-form. Both halves are pinned: with the automatic redirect on, the site would be shadowed or doubled.
  it("port 80 is a site of its own that refuses a non-origin target and then redirects, and the automatic redirect is off", () => {
    const global = text.slice(0, text.indexOf("\n}\n"));
    expect(global).toMatch(/^\tauto_https disable_redirects$/m);
    const site = blocks().get("http://");
    expect(site, "an http:// site").toBeDefined();
    const body = site!.join("\n");
    expect(body).toContain("import quiet_log");
    expect(body).toContain("@bad_target not expression {http.request.uri}.matches('^/')");
    const order = site!.map((l) => l.trim()).filter((l) => l.startsWith("respond ") || l.startsWith("redir "));
    expect(order, "the refusal comes before the redirect, and nothing else answers").toEqual(["respond @bad_target 400", "redir https://{host}{uri} 308"]);
    expect(body, "no web or API handle on port 80").not.toMatch(/reverse_proxy|import web_rules|import hardening/);
    // The opaque spellings of the review: neither starts with a slash, so both are refused before the redirect can name another host.
    for (const target of ["x:@evil.example/", "x:.evil.example/"]) expect(/^\//.test(target), target).toBe(false);
  });

  // merge-r3-2. Two non-terminal header handlers write Allow, and the file rule comes last so it wins on a file path. Swapping them would
  // advertise POST on /logo.png, and only the Caddy case would notice.
  it("the Allow header of the page rule comes before the one of the file rule, and each names its own methods", () => {
    const body = rules();
    const page = body.indexOf('header @method_not_allowed Allow "GET, HEAD, POST"');
    const file = body.indexOf('header @file_not_read Allow "GET, HEAD"');
    expect(page).toBeGreaterThan(-1);
    expect(file).toBeGreaterThan(page);
  });

  it("the length expression refuses 10000 bytes and more, and leaves a real form and the cap alone", () => {
    const line = rules().split("\n").find((l) => l.includes("@body_too_large"))!;
    const re = new RegExp(line.slice(line.indexOf(".matches('") + ".matches('".length, line.lastIndexOf("')")));
    for (const n of ["10000", "200000", "0010000", "99999999999"]) expect(re.test(n), n).toBe(true);
    for (const n of ["0", "12", "400", "9999", "09999", ""]) expect(re.test(n), n).toBe(false);
  });

  it("the .json exception of the data rule is read from the request target as written, so %2Ejson and .js%6Fn are Caddy's 404", () => {
    expect(rules()).toContain("not expression {http.request.uri}.matches('^[^?]*[.]json([?]|$)')");
    expect(rules()).not.toMatch(/not path_regexp/);
  });

  it("a percent-escaped slash, backslash or dot under /_next/ is refused on the raw target, and so is a dot segment", () => {
    expect(rules()).toContain("@next_escaped expression {http.request.uri}.matches('(?i)^/_next/[^?]*%(2f|5c|2e)')");
    expect(rules()).toContain("respond @next_escaped 404");
    expect(rules()).toContain("@dot_segment expression {http.request.uri.path}.matches('(^|/)[.][.]?(/|$)')");
    expect(rules()).toContain("respond @dot_segment 404");
  });

  it("the .rsc rule lets the dot match a decoded newline", () => {
    expect(rules()).toContain("@rsc_static path_regexp (?is)^/_next/static/.*\\.rsc$");
  });

  // The same expressions, run as the regular expression engine of Caddy (RE2) would read them: JavaScript has the same syntax for
  // everything used here. A rule that never matches the spelling it exists for fails here and not only on the stack.
  it("the expressions of the rules match the spellings they exist for and leave the real names alone", () => {
    const pattern = (marker: string) => {
      const line = rules().split("\n").find((l) => l.includes(marker))!;
      return line.slice(line.indexOf(".matches('") + ".matches('".length, line.lastIndexOf("')")).replace(/^\(\?i\)/, "");
    };
    const json = new RegExp(pattern("[.]json("));
    expect(json.test("/_next/data/abc/fa/login.json")).toBe(true);
    expect(json.test("/_next/data/abc/fa/login.json?x=1")).toBe(true);
    for (const raw of ["/_next/data/abc/fa/login%2Ejson", "/_next/data/abc/fa/login%2ejson", "/_next/data/abc/fa/login.js%6Fn", "/_next/data/abc/fa/login", "/_next/data/abc/x?y=.json"]) {
      expect(json.test(raw), raw).toBe(false);
    }
    const escaped = new RegExp(pattern("@next_escaped"), "i");
    for (const raw of ["/_next/data/abc/..%2f..%2fx", "/_next/static/..%2F..%2Fa.rsc", "/_next/data/abc/fa/login%2Ejson", "/_next/static/a%5Cb"]) expect(escaped.test(raw), raw).toBe(true);
    for (const real of ["/_next/static/chunks/app/%5Blocale%5D/page-1a2b.js", "/_next/static/media/Dana.woff2", "/_next/data/abc/fa/login.json", "/_next/image?url=%2Flogo.png", "/fa/login%2F"]) {
      expect(escaped.test(real), real).toBe(false);
    }
    const dots = new RegExp(pattern("@dot_segment"));
    for (const decoded of ["/_next/data/x/../y", "/a/./b", "/..", "/a/..", "/%2e%2e/x".replace(/%2e/g, ".")]) expect(dots.test(decoded), decoded).toBe(true);
    for (const real of ["/fa/login", "/.well-known/x", "/a/..b", "/a/b..", "/_next/static/chunks/a.b.js"]) expect(dots.test(real), real).toBe(false);
  });
});
