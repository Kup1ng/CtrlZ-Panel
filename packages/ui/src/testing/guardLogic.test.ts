import {describe, expect, it} from "vitest";

import {cspDirectiveOfConsole, documentWithoutPolicy, externalHintOrigins, isExternal, isForwardPathNoise, isHintRel, isNetworkUrl, isUnexpectedConsoleError, isVerifyProbe, originOf, redactUrls, speculationHeaderTargets, unrestrictedCode, weakDirectives} from "./guardLogic.ts";
import {buildCsp} from "../proxy/csp.ts";

const own = new Set(["http://localhost:3410"]);

describe("isExternal (spec 17.2)", () => {
  it("lets the app's own origin through, whatever the path", () => {
    expect(isExternal("http://localhost:3410/fa/profiles", own)).toBe(false);
    expect(isExternal("http://localhost:3410/api/v1/me?x=1", own)).toBe(false);
  });
  it("refuses another origin, another port and another scheme of the same host", () => {
    expect(isExternal("https://fonts.googleapis.com/css2", own)).toBe(true);
    expect(isExternal("http://localhost:3411/", own)).toBe(true);
    expect(isExternal("https://localhost:3410/", own)).toBe(true);
    expect(isExternal("wss://example.com/socket", own)).toBe(true);
  });
  it("does not count data: and blob: as leaving the page", () => {
    expect(isExternal("data:image/svg+xml;base64,AAAA", own)).toBe(false);
    expect(isExternal("blob:http://localhost:3410/6a1", own)).toBe(false);
    expect(isNetworkUrl("about:blank")).toBe(false);
  });
});

describe("originOf", () => {
  it("keeps the origin and nothing a URL may hold", () => {
    expect(originOf("https://example.com/path?ticket=abc#secret")).toBe("https://example.com");
    expect(originOf("not a url")).toBe("invalid-url");
  });
});

describe("isUnexpectedConsoleError", () => {
  it("is true unless a pattern allows the message", () => {
    expect(isUnexpectedConsoleError("Failed to load resource: the server responded with a status of 503", [])).toBe(true);
    expect(isUnexpectedConsoleError("Failed to load resource: the server responded with a status of 503", [/status of 503/])).toBe(false);
    expect(isUnexpectedConsoleError("Uncaught TypeError", [/status of 503/])).toBe(true);
  });
});

describe("resource hints (gate-r2-4)", () => {
  it("knows the rel values that make a browser connect", () => {
    for (const rel of ["preconnect", "dns-prefetch", "prefetch", "preload", "modulepreload", "prerender", "PRECONNECT", "preload prefetch", "x  preconnect"]) expect(isHintRel(rel), rel).toBe(true);
    for (const rel of ["stylesheet", "icon", "canonical", "preconnected", ""]) expect(isHintRel(rel), rel).toBe(false);
  });
  it("reads the hints of a Link header that point away from the app, and only those", () => {
    const base = "http://localhost:3410/fa/login";
    const header = [
      '</_next/static/media/a.woff2>; rel=preload; as="font"; crossorigin=""; nonce="n"; type="font/woff2"',
      "<https://cdn.example/lib.js>; rel=preload; as=script",
      '<https://api.example>; rel="preconnect"',
      "<//dns.example/>; rel=dns-prefetch",
      "<https://cdn.example/a.css>; rel=stylesheet",
      "<http://localhost:3410/x>; rel=prefetch",
      "<not a url>; rel=preconnect",
    ].join(", ");
    expect(externalHintOrigins(header, base, own)).toEqual(["https://cdn.example", "https://api.example", "http://dns.example"]);
    expect(externalHintOrigins("", base, own)).toEqual([]);
  });
  it("splits entries on the comma that starts the next target, not on a comma in a parameter", () => {
    expect(externalHintOrigins('<https://a.example/>; rel=preconnect; title="x, y", <https://b.example/>; rel=preconnect', "http://localhost:3410/", own)).toEqual(["https://a.example", "https://b.example"]);
  });
});

describe("speculationHeaderTargets (gate-r26-1)", () => {
  const base = "http://localhost:3410/fa/login";
  it("names the origin of each file the header points at, and never a path or a query", () => {
    expect(speculationHeaderTargets('"/rules.json?t=secret"', base)).toEqual(["http://localhost:3410"]);
    expect(speculationHeaderTargets('"/a.json", "https://rules.example/b.json"', base)).toEqual(["http://localhost:3410", "https://rules.example"]);
    expect(speculationHeaderTargets('"//rules.example/c.json"', base)).toEqual(["http://rules.example"]);
  });
  it("is never empty: a header that sent no readable target still means a rule set was sent", () => {
    expect(speculationHeaderTargets("", base)).toEqual(["header"]);
    expect(speculationHeaderTargets("not a list", base)).toEqual(["header"]);
    expect(speculationHeaderTargets('"http://["', base)).toEqual(["header"]);
  });
});

describe("documentWithoutPolicy (gate-r3-4)", () => {
  const csp = "default-src 'none'; script-src 'self' 'nonce-abc'";
  it("flags an HTML document with no policy, or with one that has no nonce", () => {
    expect(documentWithoutPolicy(404, "text/html; charset=utf-8", undefined, "/_next/data/x", false)).toBe(true);
    expect(documentWithoutPolicy(200, "text/html", "default-src 'none'", "/fa/login", false)).toBe(true);
    expect(documentWithoutPolicy(200, "TEXT/HTML", "", "/fa/login", false)).toBe(true);
  });
  it("passes a document with a nonce, a redirect, a file that is not HTML, and the pages of the guard's own tests", () => {
    expect(documentWithoutPolicy(200, "text/html; charset=utf-8", csp, "/fa/login", false)).toBe(false);
    expect(documentWithoutPolicy(404, "text/html", csp, "/fa/nothing", false)).toBe(false);
    expect(documentWithoutPolicy(307, "text/html", undefined, "/", false)).toBe(false);
    expect(documentWithoutPolicy(200, "application/json", undefined, "/api/v1/me", false)).toBe(false);
    expect(documentWithoutPolicy(200, undefined, undefined, "/x", false)).toBe(false);
    expect(documentWithoutPolicy(200, "text/html", undefined, "/guard-selftest/quiet", true)).toBe(false);
    expect(documentWithoutPolicy(200, "text/html", undefined, "/axe-selftest", true)).toBe(false);
    expect(documentWithoutPolicy(200, "text/html", undefined, "/guard-selftestx", true)).toBe(true);
  });
  it("excuses a self-test path only for a response that a mock route made, not for a real server (gate-r5-2)", () => {
    expect(documentWithoutPolicy(200, "text/html", undefined, "/axe-selftest/x", false)).toBe(true);
    expect(documentWithoutPolicy(200, "text/html", undefined, "/guard-selftest", false)).toBe(true);
    expect(documentWithoutPolicy(404, "text/html", "default-src 'none'", "/guard-selftest/x", false)).toBe(true);
    expect(documentWithoutPolicy(200, "text/html", undefined, "/axe-selftest/x", true)).toBe(false);
    // A mock route does not excuse a page outside the self-test paths.
    expect(documentWithoutPolicy(200, "text/html", undefined, "/fa/login", true)).toBe(true);
  });
});

// gate-r9-3. The no-policy check must also refuse a policy that has a nonce and still lets an element without it run.
describe("a policy that has a nonce and is not the strict one (gate-r9-3)", () => {
  const strict = buildCsp("abc", {dev: false});
  const dev = buildCsp("abc", {dev: true});
  it("passes the policy of next start, with and without the verify origin", () => {
    expect(weakDirectives(strict)).toEqual([]);
    expect(weakDirectives(buildCsp("abc", {dev: false, verifyOrigins: ["https://*.verify.dns.example.test", "https://*.verify.dns.old.example.test"]}))).toEqual([]);
    expect(documentWithoutPolicy(200, "text/html", strict, "/fa/login", false)).toBe(false);
  });
  it("flags the policy of next dev, which has a nonce on script-src, unsafe-inline for styles and unsafe-eval", () => {
    expect(weakDirectives(dev)).toEqual(["script-src 'unsafe-eval'", "style-src 'unsafe-inline'", "style-src-elem 'unsafe-inline'"]);
    expect(documentWithoutPolicy(200, "text/html", dev, "/fa/login", false)).toBe(true);
  });
  it("flags a host, a wildcard, a scheme and strict-dynamic in a script or style directive, in any case", () => {
    for (const source of ["https://cdn.example", "*", "data:", "blob:", "https:", "'strict-dynamic'", "'unsafe-hashes'"]) {
      for (const directive of ["default-src", "script-src", "script-src-elem", "style-src", "style-src-elem", "STYLE-SRC-ELEM"]) {
        const csp = `${directive} 'self' 'nonce-abc' ${source}`;
        expect(weakDirectives(csp), csp).toHaveLength(1);
        expect(documentWithoutPolicy(200, "text/html", csp, "/fa/login", false), csp).toBe(true);
      }
    }
  });
  it("leaves the directives that are not about code alone", () => {
    expect(weakDirectives("script-src 'self' 'nonce-abc'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws:")).toEqual([]);
  });
});

// gate-r12-1. The check must also see script-src-attr, and a policy that limits no script or style although it has a nonce.
describe("a policy that lets inline handlers run, or that limits no script (gate-r12-1)", () => {
  const strict = buildCsp("abc", {dev: false});
  it("flags 'unsafe-inline' and 'unsafe-hashes' in script-src-attr, and leaves style-src-attr alone", () => {
    for (const source of ["'unsafe-inline'", "'unsafe-hashes'", "*"]) {
      const csp = `${strict}; script-src-attr ${source}`;
      expect(weakDirectives(csp), csp).toEqual([`script-src-attr ${source}`]);
      expect(documentWithoutPolicy(200, "text/html", csp, "/fa/login", false), csp).toBe(true);
    }
    expect(weakDirectives(`${strict}; script-src-attr 'none'`)).toEqual([]);
    // The real policy carries style-src-attr 'unsafe-inline' by design.
    expect(weakDirectives(strict)).toEqual([]);
  });
  it("flags a policy with a nonce and no script limit, and one with no style limit", () => {
    const noScripts = "style-src 'nonce-a'; img-src 'self'";
    expect(weakDirectives(noScripts)).toEqual([]);
    expect(unrestrictedCode(noScripts)).toEqual(["script-src"]);
    expect(documentWithoutPolicy(200, "text/html", noScripts, "/fa/login", false)).toBe(true);
    const noStyles = "script-src 'self' 'nonce-a'; img-src 'self'";
    expect(unrestrictedCode(noStyles)).toEqual(["style-src"]);
    expect(documentWithoutPolicy(200, "text/html", noStyles, "/fa/login", false)).toBe(true);
    // script-src-elem alone leaves inline event handlers unlimited.
    expect(unrestrictedCode("script-src-elem 'nonce-a'; style-src 'nonce-a'")).toEqual(["script-src"]);
  });
  it("passes a default-src that covers both, and the real policy", () => {
    expect(unrestrictedCode("default-src 'none' 'nonce-a'")).toEqual([]);
    expect(unrestrictedCode(strict)).toEqual([]);
    expect(documentWithoutPolicy(200, "text/html", strict, "/fa/login", false)).toBe(false);
  });
});

// gate-r4-5: the text of a console or page error goes into a failure message, so no URL in it may keep a path, a query or a fragment.
describe("redactUrls", () => {
  const SECRETS = ["SECRET123", "09120000000", "tok-abc"];

  it("cuts the URL of a Chrome CSP message and of a failed fetch to its origin", () => {
    const csp = "Connecting to 'https://evil.invalid/collect?ticket=SECRET123&phone=09120000000' violates the following Content Security Policy directive: \"connect-src 'self'\".";
    const fetchFailed = "Fetch API cannot load https://evil.invalid:8443/a/b?ticket=SECRET123#tok-abc. Refused to connect because it violates the document's Content Security Policy.";
    for (const text of [csp, fetchFailed]) {
      const out = redactUrls(text);
      for (const secret of SECRETS) expect(out, text).not.toContain(secret);
      expect(out).toContain("https://evil.invalid");
      expect(out).not.toContain("/collect");
    }
    expect(redactUrls(csp)).toBe("Connecting to 'https://evil.invalid' violates the following Content Security Policy directive: \"connect-src 'self'\".");
  });
  it("handles several URLs, a websocket, an own-origin URL and a URL that is not a network one", () => {
    expect(redactUrls("a wss://h.example/s?k=SECRET123 b http://localhost:3420/fa/reset?t=tok-abc c")).toBe("a wss://h.example b http://localhost:3420 c");
    expect(redactUrls("blob:http://localhost:3420/6a1-SECRET123 x")).not.toContain("SECRET123");
    expect(redactUrls("see foo://[bad?q=SECRET123")).not.toContain("SECRET123");
  });
  it("cuts a long query before it can push the limit off, and leaves a message with no URL alone", () => {
    const long = `https://evil.invalid/x?${"a=SECRET123&".repeat(100)}`;
    expect(redactUrls(`Connecting to '${long}' violates`)).toBe("Connecting to 'https://evil.invalid' violates");
    expect(redactUrls("Uncaught TypeError: x is not a function")).toBe("Uncaught TypeError: x is not a function");
    expect(redactUrls("x".repeat(500))).toHaveLength(200);
  });
});

describe("isForwardPathNoise (gate-r27-1)", () => {
  const path = "/_next/static/guard-forward";
  const msg = "Failed to load resource: the server responded with a status of 404 (Not Found)";
  it("excuses the 404 of the guard's own take-back navigation and nothing else", () => {
    expect(isForwardPathNoise("error", msg, `http://localhost:3420${path}`, path)).toBe(true);
    expect(isForwardPathNoise("error", msg, "http://localhost:3420/_next/static/chunks/x.js", path)).toBe(false);
    expect(isForwardPathNoise("error", msg, `http://localhost:3420${path}/x`, path)).toBe(false);
    expect(isForwardPathNoise("error", "Failed to load resource: the server responded with a status of 500 (Internal Server Error)", `http://localhost:3420${path}`, path)).toBe(false);
    expect(isForwardPathNoise("warning", msg, `http://localhost:3420${path}`, path)).toBe(false);
    expect(isForwardPathNoise("error", msg, "", path)).toBe(false);
  });
});

describe("cspDirectiveOfConsole (gate-r15-2)", () => {
  it("reads the directive from the messages Chrome writes for an enforced violation", () => {
    expect(cspDirectiveOfConsole(`Refused to evaluate a string as JavaScript because 'unsafe-eval' is not an allowed source of script in the following Content Security Policy directive: "script-src 'none'".`)).toBe("script-src");
    expect(cspDirectiveOfConsole(`Refused to connect to 'http://127.0.0.1:9/beacon' because it violates the following Content Security Policy directive: "connect-src 'self'". The action has been blocked.`)).toBe("connect-src");
    expect(cspDirectiveOfConsole(`Refused to load the image 'x' because it violates the following Content Security Policy directive: "IMG-SRC 'none'".`)).toBe("img-src");
  });

  it("reads the directive from the shape without a colon, which Chrome writes for an inline style, script or event handler (gate-r27-2)", () => {
    expect(cspDirectiveOfConsole(`Applying inline style violates the following Content Security Policy directive 'style-src-elem 'self' 'nonce-abc''. Either the 'unsafe-inline' keyword, a hash ('sha256-x'), or a nonce ('nonce-...') is required to enable inline execution. The action has been blocked.`)).toBe("style-src-elem");
    expect(cspDirectiveOfConsole(`Executing inline script violates the following Content Security Policy directive 'script-src 'self' 'nonce-abc''. Either the 'unsafe-inline' keyword, a hash, or a nonce is required to enable inline execution. The action has been blocked.`)).toBe("script-src");
    expect(cspDirectiveOfConsole(`Executing inline event handler violates the following Content Security Policy directive 'script-src-attr 'none''. Either the 'unsafe-inline' keyword, a hash, or a nonce is required to enable inline execution. The action has been blocked.`)).toBe("script-src-attr");
    expect(cspDirectiveOfConsole(`[Report Only] Applying inline style violates the following Content Security Policy directive 'style-src-elem 'self''.`)).toBeUndefined();
  });

  it("returns nothing for other text, and for a report-only policy", () => {
    expect(cspDirectiveOfConsole("guard selftest: pagehide")).toBeUndefined();
    expect(cspDirectiveOfConsole("Failed to load resource: net::ERR_FAILED")).toBeUndefined();
    expect(cspDirectiveOfConsole(`[Report Only] Refused to load the image because it violates the following Content Security Policy directive: "img-src 'none'".`)).toBeUndefined();
  });
});

// p4-nodes 10.3, T-238. The probe the guard excuses is a request to a verify host of a zone of the same list the CSP was built from, and nothing near it.
describe("the verify probe the guard allows (T-238)", () => {
  const origins = ["https://*.verify.dns.example.ir", "https://*.verify.dns.old.example.ir"];
  const probe = (url: string) => isVerifyProbe(new URL(url), origins);
  it("allows a host under a zone of the list, for both zones", () => {
    expect(probe("https://abc123.verify.dns.example.ir/")).toBe(true);
    expect(probe("https://a.b.verify.dns.example.ir/x?y=1")).toBe(true);
    expect(probe("https://abc.verify.dns.old.example.ir/")).toBe(true);
  });
  it("refuses a zone that is not on the list, the zone's own name, another scheme, another port and a look-alike", () => {
    for (const url of [
      "https://abc.verify.dns.third.ir/",
      "https://verify.dns.example.ir/",
      "https://.verify.dns.example.ir/",
      "http://abc.verify.dns.example.ir/",
      "https://abc.verify.dns.example.ir:8443/",
      "https://abc.verify.dns.example.ir.evil.example/",
      "https://abcverify.dns.example.ir/",
      "https://abc.example.ir/",
    ]) {
      expect(probe(url), url).toBe(false);
    }
  });
  it("allows nothing when the list is empty, and isExternal still flags the host", () => {
    expect(isVerifyProbe(new URL("https://abc.verify.dns.example.ir/"), [])).toBe(false);
    expect(isExternal("https://abc.verify.dns.example.ir/", new Set(["https://panel.localhost"]))).toBe(true);
  });
});
