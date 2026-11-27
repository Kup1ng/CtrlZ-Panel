import {existsSync, readdirSync, readFileSync, statSync} from "node:fs";
import {join} from "node:path";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

import {buildCsp, newNonce, parseVerifyOrigins} from "./csp.ts";

const directives = (csp: string) =>
  Object.fromEntries(csp.split("; ").map((d) => [d.split(" ")[0]!, d.split(" ").slice(1)]));

describe("buildCsp in production", () => {
  const csp = buildCsp("abc", {dev: false});
  const d = directives(csp);

  it("allows nothing by default", () => expect(d["default-src"]).toEqual(["'none'"]));
  it("ties scripts to the nonce", () => {
    expect(d["script-src"]).toEqual(["'self'", "'nonce-abc'"]);
  });
  it("has no 'strict-dynamic', so a script that a trusted script creates is held to 'self' and the nonce too (wp5-r18-3)", () => {
    // Under CSP3 'strict-dynamic' makes the browser ignore 'self' and every host, so a script element built at run time
    // would load from any origin. Next serves every chunk from /_next/static, which 'self' already allows.
    for (const dev of [false, true]) {
      const script = directives(buildCsp("abc", {dev}))["script-src"]!;
      expect(script).not.toContain("'strict-dynamic'");
      expect(script.filter((v) => !v.startsWith("'"))).toEqual([]);
      expect(script.slice(0, 2)).toEqual(["'self'", "'nonce-abc'"]);
    }
  });
  it("keeps style elements nonce-only and never unsafe-inline", () => {
    expect(d["style-src"]).toEqual(["'self'", "'nonce-abc'"]);
    expect(d["style-src-elem"]).toEqual(["'self'", "'nonce-abc'"]);
    expect(d["style-src-attr"]).toEqual(["'unsafe-inline'"]);
  });
  it("has no external origin and no eval", () => {
    expect(csp).not.toMatch(/https?:/);
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("blob:");
    expect(csp).not.toContain("ws:");
    expect(d["connect-src"]).toEqual(["'self'"]);
  });
  it("allows images and fonts from this origin only, with no data: or blob:", () => {
    expect(d["img-src"]).toEqual(["'self'"]);
    expect(d["font-src"]).toEqual(["'self'"]);
    expect(csp).not.toContain("data:");
  });
  it("closes manifest-src, because no page of either app has a web-app manifest (gate-r19-3)", () => {
    expect(d["manifest-src"]).toEqual(["'none'"]);
  });
  it("closes frames, objects, workers, base and framing", () => {
    expect(d["frame-ancestors"]).toEqual(["'none'"]);
    expect(d["frame-src"]).toEqual(["'none'"]);
    expect(d["object-src"]).toEqual(["'none'"]);
    expect(d["worker-src"]).toEqual(["'none'"]);
    expect(d["base-uri"]).toEqual(["'none'"]);
    expect(d["form-action"]).toEqual(["'self'"]);
    expect(csp).toContain("upgrade-insecure-requests");
  });
});

describe("buildCsp in development", () => {
  const d = directives(buildCsp("abc", {dev: true}));
  it("allows what next dev needs", () => {
    expect(d["script-src"]).toContain("'unsafe-eval'");
    expect(d["connect-src"]).toContain("ws:");
    expect(d["style-src-elem"]).toContain("'unsafe-inline'");
  });
});

describe("verify origin (T-238, p4-nodes 10.3: a comma list of at most two origins)", () => {
  const A = "https://*.verify.dns.example.ir";
  const B = "https://*.verify.dns.old-example.ir";
  it("adds exactly the origins it is given to connect-src", () => {
    expect(directives(buildCsp("n", {dev: false, verifyOrigins: [A]}))["connect-src"]).toEqual(["'self'", A]);
    expect(directives(buildCsp("n", {dev: false, verifyOrigins: [A, B]}))["connect-src"]).toEqual(["'self'", A, B]);
  });
  // gate-r4-3: buildCsp is the one place the string becomes policy, so it does not rely on the caller having parsed it.
  it.each(["*", "https://*.verify.dns.example.ir; script-src *", "https://evil.example", "https://*.verify.dns.example.ir/", "http://*.verify.dns.example.ir", " "])(
    "buildCsp itself refuses %j instead of putting it into connect-src",
    (bad) => {
      expect(() => buildCsp("n", {dev: false, verifyOrigins: [bad]})).toThrow(/CTRLZ_VERIFY_ORIGIN/);
    },
  );
  it("buildCsp refuses a third origin and a repeated one (p4-nodes 10.3)", () => {
    expect(() => buildCsp("n", {dev: false, verifyOrigins: [A, B, "https://*.verify.dns.third.ir"]})).toThrow(/at most two/);
    expect(() => buildCsp("n", {dev: false, verifyOrigins: [A, A]})).toThrow(/twice/);
  });
  it("is optional", () => {
    expect(parseVerifyOrigins(undefined)).toEqual([]);
    expect(parseVerifyOrigins("")).toEqual([]);
    expect(directives(buildCsp("n", {dev: false}))["connect-src"]).toEqual(["'self'"]);
  });
  it("accepts one origin or two, in the order written", () => {
    expect(parseVerifyOrigins(A)).toEqual([A]);
    expect(parseVerifyOrigins("https://*.verify.dns.a-b.example.com")).toEqual(["https://*.verify.dns.a-b.example.com"]);
    expect(parseVerifyOrigins(`${A},${B}`)).toEqual([A, B]);
  });
  it.each([
    "http://*.verify.dns.example.ir",
    "https://*.verify.dns.example.ir/",
    "https://*.verify.dns.example.ir:443",
    "https://*.verify.dns.",
    "https://*.verify.dns.example.ir ",
    "https://verify.dns.example.ir",
    "https://*.verify.dns.example.ir; script-src *",
    "https://*.verify.dns.example..ir",
    "https://*.evil.example",
    "*",
    "https:",
    "https://*.verify.dns.EXAMPLE.ir",
    // The list itself: a third origin, a repeat, an empty element, a space after the comma, a second element of the wrong shape.
    "https://*.verify.dns.a.ir,https://*.verify.dns.b.ir,https://*.verify.dns.c.ir",
    `${A},${A}`,
    `${A},`,
    `,${A}`,
    `${A}, ${B}`,
    `${A},https://evil.example`,
    `${A},*`,
  ])("refuses %s", (bad) => {
    expect(() => parseVerifyOrigins(bad)).toThrow(/CTRLZ_VERIFY_ORIGIN/);
  });
});

describe("newNonce", () => {
  it("is base64 of 16 bytes and differs each time", () => {
    const a = newNonce();
    const b = newNonce();
    expect(a).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(a).not.toBe(b);
  });
});

// manifest-src is 'none' because no app has a web-app manifest (gate-r19-3). The day one is added, this fails and names the three places
// that change together: csp.ts, expectedCsp.ts and spec 15.2. Walks the whole app source and public/, so a route, a file or a metadata
// key in any layout is caught, not only the two names Next treats as special.
describe("manifest-src and the apps' own files (gate-r19-3)", () => {
  const appsDir = fileURLToPath(new URL("../../../../apps", import.meta.url));
  const files = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const full = join(dir, name);
      return statSync(full).isDirectory() ? files(full) : [full];
    });
  for (const app of ["panel", "admin"]) {
    it(`${app} has no manifest route, file, link or metadata key`, () => {
      const found: string[] = [];
      for (const root of ["src", "public"]) {
        const dir = join(appsDir, app, root);
        if (!existsSync(dir)) continue;
        for (const file of files(dir)) {
          if (/(^|[\/])manifest\.[^\/]+$|\.webmanifest$/i.test(file)) found.push(file);
          else if (/\.(tsx?|jsx?|mjs|html)$/.test(file) && /rel=["']manifest["']|\bmanifest\s*:/.test(readFileSync(file, "utf8"))) found.push(file);
        }
      }
      expect(found, "a web-app manifest needs manifest-src in csp.ts, EXPECTED_DIRECTIVES in expectedCsp.ts and spec 15.2 changed together").toEqual([]);
    });
  }
});
