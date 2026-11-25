import {existsSync, readdirSync, readFileSync, statSync} from "node:fs";
import {join} from "node:path";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

import {buildCsp, newNonce, parseVerifyOrigin} from "./csp.ts";

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

describe("verify origin", () => {
  it("adds exactly one connect source", () => {
    const origin = "https://*.verify.dns.example.ir";
    const d = directives(buildCsp("n", {dev: false, verifyOrigin: origin}));
    expect(d["connect-src"]).toEqual(["'self'", origin]);
  });
  // gate-r4-3: buildCsp is the one place the string becomes policy, so it does not rely on the caller having parsed it.
  it.each(["*", "https://*.verify.dns.example.ir; script-src *", "https://evil.example", "https://*.verify.dns.example.ir/", "http://*.verify.dns.example.ir", " "])(
    "buildCsp itself refuses %j instead of putting it into connect-src",
    (bad) => {
      expect(() => buildCsp("n", {dev: false, verifyOrigin: bad})).toThrow(/CTRLZ_VERIFY_ORIGIN/);
    },
  );
  it("is optional", () => {
    expect(parseVerifyOrigin(undefined)).toBeUndefined();
    expect(parseVerifyOrigin("")).toBeUndefined();
  });
  it("accepts the one shape", () => {
    expect(parseVerifyOrigin("https://*.verify.dns.example.ir")).toBe("https://*.verify.dns.example.ir");
    expect(parseVerifyOrigin("https://*.verify.dns.a-b.example.com")).toBe("https://*.verify.dns.a-b.example.com");
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
  ])("refuses %s", (bad) => {
    expect(() => parseVerifyOrigin(bad)).toThrow();
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
