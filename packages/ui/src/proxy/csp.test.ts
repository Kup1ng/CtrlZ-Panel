import {describe, expect, it} from "vitest";

import {buildCsp, newNonce, parseVerifyOrigin} from "./csp.ts";

const directives = (csp: string) =>
  Object.fromEntries(csp.split("; ").map((d) => [d.split(" ")[0]!, d.split(" ").slice(1)]));

describe("buildCsp in production", () => {
  const csp = buildCsp("abc", {dev: false});
  const d = directives(csp);

  it("allows nothing by default", () => expect(d["default-src"]).toEqual(["'none'"]));
  it("ties scripts to the nonce", () => {
    expect(d["script-src"]).toEqual(["'self'", "'nonce-abc'", "'strict-dynamic'"]);
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
