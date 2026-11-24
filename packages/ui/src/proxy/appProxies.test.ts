import {fileURLToPath} from "node:url";

import {NextRequest} from "next/server";
import {afterEach, describe, expect, it, vi} from "vitest";

import {checkMatcher} from "./matcher.ts";

// The two proxy files as the apps ship them (spec 15.3, 15.4): the matcher literal against the files
// of each app, and CTRLZ_VERIFY_ORIGIN read the way `next start` reads it, once, when the file loads.
// The import path is relative on purpose: it is the file Next compiles, not a package.
const appDir = (name: string) => fileURLToPath(new URL(`../../../../apps/${name}`, import.meta.url));
const PANEL = `${appDir("panel")}/src/proxy.ts`;
const ADMIN = `${appDir("admin")}/src/proxy.ts`;

const ORIGIN = "https://*.verify.dns.example.ir";
const connectSrc = (r: Response) => /connect-src ([^;]*)/.exec(r.headers.get("content-security-policy") ?? "")?.[1];
const request = () => new NextRequest("https://panel.localhost/fa");

async function load(path: string, env: string | undefined) {
  vi.resetModules();
  vi.unstubAllEnvs();
  if (env !== undefined) vi.stubEnv("CTRLZ_VERIFY_ORIGIN", env);
  // A variable path keeps TypeScript from resolving it: the apps' files are not part of this package.
  return (await import(/* @vite-ignore */ path)) as {default: (r: NextRequest) => Response; config: {matcher: string[]}};
}

afterEach(() => vi.unstubAllEnvs());

describe.each([
  ["panel", PANEL],
  ["admin", ADMIN],
])("the %s proxy file", (name, path) => {
  it("declares one matcher literal that fits the files of the app", async () => {
    const {config} = await load(path, undefined);
    expect(config.matcher).toHaveLength(1);
    expect(checkMatcher(config.matcher[0]!, appDir(name))).toEqual([]);
  });
  it("sets the CSP and the three security headers on a page", async () => {
    const r = (await load(path, undefined)).default(request());
    expect(r.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(r.headers.get("cross-origin-opener-policy")).toBe("same-origin");
    expect(r.headers.get("cross-origin-resource-policy")).toBe("same-origin");
    expect(r.headers.get("permissions-policy")).toContain("camera=()");
  });
});

describe("CTRLZ_VERIFY_ORIGIN (spec 15.3)", () => {
  it("is absent in P1: the panel's policy has connect-src 'self'", async () => {
    expect(connectSrc((await load(PANEL, undefined)).default(request()))).toBe("'self'");
    expect(connectSrc((await load(PANEL, "")).default(request()))).toBe("'self'");
  });
  it("adds exactly one source to the panel", async () => {
    expect(connectSrc((await load(PANEL, ORIGIN)).default(request()))).toBe(`'self' ${ORIGIN}`);
  });
  it("never reaches the admin, even when the variable is set", async () => {
    expect(connectSrc((await load(ADMIN, ORIGIN)).default(request()))).toBe("'self'");
  });
  it("makes the panel proxy throw when its file loads on a wrong value, so every proxied request answers 500, and the admin ignores it", async () => {
    for (const bad of ["*", "https://*.verify.dns.example.ir/", "https://evil.example", "http://*.verify.dns.example.ir"]) {
      await expect(load(PANEL, bad), bad).rejects.toThrow(/CTRLZ_VERIFY_ORIGIN/);
    }
    await expect(load(ADMIN, "*")).resolves.toBeDefined();
  });
});
