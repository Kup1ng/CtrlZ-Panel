import {fileURLToPath} from "node:url";

import {afterEach, describe, expect, it, vi} from "vitest";

// The two next.config.ts files as Next loads them. Both apps depend on what is NOT in them as much as on what is (gate-r8-3):
// - nextRequests.ts answers every `.segments/` and `.segment.rsc` path with a 404 and the `.rsc` redirect cuts the suffix, which is safe only
//   because neither app serves or prefetches such URLs (no cacheComponents, no segment cache);
// - the CSP carries a per-request nonce, and a prerendered shell (ppr, cacheComponents) cannot.
// So a new top-level or `experimental` key fails here, and whoever adds one has to read this comment and the two files above.
const appDir = (name: string) => fileURLToPath(new URL(`../../../../apps/${name}`, import.meta.url));

type Loaded = {
  default: Record<string, unknown> & {experimental?: Record<string, unknown>};
};

async function load(app: string): Promise<Loaded["default"]> {
  // next-intl's plugin looks for ./src/i18n/request.ts from the working directory, which is the app's when Next loads the file.
  vi.spyOn(process, "cwd").mockReturnValue(appDir(app));
  vi.resetModules();
  const loaded = (await import(/* @vite-ignore */ `${appDir(app)}/next.config.ts`)) as Loaded;
  return loaded.default;
}

afterEach(() => vi.restoreAllMocks());

const FORBIDDEN_TOP = ["cacheComponents", "ppr", "dynamicIO", "useCache", "cacheLife", "basePath", "assetPrefix", "i18n", "trailingSlash", "skipProxyUrlNormalize", "skipMiddlewareUrlNormalize"];
const FORBIDDEN_EXPERIMENTAL = ["ppr", "cacheComponents", "dynamicIO", "useCache", "clientSegmentCache", "clientParamParsing", "sri", "prerenderEarlyExit", "staleTimes", "cssChunking", "optimisticClientCache"];

describe.each(["panel", "admin"])("next.config.ts of %s (gate-r8-3)", (app) => {
  it("turns on no prerendered shell, no segment cache and no other key that changes what the proxy sees", async () => {
    const config = await load(app);
    for (const key of FORBIDDEN_TOP) expect(config[key], key).toBeUndefined();
    const experimental = config.experimental ?? {};
    for (const key of FORBIDDEN_EXPERIMENTAL) expect(experimental[key], `experimental.${key}`).toBeUndefined();
  });

  it("has only the top-level and experimental keys that were reviewed", async () => {
    const config = await load(app);
    expect(Object.keys(config).sort()).toEqual(
      ["experimental", "headers", "images", "output", "outputFileTracingRoot", "poweredByHeader", "redirects", "transpilePackages", "turbopack", "webpack"].filter((k) => k in config).sort(),
    );
    // What next-intl's plugin adds on its own is its business. The one key of ours is the body limit (merge-r2-4): it bounds what Next buffers of a
    // request and touches nothing that the two points above rest on, and its value is read in the next case.
    expect(Object.keys(config.experimental ?? {}).filter((k) => !["swcPlugins", "turbo"].includes(k))).toEqual(["proxyClientMaxBodySize"]);
    expect(config.experimental?.proxyClientMaxBodySize).toBe("64kb");
  });

  // A rewrite for /_next/static/*.rsc was tried for gate-r8-1 and does not reach the request: Next has already cut the suffix when rewrites are
  // matched (measured on next start, the lowercase suffix kept its 200 flight payload), and a redirect skips /_next. So the only rules are these,
  // and the /_next/static/*.rsc answer is closed by Caddy (headersSpec.ts, gate-r8-1).
  it("has the .rsc redirect (gate-r7-2) and no other rule", async () => {
    const config = await load(app);
    expect(await (config.redirects as () => Promise<unknown>)()).toEqual([{source: "/:path(.+)\\.rsc", destination: "/:path", permanent: false}]);
    expect(config.rewrites).toBeUndefined();
  });

  // S8-r2-5: the share page of the panel is opened from a link that is a secret, and a meta tag comes too late for the first requests of the page
  // (the stylesheets, and the font that a Link header preloads). The one header rule says the policy in the response, for that path only; the admin has none.
  it("has the one header rule of the share page on the panel and no header rule on the admin", async () => {
    const config = await load(app);
    if (app === "admin") {
      expect(config.headers).toBeUndefined();
      return;
    }
    expect(await (config.headers as () => Promise<unknown>)()).toEqual([
      {
        source: "/:locale/s/:path*",
        headers: [
          {key: "Referrer-Policy", value: "no-referrer"},
          {key: "X-Robots-Tag", value: "noindex, nofollow, noarchive"},
        ],
      },
    ]);
  });
});
