import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {PANEL_PROTECTED_PREFIXES} from "@ctrlz/ui/proxy/prefixes.ts";

import {freePort, startNext, stop, waitUntilUp} from "./realServer.ts";

// gate-r2-9. A wrong CTRLZ_VERIFY_ORIGIN makes `src/proxy.ts` throw when it loads, and the promise of spec 15.3 and 15.5 is that then every page
// answers 500 and nothing is served with a wrong or missing policy. The unit test only sees the import throw. What a server does with a proxy
// module that fails to load is Next's own handling, and a Next that turned it into a logged warning and served the pages without the proxy
// (no CSP, a nonce that the client chose, no gate) would pass every other test. So this one starts a real `next start` with a wrong value.
//
// The files of public/ are the one thing that is still served (`/logo.png`): they never run the proxy. `/icon.png` is a route of `src/app`,
// not a file, so it answers 500 like a page (gate-r2-5): a healthcheck must ask for a page, never for either of these.
//
// Port: E2E_BAD_ORIGIN_PORT when set (the run that is given a range of ports), else any free one.

const BAD = ["https://evil.example", "https://*.verify.dns.example.ir/", "*"];

test.describe("a wrong CTRLZ_VERIFY_ORIGIN, on a real server (spec 15.3, 15.5)", () => {
  test.describe.configure({mode: "serial", timeout: 180_000});

  for (const bad of BAD) {
    test(`${JSON.stringify(bad)}: every page and route of Next answers 500, and only the files of public/ are served`, async ({request}) => {
      const port = await freePort("E2E_BAD_ORIGIN_PORT");
      const origin = `http://127.0.0.1:${port}`;
      const child = startNext(port, {CTRLZ_VERIFY_ORIGIN: bad, CTRLZ_LAB: "1"});
      try {
        await waitUntilUp(origin, child);
        const gated = `/fa${PANEL_PROTECTED_PREFIXES[0]}`;
        for (const path of ["/", "/fa", "/fa/login", "/en/login", gated, "/fa/nothing-here", "/de", "/_next/static/chunks/nothing-here.js", "/icon.png", "/fa/%zz", "/api/v1/me"]) {
          for (const cookie of [undefined, "__Host-ctrlz_session=x"]) {
            const response = await request.get(`${origin}${path}`, {headers: cookie ? {cookie} : {}, maxRedirects: 0});
            const label = `${path} ${cookie ?? "without a cookie"}`;
            expect(response.status(), label).toBe(500);
            expect(response.headers()["content-type"] ?? "", `${label} is not a page`).not.toContain("text/html");
            expect(await response.text(), label).not.toMatch(/<html|<script|nonce/i);
            // A 500 that Next builds has no CSP: the point is that it is not a page, and that nothing wrong was served as one.
            expect(response.headers()["location"], label).toBeUndefined();
          }
        }
        // The one thing that stays served, and the reason a healthcheck must not ask for it.
        const logo = await request.get(`${origin}/logo.png`, {maxRedirects: 0});
        expect(logo.status()).toBe(200);
        expect(logo.headers()["content-type"]).toContain("image/png");
      } finally {
        stop(child);
      }
    });
  }
});
