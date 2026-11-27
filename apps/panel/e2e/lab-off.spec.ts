import {existsSync, readdirSync, readFileSync, statSync} from "node:fs";
import {join, resolve} from "node:path";

import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {pageFiles, routeOf, withoutLocale} from "@ctrlz/ui/testing/routes.ts";

import {freePort, startNext, stop, waitUntilUp} from "./realServer.ts";

// gate-r4-10. The lab pages render the tenant shell with sample rows and sit outside every protected prefix, so the proxy gate never covers
// them. What keeps them out of production is one line, `if (process.env.CTRLZ_LAB !== "1") notFound()`, in the group's layout and in each
// page (spec 6.3, 8.10), and the production Compose has no such variable. Every other server of the suite has CTRLZ_LAB=1, so none of them
// can fail when that line breaks. This spec starts servers of its own, in the run's functional project:
//   - the built output has no prerendered lab page (a page that is built with the variable set, or loses `force-dynamic`, would be a file
//     that Next serves with no check at all),
//   - with the variable absent, "0" or "true", every lab page in both languages is a 404, with a cookie and without one,
//   - with "1", the same pages are served, so that the 404s above are not a server that answers nothing.
//
// The lab pages are read from the `(lab)` group of the app tree, so a page that is added to the group is covered with no edit here.
// Port: E2E_LAB_OFF_PORT when set (the run that is given a range of ports), else any free one.

const appDir = resolve(__dirname, "..");
const LAB_ROUTES = pageFiles(join(appDir, "src/app"))
  .filter((file) => file.includes("/(lab)/"))
  .map((file) => withoutLocale(routeOf(file)));

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

test.describe("the lab pages, on a real server (spec 6.3, 8.10)", () => {
  test.describe.configure({mode: "serial", timeout: 180_000});

  test("the group has pages, and the build holds none of them as a file", () => {
    expect(LAB_ROUTES.length, "the (lab) group has pages: otherwise this spec checks nothing").toBeGreaterThanOrEqual(2);
    const built = resolve(appDir, ".next");
    test.skip(!existsSync(resolve(built, "BUILD_ID")), "the app is not built here");
    const manifest = JSON.parse(readFileSync(resolve(built, "prerender-manifest.json"), "utf8")) as {routes: Record<string, unknown>; dynamicRoutes: Record<string, unknown>};
    const names = LAB_ROUTES.map((route) => route.replace(/^\//, ""));
    for (const key of [...Object.keys(manifest.routes), ...Object.keys(manifest.dynamicRoutes)]) {
      expect(names.some((name) => key.includes(name)), `${key} is a prerendered lab page: it would be served whatever CTRLZ_LAB says`).toBe(false);
    }
    const files = walk(resolve(built, "server/app")).filter((file) => /\.(html|rsc|body|segment\.rsc)$/.test(file));
    for (const file of files) {
      expect(names.some((name) => file.replaceAll("\\", "/").includes(name)), `${file} is a prerendered lab page`).toBe(false);
    }
  });

  for (const value of [undefined, "0", "true", ""]) {
    test(`CTRLZ_LAB=${JSON.stringify(value)}: every lab page is a 404, in both languages, with a cookie and without one`, async ({request}) => {
      const port = await freePort("E2E_LAB_OFF_PORT");
      const origin = `http://127.0.0.1:${port}`;
      const child = startNext(port, {CTRLZ_LAB: value});
      try {
        await waitUntilUp(origin, child);
        for (const lang of ["fa", "en"]) {
          for (const route of LAB_ROUTES) {
            for (const cookie of [undefined, "__Host-ctrlz_session=x"]) {
              const label = `/${lang}${route} ${cookie ?? "without a cookie"}`;
              const response = await request.get(`${origin}/${lang}${route}`, {headers: cookie ? {cookie} : {}, maxRedirects: 0});
              expect(response.status(), label).toBe(404);
              const body = await response.text();
              // Nothing of the page, not even its title, which Next puts into the 404 document of a matched route.
              expect(body, label).not.toMatch(/Virtual lists lab|Feedback lab|Token lab/);
              // Nor the lab catalogue in the page payload, in either language (gate-r34-3).
              expect(body, label).not.toMatch(/Proof of virtual rendering|اثبات رندر مجازی/);
            }
          }
        }
      } finally {
        stop(child);
      }
    });
  }

  test('CTRLZ_LAB="1": the same pages are served, so the 404s above mean something', async ({request}) => {
    const port = await freePort("E2E_LAB_OFF_PORT");
    const origin = `http://127.0.0.1:${port}`;
    const child = startNext(port, {CTRLZ_LAB: "1"});
    try {
      await waitUntilUp(origin, child);
      for (const lang of ["fa", "en"]) {
        for (const route of LAB_ROUTES) {
          const response = await request.get(`${origin}/${lang}${route}`, {headers: {cookie: "__Host-ctrlz_session=x"}, maxRedirects: 0});
          expect(response.status(), `/${lang}${route}`).toBe(200);
        }
      }
    } finally {
      stop(child);
    }
  });
});
