import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {allowAuthErrors, openAnonymous} from "./auth-support.ts";

// Gate round 10 (gate-r10-1), spec 5.1 and 15.4. ThemeScript is the one inline script we write, and the first paint of a visitor with
// no theme cookie (mode `system`) rests on it. The matrix projects all set the cookie, so the script returns at its first line there
// and no other case runs the branch that does the work. This one sends no cookie and no hint but the OS colour scheme, and reads the
// <html> element at the moment the parser creates <body>: after the nonce'd script has run and long before React hydrates, so the
// client hook cannot be what made the classes. The guard fails the test on any CSP violation, so the same case proves that the
// production policy let the script run (a missing or wrong nonce would leave <html> bare here).

test.beforeEach(({guard}) => allowAuthErrors(guard));
test.use({viewport: {width: 1280, height: 800}});

type Snapshot = {className: string; dataTheme: string | null};

/** Records <html> when <body> first exists. Runs from the start of every document of the page. */
const RECORD_AT_BODY = `(() => {
  const take = () => { window.__themeAtBody = {className: document.documentElement.className, dataTheme: document.documentElement.getAttribute("data-theme")}; };
  const o = new MutationObserver(() => { if (document.body) { take(); o.disconnect(); } });
  o.observe(document, {childList: true, subtree: true});
})();`;

for (const scheme of ["dark", "light"] as const) {
  test(`a first-time visitor on a ${scheme} OS gets the ${scheme} classes before <body> is parsed, with the production CSP`, async ({page, context, baseURL}) => {
    await openAnonymous(context);
    expect((await context.cookies(baseURL)).some((c) => c.name === "ctrlz_theme"), "the test sends no theme cookie").toBe(false);
    await page.emulateMedia({colorScheme: scheme});
    await page.addInitScript(RECORD_AT_BODY);
    await page.goto("/fa/login", {waitUntil: "commit"});
    await page.waitForFunction(() => (window as unknown as {__themeAtBody?: unknown}).__themeAtBody !== undefined);
    const atBody = (await page.evaluate(() => (window as unknown as {__themeAtBody: Snapshot}).__themeAtBody));
    const classes = atBody.className.split(/\s+/).filter(Boolean);
    expect(classes, "the stock class and the Flat class, added by the script").toEqual(expect.arrayContaining([scheme, `flat-${scheme}`]));
    expect(classes, "the other scheme's classes are absent").not.toEqual(expect.arrayContaining([scheme === "dark" ? "light" : "dark"]));
    expect(classes.some((c) => c === (scheme === "dark" ? "flat-light" : "flat-dark"))).toBe(false);
    expect(atBody.dataTheme).toBe(scheme);
    // The script adds classes and never replaces className, so the font class the server rendered survives it (spec 5.1).
    expect(classes.length, "more than the two theme classes: the font class is still there").toBeGreaterThan(2);
    // After hydration the page is still in the same theme.
    await expect(page.locator("html")).toHaveAttribute("data-theme", scheme);
    await expect.poll(() => page.evaluate((s) => document.documentElement.classList.contains(`flat-${s}`), scheme)).toBe(true);
  });
}

// Gate round 11 (gate-r11-1). A panel 404 is Next's own error shell (gate-r2-1): the document the server sends has no ThemeScript that runs, and
// the page is rebuilt by client recovery, where a script element that React creates never executes. A visitor with no cookie (or `system`) on a
// dark OS who typed a wrong address got a light page for good. The client now applies the system theme when it mounts and finds no theme class
// on <html>. The wait is for the recovered document (lang and dir come from the flight data), so a check on the bare shell cannot pass.
for (const scheme of ["dark", "light"] as const) {
  for (const cookie of [undefined, "system"] as const) {
    test(`an unknown address on a ${scheme} OS gets the ${scheme} theme after recovery, ${cookie ? `with ctrlz_theme=${cookie}` : "with no cookie"}`, async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 404/);
      await openAnonymous(context);
      if (cookie) await context.addCookies([{name: "ctrlz_theme", value: cookie, url: baseURL!}]);
      await page.emulateMedia({colorScheme: scheme});
      const response = await page.goto("/fa/nothing-here");
      expect(response?.status()).toBe(404);
      await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
      await expect(page.locator('meta[name="csp-nonce"]')).toHaveCount(1);
      await expect(page.locator("html")).toHaveAttribute("data-theme", scheme);
      const classes = (await page.locator("html").getAttribute("class"))!.split(/\s+/);
      expect(classes).toEqual(expect.arrayContaining([scheme, `flat-${scheme}`]));
      const other = scheme === "dark" ? "light" : "dark";
      expect(classes).not.toContain(other);
      expect(classes).not.toContain(`flat-${other}`);
      // What a person sees: the ground of the page is the theme's.
      const luminance = await page.evaluate(() => {
        const probe = document.createElement("canvas").getContext("2d")!;
        probe.fillStyle = getComputedStyle(document.body).backgroundColor;
        probe.fillRect(0, 0, 1, 1);
        const [r = 0, g = 0, b = 0] = probe.getImageData(0, 0, 1, 1).data;
        return (r * 0.2126 + g * 0.7152 + b * 0.0722) / 255;
      });
      if (scheme === "dark") expect(luminance, "a dark ground").toBeLessThan(0.3);
      else expect(luminance, "a light ground").toBeGreaterThan(0.7);
    });
  }
}

test("a 404 with a cookie that names a theme keeps that theme whatever the OS says", async ({page, context, baseURL, guard}) => {
  guard.allowConsole(/status of 404/);
  await openAnonymous(context);
  await context.addCookies([{name: "ctrlz_theme", value: "light", url: baseURL!}]);
  await page.emulateMedia({colorScheme: "dark"});
  await page.goto("/fa/nothing-here");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(await page.locator("html").getAttribute("class")).not.toContain("dark");
});

test("a cookie that names a theme is final: the script returns and the OS scheme does not override it", async ({page, context, baseURL}) => {
  await openAnonymous(context);
  await context.addCookies([{name: "ctrlz_theme", value: "light", url: baseURL!}]);
  await page.emulateMedia({colorScheme: "dark"});
  await page.addInitScript(RECORD_AT_BODY);
  await page.goto("/fa/login", {waitUntil: "commit"});
  await page.waitForFunction(() => (window as unknown as {__themeAtBody?: unknown}).__themeAtBody !== undefined);
  const atBody = await page.evaluate(() => (window as unknown as {__themeAtBody: Snapshot}).__themeAtBody);
  const classes = atBody.className.split(/\s+/);
  expect(classes).toEqual(expect.arrayContaining(["light", "flat-light"]));
  expect(classes).not.toContain("dark");
  expect(atBody.dataTheme).toBe("light");
});
