import {meFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock, type ApiMock} from "@ctrlz/api-client/testing/mock.ts";
import type {BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {bodies} from "./account-support.ts";
import {openAnonymous} from "./auth-support.ts";

// Spec 17.3 `theme.spec.ts` (T-467, T-308), in mock mode. The first paint under the production CSP is `theme-script.spec.ts`, the two quick
// switches and the server's theme over the cookie's are in `session.spec.ts`; this file holds what they leave out: the System choice (the
// write and the cookie), an OS that changes its scheme while the mode is System, a choice that survives a reload, the raw first HTML of a
// dark cookie, and a write that the server refused.

const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;

type Mode = "light" | "dark" | "system";

async function open(context: BrowserContext, baseURL: string | undefined, theme: Mode): Promise<ApiMock> {
  await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
  return installApiMock(context, {me: meFixture({user: {theme}})});
}

const cookieOf = async (context: BrowserContext, baseURL: string | undefined) => (await context.cookies(baseURL)).find((c) => c.name === "ctrlz_theme")?.value;
const html = (page: Page) => page.locator("html");

// The logo menu: the language items first (fa, en), then Light, Dark, System.
const MODE_INDEX: Record<Mode, number> = {light: 2, dark: 3, system: 4};
async function pick(page: Page, mode: Mode) {
  await page.locator(".shell-logo-trigger").first().click();
  await page.getByRole("menuitemradio").nth(MODE_INDEX[mode]).click();
}

for (const {lang} of LANGS) {
  test.describe(`${lang}`, () => {
    test.use({viewport: {width: 1280, height: 800}, colorScheme: "light"});

    test("System: the write is {theme: system}, the cookie says system, and the page follows the OS (T-308)", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL, "dark");
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      // The account holds dark and the gate adopted it.
      await expect(html(page)).toHaveClass(/\bdark\b/);
      expect(await cookieOf(context, baseURL)).toBe("dark");

      await pick(page, "system");
      await expect.poll(() => bodies(mock, "PATCH", "/account/preferences").at(-1)).toEqual({theme: "system"});
      expect(await cookieOf(context, baseURL)).toBe("system");
      // The OS is light, so System is light, with the pair of classes that the server writes for a light page.
      await expect(html(page)).toHaveClass(/\blight\b/);
      await expect(html(page)).toHaveClass(/\bflat-light\b/);
      await expect(html(page)).not.toHaveClass(/\bdark\b/);
      await expect(html(page)).toHaveAttribute("data-theme", "light");
      await expect.poll(() => mock.state.me.user.theme).toBe("system");
    });

    test("System: when the OS changes its scheme after the load, the page follows it, both ways, with no write", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL, "system");
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect(html(page)).toHaveClass(/\bflat-light\b/);

      await page.emulateMedia({colorScheme: "dark"});
      await expect(html(page)).toHaveClass(/\bflat-dark\b/);
      await expect(html(page)).toHaveClass(/\bdark\b/);
      await expect(html(page)).not.toHaveClass(/\blight\b/);
      await expect(html(page)).toHaveAttribute("data-theme", "dark");

      await page.emulateMedia({colorScheme: "light"});
      await expect(html(page)).toHaveClass(/\bflat-light\b/);
      await expect(html(page)).not.toHaveClass(/\bdark\b/);
      // The OS moved, the account did not: nothing is written, and no cookie names a fixed theme that would stop the page following it.
      expect(mock.count("PATCH /account/preferences")).toBe(0);
      expect([undefined, "system"]).toContain(await cookieOf(context, baseURL));
    });

    test("a chosen mode ignores the OS, and a choice survives a reload with the server's first HTML already in it", async ({page, context, baseURL}) => {
      const mock = await open(context, baseURL, "system");
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await pick(page, "dark");
      await expect(html(page)).toHaveClass(/\bflat-dark\b/);
      await expect.poll(() => mock.state.me.user.theme).toBe("dark");
      // Dark is Dark whatever the OS says.
      await page.emulateMedia({colorScheme: "dark"});
      await page.emulateMedia({colorScheme: "light"});
      await expect(html(page)).toHaveClass(/\bflat-dark\b/);

      const response = await page.reload();
      const tag = /<html\b[^>]*>/.exec(await response!.text())?.[0] ?? "";
      const classes = (/\bclass="([^"]*)"/.exec(tag)?.[1] ?? "").split(/\s+/);
      expect(classes, "the first byte of the reloaded page").toEqual(expect.arrayContaining(["dark", "flat-dark"]));
      expect(tag).toContain('data-theme="dark"');
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect(html(page)).toHaveClass(/\bflat-dark\b/);
      expect(await cookieOf(context, baseURL)).toBe("dark");
    });

    test("a dark cookie: the raw first HTML has the dark classes; no cookie: the script that picks them is in the head", async ({page, context, baseURL}) => {
      // A visitor with no session: the login page is the first document that any visitor gets. Its one API call is mocked, as in every spec.
      await openAnonymous(context);
      await context.addCookies([{name: "ctrlz_theme", value: "dark", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      const dark = await page.goto(`/${lang}/login`);
      const tag = /<html\b[^>]*>/.exec(await dark!.text())?.[0] ?? "";
      expect(tag).toContain(`lang="${lang}"`);
      expect(tag).toContain('data-theme="dark"');
      const classes = (/\bclass="([^"]*)"/.exec(tag)?.[1] ?? "").split(/\s+/);
      expect(classes).toEqual(expect.arrayContaining(["dark", "flat-dark"]));
      expect(classes).not.toContain("light");
      // The OS is light and the cookie wins: the painted page is dark as well.
      await expect(html(page)).toHaveClass(/\bflat-dark\b/);

      // With no cookie the server cannot know, so it writes no class and the script before </head> picks one: it must be in the head,
      // or the first paint would be a flash of the wrong theme (spec 5.2).
      await context.clearCookies({name: "ctrlz_theme"});
      const bare = await page.goto(`/${lang}/login`);
      const raw = await bare!.text();
      expect(/<html\b[^>]*>/.exec(raw)?.[0] ?? "").not.toMatch(/\bflat-(light|dark)\b/);
      const script = raw.indexOf("prefers-color-scheme: dark");
      expect(script, "the theme script is in the first HTML").toBeGreaterThan(-1);
      expect(script, "the theme script comes before </head>").toBeLessThan(raw.indexOf("</head>"));
      await expect(html(page)).toHaveClass(/\bflat-light\b/);
    });

    test("a write the server refused: the page goes back to the saved theme and a toast says so (T-308)", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 503/);
      const mock = await open(context, baseURL, "light");
      mock.on("PATCH /account/preferences", {status: 503, body: {code: "service_unavailable"}});
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect(html(page)).toHaveClass(/\bflat-light\b/);

      await pick(page, "dark");
      // The server wins: the account holds light, so light comes back, and the person is told why.
      await expect(page.locator(".toast")).toContainText(lang === "fa" ? "ذخیره نشد" : "could not be saved");
      await expect(html(page)).toHaveClass(/\bflat-light\b/);
      await expect(html(page)).not.toHaveClass(/\bdark\b/);
      expect(await cookieOf(context, baseURL)).toBe("light");
      expect(mock.state.me.user.theme).toBe("light");
    });
  });
}
