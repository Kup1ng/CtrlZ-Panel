import type {BrowserContext, Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {LIVE_ANNOUNCER} from "@ctrlz/ui/testing/axeLogic.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {allowAuthErrors, inviteInfoFixture, INVITE_TOKEN, openAnonymous} from "./auth-support.ts";
import {meFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";

// The smoke case of the states of spec 8.7 and 8.9 (T-468, T-478) on all 12 projects (three widths, two languages, two themes): the Not found
// screen inside the shell and outside it, a stub page of a later phase, and the fatal page. Each renders in the project's language, direction
// and theme (the fatal page, which supplies its own document, in its own two languages and colours), has no sideways scroll, carries dark text on
// the accent where the document has an accent, and has no serious or critical axe violation (17.5). `states.spec.ts` holds the behaviour of the
// states; this file is the look of them at every width and in every theme.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const NOT_FOUND = "/no/such/page";

type Screen = {
  name: string;
  path: string;
  /** The answer the screen is meant to give. */
  status?: number;
  signedIn: boolean;
  /** What shows that the screen is drawn and React owns it. */
  ready: (page: Page) => Promise<void>;
  after?: (page: Page) => Promise<void>;
};

const SCREENS: Screen[] = [
  {
    name: "not-found-in-shell",
    path: NOT_FOUND,
    status: 404,
    signedIn: true,
    ready: async (page) => {
      await expect(page.locator(".not-found .empty-state__title")).toBeVisible();
      await expect(page.locator(".shell-page")).toBeVisible();
    },
  },
  {
    name: "not-found-alone",
    path: NOT_FOUND,
    status: 404,
    signedIn: false,
    ready: async (page) => {
      await expect(page.locator(".not-found--standalone .empty-state__title")).toBeVisible();
      await expect(page.locator("aside.sidebar")).toHaveCount(0);
    },
  },
  {
    // A stub of a later phase (spec 8.9; Endpoints and Profiles are real screens now, Statistics is still the stub): the page header with its help button, and SectionEmpty with no action.
    name: "stub-statistics",
    path: "/analytics/statistics",
    signedIn: true,
    ready: async (page) => {
      await expect(page.locator(".page-header__title")).toBeVisible();
      await expect(page.locator(".empty-state__title")).toBeVisible();
    },
  },
];

// The session gate adopts the account's theme once `/me` answers (spec 5.1), so the account holds the project's, as in account.matrix.spec.ts.
async function sessionFor(screen: Screen, context: BrowserContext, baseURL: string | undefined, theme: "light" | "dark") {
  if (!screen.signedIn) {
    await openAnonymous(context);
    return;
  }
  await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
  await installApiMock(context, {me: meFixture({user: {theme}})});
}

for (const screen of SCREENS) {
  test(`${screen.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix, guard}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    if (screen.status === 404) guard.allowConsole(/status of 404/);
    await sessionFor(screen, context, baseURL, matrix!.theme);
    const response = await page.goto(`/${matrix!.lang}${screen.path}`);
    await screen.ready(page);
    await screen.after?.(page);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!, status: screen.status});
    await expectAccessible(page, {screen: `states-${screen.name}`, libraryDefects: [LIVE_ANNOUNCER]});
  });
}

// The fatal page (global-error.tsx, 8.7) replaces the whole document, with no theme, no catalogue and no stylesheet of ours, so the document
// promises of `expectMatrixPage` (a lang, a dir and a data-theme chosen by the server) do not apply to it: it is Persian over English in two
// sections, and its colours come from `light-dark()`, which follows the project's colour scheme. What is asserted instead is what it does
// promise: both languages, the ground of the project's theme, no sideways scroll at the project's width, a Try again button that fits
// and carries dark text on the accent, and no CSP violation. The crash is the one of `fatal.spec.ts`: a lookup reply that React refuses to render.
test("fatal: both languages, the ground of the theme, no overflow, accessible", async ({page, context, matrix, guard}) => {
  expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
  guard.allowConsole(/Minified React error|Objects are not valid as a React child|status of (404|500)/);
  await openAnonymous(context, {"POST /auth/invites/lookup": () => ({body: {...inviteInfoFixture(), phone_masked: {broken: true}}})});
  await page.goto(`/${matrix!.lang}/invite#${INVITE_TOKEN}`);

  const fatal = page.locator("main", {hasText: "Something went wrong"});
  await expect(fatal).toBeVisible();
  await expect(fatal).toContainText("مشکلی پیش آمد");
  await expect(fatal.locator('section[lang="fa"]')).toHaveAttribute("dir", "rtl");
  await expect(fatal.locator('section[lang="en"]')).toHaveAttribute("dir", "ltr");

  const {width, theme} = matrix!;
  expect(await page.evaluate(() => window.innerWidth)).toBe(width);
  expect(await page.evaluate(() => matchMedia("(prefers-color-scheme: dark)").matches)).toBe(theme === "dark");
  const ground = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(ground, `the ground in ${theme}`).toBe(theme === "dark" ? "rgb(10, 11, 12)" : "rgb(247, 247, 248)");
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, "horizontal page overflow in px").toBeLessThanOrEqual(0);

  // The button stays inside the screen, at least 44px high, and its text is dark on the accent.
  const retry = page.getByRole("button", {name: /تلاش دوباره \/ Try again/});
  await expect(retry).toBeVisible();
  const box = (await retry.boundingBox())!;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(width);
  expect(box.height).toBeGreaterThanOrEqual(44);
  const colours = await retry.evaluate((el) => {
    const s = getComputedStyle(el);
    return {color: s.color, background: s.backgroundColor};
  });
  expect(colours).toEqual({color: "rgb(10, 26, 34)", background: "rgb(4, 181, 251)"});

  expect(guard.consume("csp"), "a CSP violation while the fatal state is shown").toEqual([]);
  await expectAccessible(page, {screen: "states-fatal"});
});
