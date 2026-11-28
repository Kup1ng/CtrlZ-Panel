import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {ENDPOINT, endpointPath, sharePath} from "./endpoints-support.ts";
import {PROFILE, lockBanner, openProfiles, profilePath, profilesPath, screen, type Lang} from "./profiles-support.ts";
import {VALID_SHARE_LINK} from "./setup-support.ts";

// The smoke case of the frames of P2 and P3 (spec 17.1, 17.5) on all 12 projects (three widths, two languages, two themes): the page
// renders in the project's language, direction and theme, has no sideways scroll (a header with a switcher, four actions and four tabs
// at 375 px is what could break it), carries dark text on the accent, and has no serious or critical axe violation.

type Case = {name: string; path: (lang: Lang) => string; ready: (page: Page) => Promise<void>};

const CASES: Case[] = [
  {name: "profile-frame", path: (l) => profilePath(l, PROFILE.home, "filters"), ready: (p) => expect(screen(p, "profile-filters")).toBeVisible()},
  {name: "profile-frame-locked", path: (l) => profilePath(l, PROFILE.office, "options"), ready: (p) => expect(lockBanner(p)).toBeVisible()},
  {name: "profile-frame-no-endpoint", path: (l) => profilePath(l, PROFILE.gaming, "services"), ready: (p) => expect(screen(p, "profile-services")).toBeVisible()},
  {name: "endpoint-frame", path: (l) => endpointPath(l, ENDPOINT.home, "clients"), ready: (p) => expect(screen(p, "endpoint-clients")).toBeVisible()},
  {name: "endpoint-frame-pending", path: (l) => endpointPath(l, ENDPOINT.pending, "ips"), ready: (p) => expect(screen(p, "endpoint-ips")).toBeVisible()},
  {name: "endpoint-frame-held", path: (l) => endpointPath(l, ENDPOINT.held, "schedule"), ready: (p) => expect(screen(p, "endpoint-schedule")).toBeVisible()},
  {name: "profiles-list-with-counters", path: (l) => profilesPath(l), ready: (p) => expect(p.locator(".onboarding")).toBeVisible()},
];

for (const c of CASES) {
  test(`${c.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    await openProfiles(context, baseURL, {theme: matrix!.theme, rules: 200, clients: 50});
    const response = await page.goto(c.path(matrix!.lang));
    await c.ready(page);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `frames-${c.name}`});
  });
}

test("share page: language, direction, theme, no overflow, accessible", async ({page, context, baseURL, matrix}) => {
  expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
  await openProfiles(context, baseURL, {theme: matrix!.theme});
  const response = await page.goto(sharePath(matrix!.lang, VALID_SHARE_LINK));
  await expect(screen(page, "share")).toBeVisible();
  await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
  await expectAccessible(page, {screen: "frames-share"});
});
