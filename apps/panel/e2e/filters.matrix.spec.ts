import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {PROFILE, openProfiles, profilePath, screen, text, type Lang, type ScreensMock} from "./profiles-support.ts";

// The smoke case of the Filters screens of P2 (spec 17.1, 17.5) on all 12 projects: language, direction and theme as the project says, no
// sideways scroll (a grid of cards at 375 px is what could break it), dark text on the accent, and no serious or critical axe violation, with a
// popover and two dialogs among the cases (the spec asks for one open dialog per screen).

type Case = {
  name: string;
  path: (lang: Lang) => string;
  arrange?: (mock: ScreensMock) => void;
  ready: (page: Page, lang: Lang) => Promise<void>;
  open?: (page: Page, lang: Lang) => Promise<void>;
};

const NAME = {
  fa: {malware: "بدافزار", newDomains: "دامنه‌های تازه"},
  en: {malware: "Malware", newDomains: "New domains"},
} as const;

const firstCard = (p: Page) => screen(p, "profile-filters").getByRole("listitem").first();

const CASES: Case[] = [
  {name: "filters", path: (l) => profilePath(l, PROFILE.home, "filters"), ready: (p) => expect(firstCard(p)).toBeVisible()},
  {name: "filters-locked", path: (l) => profilePath(l, PROFILE.office, "filters"), ready: (p) => expect(firstCard(p)).toBeVisible()},
  {
    name: "filters-mode-menu",
    path: (l) => profilePath(l, PROFILE.home, "filters"),
    ready: (p) => expect(firstCard(p)).toBeVisible(),
    open: async (p, l) => {
      await p.waitForLoadState("networkidle");
      await p.getByRole("button", {name: text(l, "profiles", "filters.modeButton", {name: NAME[l].malware, mode: text(l, "profiles", "filters.modes.strict.name")})}).click();
      await expect(p.getByRole("radiogroup")).toBeVisible();
    },
  },
  {
    name: "filters-explanation",
    path: (l) => `${profilePath(l, PROFILE.home, "filters")}?helpPane=filter.new-domains`,
    ready: (p) => expect(p.getByRole("dialog")).toBeVisible(),
  },
  {
    name: "filters-new-domains-notice",
    path: (l) => profilePath(l, PROFILE.gaming, "filters"),
    ready: (p) => expect(firstCard(p)).toBeVisible(),
    open: async (p, l) => {
      await p.waitForLoadState("networkidle");
      const card = screen(p, "profile-filters").getByRole("listitem").filter({has: p.getByRole("heading", {name: NAME[l].newDomains, exact: true})});
      await card.locator(".switch__control").click();
      await expect(p.getByRole("alertdialog")).toBeVisible();
    },
  },
  {
    name: "third-party-with-warning",
    path: (l) => profilePath(l, PROFILE.home, "filters/third-party"),
    arrange: (mock) =>
      mock.screens.filters.set(PROFILE.home, [
        {filter_id: "hagezi-pro", enabled: true},
        {filter_id: "oisd-big", enabled: true},
      ]),
    ready: (p, l) => expect(p.getByTestId("many-lists")).toContainText(text(l, "profiles", "thirdParty.many.title")),
  },
];

for (const c of CASES) {
  test(`${c.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    const mock = await openProfiles(context, baseURL, {theme: matrix!.theme, rules: 200, clients: 50});
    c.arrange?.(mock);
    const response = await page.goto(c.path(matrix!.lang));
    await c.ready(page, matrix!.lang);
    await c.open?.(page, matrix!.lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `filters-${c.name}`});
  });
}
