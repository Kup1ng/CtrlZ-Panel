import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {PROFILE, openProfiles, profilePath, screen, text, type Lang} from "./profiles-support.ts";

// The smoke case of the Services screen, Choose Service and Destinations of P2 (spec 17.1, 17.5) on all 12 projects: the page and one open
// dialog or step each, in the language, direction and theme of the project, with no sideways scroll and no serious or critical axe violation.

type Case = {name: string; path: (lang: Lang) => string; ready: (page: Page, lang: Lang) => Promise<void>; open?: (page: Page, lang: Lang) => Promise<void>};

const S = (lang: Lang, path: string, values: Record<string, string | number> = {}) => text(lang, "services", path, values);
const DIGITS = "۰۱۲۳۴۵۶۷۸۹";
// The Add button of Choose Service names its count: "Add (2)", and in Persian with Persian digits.
const addName = (lang: Lang, n: number) => new RegExp(`^${lang === "fa" ? "افزودن" : "Add"} \\((?:${n}|${String(n).replace(/\d/g, (d) => DIGITS[Number(d)]!)})\\)`);
const VIDEO = {fa: "ویدیو", en: "Video"} as const;
const NEWS = {fa: "خبر", en: "News"} as const;
const cards = (p: Page) => screen(p, "profile-services").getByRole("listitem");
const chooseOpen = async (p: Page, l: Lang) => {
  await expect(p.getByRole("dialog", {name: S(l, "choose.title")})).toBeVisible();
};

const CASES: Case[] = [
  {name: "services", path: (l) => profilePath(l, PROFILE.home, "services"), ready: (p) => expect(cards(p).first()).toBeVisible()},
  {name: "services-empty", path: (l) => profilePath(l, PROFILE.gaming, "services"), ready: (p, l) => expect(p.getByText(S(l, "page.emptyTitle"))).toBeVisible()},
  {name: "services-locked", path: (l) => profilePath(l, PROFILE.office, "services"), ready: (p, l) => expect(p.getByText(S(l, "page.emptyTitle"))).toBeVisible()},
  {
    name: "choose-service",
    path: (l) => `${profilePath(l, PROFILE.home, "services")}?serviceDialog=choose`,
    ready: chooseOpen,
    open: async (p, l) => {
      await p.getByRole("button", {name: new RegExp(`^${VIDEO[l]}${l === "fa" ? "،" : ","} `)}).click();
      await expect(p.getByRole("listbox", {name: S(l, "choose.list", {category: VIDEO[l]})}).getByRole("option").first()).toBeVisible();
    },
  },
  {
    name: "choose-service-risk",
    path: (l) => `${profilePath(l, PROFILE.home, "services")}?serviceDialog=choose`,
    ready: chooseOpen,
    open: async (p, l) => {
      await p.getByRole("checkbox", {name: S(l, "choose.selectCategory", {category: NEWS[l]})}).check({force: true});
      await p.getByRole("button", {name: addName(l, 1)}).click();
      await expect(p.getByRole("dialog", {name: S(l, "risk.title")})).toBeVisible();
    },
  },
  {
    name: "choose-service-destination",
    path: (l) => `${profilePath(l, PROFILE.home, "services")}?serviceDialog=choose`,
    ready: chooseOpen,
    open: async (p, l) => {
      await p.getByRole("checkbox", {name: S(l, "choose.selectCategory", {category: NEWS[l]})}).check({force: true});
      await p.getByLabel(text(l, "rules", "three.set", {action: text(l, "rules", "action.redirect"), subject: S(l, "choose.actionSubject")}), {exact: false}).first().click();
      await expect(p.getByRole("dialog", {name: S(l, "choose.destinationTitle")})).toBeVisible();
      await expect(p.getByRole("radio").first()).toBeVisible();
    },
  },
  {
    name: "service-destination",
    path: (l) => `${profilePath(l, PROFILE.home, "services")}?serviceDialog=destination:spotify`,
    ready: (p, l) => expect(p.getByRole("dialog", {name: S(l, "destinations.title", {subject: "Spotify"})})).toBeVisible(),
  },
  {
    name: "remove-all-confirm",
    path: (l) => profilePath(l, PROFILE.home, "services"),
    ready: (p) => expect(cards(p).first()).toBeVisible(),
    open: async (p, l) => {
      await p.waitForLoadState("networkidle");
      await p.getByRole("button", {name: S(l, "category.removeAllAria", {category: VIDEO[l]})}).click();
      await expect(p.getByRole("alertdialog")).toBeVisible();
    },
  },
];

for (const c of CASES) {
  test(`${c.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    await openProfiles(context, baseURL, {theme: matrix!.theme, rules: 200, clients: 50});
    const response = await page.goto(c.path(matrix!.lang));
    await c.ready(page, matrix!.lang);
    await c.open?.(page, matrix!.lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `services-${c.name}`});
  });
}
