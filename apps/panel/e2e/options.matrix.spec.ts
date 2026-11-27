import type {Locator, Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {PROFILE, commonWord, lockBanner, openProfiles, profilePath, screen, text, type Handlers, type Lang} from "./profiles-support.ts";

// The smoke case of Profile Options (spec p2 10.6, FE 17.1, 17.5) on all 12 projects (three widths, two languages, two themes): the page
// renders in the project's language, direction and theme, has no sideways scroll (a row with a name, a description and a three-state
// control at 375 px is what could break it), carries dark text on the accent, and has no serious or critical axe violation, also with
// one dialog or one open value. Each case is one state of the screen.

type Case = {
  name: string;
  path: (lang: Lang) => string;
  options?: {handlers?: Handlers};
  /** The console error this case causes on purpose (a mocked refusal). */
  refusal?: RegExp;
  ready: (page: Page, lang: Lang) => Promise<void>;
  act?: (page: Page, lang: Lang) => Promise<void>;
};

const row = (page: Page, name: string) => page.locator(`[data-option="${name}"]`);
const title = (lang: Lang, name: string) => text(lang, "rules", `options.rows.${name}.name`);
const press = (toggle: Locator) => toggle.locator("xpath=ancestor::*[contains(@class,'switch')][1]").locator(".switch__control").click();
const optionsReady = (p: Page) => expect(row(p, "lock")).toBeVisible();

const CASES: Case[] = [
  {name: "options", path: (l) => profilePath(l, PROFILE.home, "options"), ready: (p) => optionsReady(p)},
  {name: "options-locked", path: (l) => profilePath(l, PROFILE.office, "options"), ready: (p) => expect(lockBanner(p)).toBeVisible()},
  {name: "options-disabled-profile", path: (l) => profilePath(l, PROFILE.gaming, "options"), ready: (p) => optionsReady(p)},
  {
    name: "options-nothing-set",
    path: (l) => profilePath(l, PROFILE.travel, "options"),
    options: {handlers: {"GET /profiles/{id}/options": {status: 200, body: {default_location_unavailable: false}}}},
    ready: (p) => optionsReady(p),
  },
  {
    name: "options-error",
    path: (l) => profilePath(l, PROFILE.home, "options"),
    options: {handlers: {"GET /profiles/{id}/options": {status: 500, body: errorBody("internal")}}},
    refusal: /status of 500/,
    ready: (p) => expect(screen(p, "profile-options").getByRole("button").first()).toBeVisible(),
  },
  {
    name: "options-help-pane",
    path: (l) => `${profilePath(l, PROFILE.home, "options")}?helpPane=option.block_response`,
    ready: (p, l) => expect(p.getByRole("dialog", {name: title(l, "block_response")})).toBeVisible(),
  },
  {
    name: "options-default-rule-dialog",
    path: (l) => `${profilePath(l, PROFILE.home, "options")}?profileDialog=default-rule`,
    ready: (p, l) => expect(p.getByRole("dialog", {name: text(l, "services", "destinations.title", {subject: title(l, "default_rule")})})).toBeVisible(),
  },
  {
    name: "options-ttl-editing",
    path: (l) => profilePath(l, PROFILE.home, "options"),
    ready: (p) => optionsReady(p),
    act: async (p, l) => {
      await row(p, "block_ttl").getByRole("button", {name: text(l, "rules", "options.editAria", {name: title(l, "block_ttl")})}).click();
      await expect(row(p, "block_ttl").getByRole("textbox")).toBeVisible();
    },
  },
  {
    name: "options-block-response-custom",
    path: (l) => profilePath(l, PROFILE.home, "options"),
    ready: (p) => optionsReady(p),
    act: async (p, l) => {
      await row(p, "block_response").locator(".select__trigger").click();
      await p.getByRole("option", {name: text(l, "rules", "options.blockResponse.mode.custom")}).click();
      await expect(row(p, "block_response").getByRole("textbox")).toHaveCount(2);
    },
  },
  {
    name: "options-ecs-custom",
    path: (l) => profilePath(l, PROFILE.home, "options"),
    ready: (p) => optionsReady(p),
    act: async (p, l) => {
      await row(p, "ecs").getByRole("radio", {name: new RegExp(`^${text(l, "rules", "options.ecs.mode.custom")}`)}).click();
      await expect(row(p, "ecs").getByRole("textbox")).toHaveCount(2);
    },
  },
  {
    name: "options-ecs-problem",
    path: (l) => profilePath(l, PROFILE.home, "options"),
    ready: (p) => optionsReady(p),
    act: async (p, l) => {
      const r = row(p, "ecs");
      await r.getByRole("radio", {name: new RegExp(`^${text(l, "rules", "options.ecs.mode.custom")}`)}).click();
      await r.getByRole("textbox", {name: text(l, "rules", "options.ecs.v4")}).fill("203.0.113.7/24");
      await r.getByRole("button", {name: `${commonWord(l, "save")}: ${title(l, "ecs")}`}).click();
      await expect(r.getByRole("textbox", {name: text(l, "rules", "options.ecs.v4")})).toHaveAttribute("aria-invalid", "true");
    },
  },
  {
    name: "options-disable-custom",
    path: (l) => profilePath(l, PROFILE.home, "options"),
    ready: (p) => optionsReady(p),
    act: async (p, l) => {
      await row(p, "disable").getByRole("radio", {name: new RegExp(`^${text(l, "rules", "options.disable.choice.custom")}`)}).click();
      await expect(row(p, "disable").getByTestId("disable-picker")).toBeVisible();
    },
  },
  {
    name: "options-disable-on",
    path: (l) => profilePath(l, PROFILE.home, "options"),
    ready: (p) => optionsReady(p),
    act: async (p, l) => {
      await press(row(p, "disable").getByRole("switch", {name: title(l, "disable")}));
      await expect(row(p, "disable").getByTestId("disable-until")).toBeVisible();
    },
  },
  {
    name: "options-lock-dialog",
    path: (l) => profilePath(l, PROFILE.home, "options"),
    ready: (p) => optionsReady(p),
    act: async (p, l) => {
      await press(row(p, "lock").getByRole("switch", {name: title(l, "lock")}));
      await expect(p.getByRole("dialog", {name: text(l, "profiles", "lock.dialog.lockTitle", {name: "Home"})})).toBeVisible();
    },
  },
  {
    name: "options-unlock-dialog",
    path: (l) => profilePath(l, PROFILE.office, "options"),
    ready: (p) => expect(lockBanner(p)).toBeVisible(),
    act: async (p, l) => {
      await press(row(p, "lock").getByRole("switch", {name: title(l, "lock")}));
      await expect(p.getByRole("dialog", {name: text(l, "profiles", "lock.dialog.unlockTitle", {name: "Office"})})).toBeVisible();
    },
  },
];

for (const c of CASES) {
  test(`${c.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix, guard}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    if (c.refusal) guard.allowConsole(c.refusal);
    await openProfiles(context, baseURL, {theme: matrix!.theme, rules: 200, ...c.options});
    const response = await page.goto(c.path(matrix!.lang));
    await c.ready(page, matrix!.lang);
    await c.act?.(page, matrix!.lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    // A look at the page: `E2E_SHOTS=<folder>` saves one image per case and project, for the review of the layout (not part of a normal run).
    if (process.env.E2E_SHOTS) {
      await page.screenshot({fullPage: true, path: `${process.env.E2E_SHOTS}/${c.name}-w${matrix!.width}-${matrix!.lang}-${matrix!.theme}.png`});
    }
    await expectAccessible(page, {screen: `options-${c.name}`});
  });
}
