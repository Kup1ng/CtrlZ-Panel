import type {Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import type {LibraryDefect} from "@ctrlz/ui/testing/axeLogic.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {profileFile, profileRows} from "./profiles-list-support.ts";
import {PROFILE, openProfiles, profilePath, profilesPath, text, type Handlers, type Lang} from "./profiles-support.ts";

// The smoke case of the profile list and its dialogs (spec p2 10.6, FE 17.1, 17.5) on all 12 projects (three widths, two languages, two
// themes): the page renders in the project's language, direction and theme, has no sideways scroll (a row with four counters and an Endpoint
// line at 375 px is what could break it), carries dark text on the accent, and has no serious or critical axe violation, also with one dialog
// open. Each case is one screen or one dialog.

// React Aria's live announcer, which a Button with `isPending` creates the first time a form is submitted (the same entry as auth.matrix.spec.ts and
// account.matrix.spec.ts): the library's own element, inert, and listed by the region it sits in. Only the cases that submit a form carry it.
const LIVE_ANNOUNCER: LibraryDefect = {
  rule: "role-img-alt",
  within: '[role="log"]',
  element: '[role="img"]',
  note: "React Aria live announcer: an empty role=img with a dangling aria-labelledby",
};

type Case = {
  name: string;
  path: (lang: Lang) => string;
  options?: {empty?: boolean; handlers?: Handlers};
  /** The case submits a form, so React Aria's announcer is on the page. */
  submits?: boolean;
  /** The console error this case causes on purpose (a mocked refusal). */
  refusal?: RegExp;
  /** What shows the page is ready: the screen, or the dialog that the address opened. */
  ready: (page: Page, lang: Lang) => Promise<void>;
  /** Steps that bring the page to the state under test. */
  act?: (page: Page, lang: Lang) => Promise<void>;
};

const dialog = (page: Page, lang: Lang, key: string, values: Record<string, string | number> = {}) => page.getByRole("dialog", {name: text(lang, "profiles", key, values), exact: true});
const confirmation = (page: Page, lang: Lang, name: string) => page.getByRole("alertdialog", {name: text(lang, "profiles", "dialogs.delete.title", {name})});

const CASES: Case[] = [
  {name: "profiles-list", path: (l) => profilesPath(l), ready: (p, l) => expect(profileRows(p, l)).toHaveCount(5)},
  {name: "profiles-list-empty", path: (l) => profilesPath(l), options: {empty: true}, ready: (p, l) => expect(p.getByText(text(l, "profiles", "list.empty"))).toBeVisible()},
  {name: "profile-add-dialog", path: (l) => `${profilesPath(l)}?profileDialog=add`, ready: (p, l) => expect(dialog(p, l, "dialogs.add.title")).toBeVisible()},
  {
    name: "profile-add-dialog-error",
    path: (l) => `${profilesPath(l)}?profileDialog=add`,
    ready: (p, l) => expect(dialog(p, l, "dialogs.add.title")).toBeVisible(),
    act: async (p, l) => {
      await dialog(p, l, "dialogs.add.title").getByRole("button", {name: text(l, "profiles", "dialogs.add.submit")}).click();
      await expect(dialog(p, l, "dialogs.add.title").getByRole("textbox", {name: text(l, "profiles", "dialogs.add.name")})).toHaveAttribute("aria-invalid", "true");
    },
  },
  {name: "profile-import-dialog", path: (l) => `${profilesPath(l)}?profileDialog=import`, ready: (p, l) => expect(dialog(p, l, "dialogs.import.title")).toBeVisible()},
  {
    name: "profile-import-dialog-problems",
    path: (l) => `${profilesPath(l)}?profileDialog=import`,
    options: {
      handlers: {
        "POST /profiles:import": {
          status: 422,
          body: errorBody("validation_failed", {fields: [{name: "/rules/12/pattern", code: "pattern_star_count"}, {name: "", code: "format_unknown"}]}),
        },
      },
    },
    refusal: /status of 422/,
    submits: true,
    ready: (p, l) => expect(dialog(p, l, "dialogs.import.title")).toBeVisible(),
    act: async (p, l) => {
      const d = dialog(p, l, "dialogs.import.title");
      await d.locator('input[type="file"]').setInputFiles(profileFile("Bad"));
      await d.getByRole("button", {name: text(l, "profiles", "dialogs.import.submit"), exact: true}).click();
      await expect(d.getByTestId("import-problems")).toBeVisible();
    },
  },
  {
    name: "profile-job-dialog",
    submits: true,
    path: (l) => `${profilesPath(l)}?profileDialog=import`,
    ready: (p, l) => expect(dialog(p, l, "dialogs.import.title")).toBeVisible(),
    act: async (p, l) => {
      const d = dialog(p, l, "dialogs.import.title");
      await d.locator('input[type="file"]').setInputFiles(profileFile("Huge", {pad: "x".repeat(6_000)}));
      await d.getByRole("button", {name: text(l, "profiles", "dialogs.import.submit"), exact: true}).click();
      await expect(dialog(p, l, "dialogs.job.import")).toBeVisible();
      // The import dialog is gone, not leaving: axe would read its elements in the middle of the exit.
      await expect(dialog(p, l, "dialogs.import.title")).toBeHidden();
    },
  },
  {name: "profile-duplicate-dialog", path: (l) => `${profilePath(l, PROFILE.home, "options")}?profileDialog=duplicate`, ready: (p, l) => expect(dialog(p, l, "dialogs.duplicate.title", {name: "Home"})).toBeVisible()},
  {name: "profile-delete-dialog", path: (l) => `${profilePath(l, PROFILE.gaming, "options")}?profileDialog=delete`, ready: (p, l) => expect(confirmation(p, l, "Gaming")).toBeVisible()},
  {
    name: "profile-delete-dialog-in-use",
    path: (l) => `${profilePath(l, PROFILE.home, "options")}?profileDialog=delete`,
    ready: (p, l) => expect(confirmation(p, l, "Home").getByTestId("delete-in-use")).toBeVisible(),
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
      // The page scrolls inside the shell, so the list is brought into view before the image is taken.
      const rows = page.locator('[data-screen="profiles-list"] [role="list"][aria-label]');
      if ((await rows.count()) > 0) await rows.first().scrollIntoViewIfNeeded();
      await page.screenshot({fullPage: true, path: `${process.env.E2E_SHOTS}/${c.name}-w${matrix!.width}-${matrix!.lang}-${matrix!.theme}.png`});
    }
    await expectAccessible(page, {screen: `profiles-${c.name}`, ...(c.submits ? {libraryDefects: [LIVE_ANNOUNCER]} : {})});
  });
}
