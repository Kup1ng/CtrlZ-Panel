import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import type {LibraryDefect} from "@ctrlz/ui/testing/axeLogic.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {configurePath, resolversPath, twoNodeView} from "./configure-support.ts";
import {ENDPOINT} from "./endpoints-support.ts";
import {openProfiles, type Lang} from "./profiles-support.ts";
import {setupText} from "./setup-support.ts";

// The smoke case of the setup dialogs (spec 17.1, 17.5; p3 11.6) on all 12 projects: each dialog renders in the project's language,
// direction and theme, has no sideways scroll at 375 (a stamp is 100 characters with no break, a row has a name, a value and a Copy), carries
// dark text on the accent, and has no serious or critical axe violation with that one dialog open.

// React Aria's live announcer, which a Button with `isPending` creates the first time it is pressed (the Create buttons of the Apple profile and of the
// setup link): the library's own element, inert, listed by the region it sits in, as account.matrix.spec.ts does.
const LIVE_ANNOUNCER: LibraryDefect = {
  rule: "role-img-alt",
  within: '[role="log"]',
  element: '[role="img"]',
  note: "React Aria live announcer: an empty role=img with a dangling aria-labelledby",
};

type Case = {
  name: string;
  path: (lang: Lang) => string;
  ready: (page: Page, lang: Lang) => Promise<void>;
  options?: {resolverNotReady?: boolean; clients?: number};
};

const dialog = (page: Page) => page.getByRole("dialog");
const t = (lang: Lang, path: string) => setupText(lang, path);

/**
 * The version picker is one line that cannot wrap, and the names of Apple TV and macOS are the longest of the fourteen platforms (S7-r2-1): the picker
 * must sit inside the dialog's body at every width, not only the page inside the viewport. Windows (short names) was the only case before.
 */
const pickerFits = (platform: string): Case => ({
  name: `configure-${platform}-version-picker`,
  path: (l) => configurePath(l, ENDPOINT.home, platform),
  ready: async (p, l) => {
    const picker = dialog(p).getByRole("radiogroup", {name: t(l, "wizard.version")});
    await expect(picker).toBeVisible();
    const fits = await picker.evaluate((el) => {
      const body = el.closest('[data-slot="modal-body"], .modal__body') ?? el.closest('[role="dialog"]')!;
      const box = el.getBoundingClientRect();
      const room = body.getBoundingClientRect();
      return {inside: box.left >= room.left - 0.5 && box.right <= room.right + 0.5, scrolls: el.scrollWidth > el.clientWidth + 1};
    });
    expect(fits, `${platform}: the version picker is inside the dialog and does not scroll`).toEqual({inside: true, scrolls: false});
  },
});

const CASES: Case[] = [
  pickerFits("apple-tv"),
  pickerFits("mac"),
  {name: "resolvers", path: (l) => resolversPath(l), ready: (p) => expect(dialog(p).getByTestId("resolver-sections")).toBeVisible()},
  {
    name: "resolvers-stamps",
    path: (l) => resolversPath(l),
    ready: async (p, l) => {
      await dialog(p).getByRole("button", {name: t(l, "resolvers.stamps.title")}).click();
      await expect(dialog(p).getByTestId("stamps-doh")).toBeVisible();
    },
  },
  {name: "resolvers-not-ready", path: (l) => resolversPath(l), ready: (p) => expect(dialog(p).getByText(/./).first()).toBeVisible(), options: {resolverNotReady: true}},
  {name: "configure-home", path: (l) => configurePath(l), ready: (p) => expect(dialog(p).getByTestId("configure-home")).toBeVisible()},
  {
    name: "configure-platforms",
    path: (l) => configurePath(l),
    ready: async (p, l) => {
      await dialog(p).getByText(t(l, "configure.entries.manual.title"), {exact: true}).click();
      await expect(dialog(p).getByTestId("platform-list")).toBeVisible();
    },
  },
  {name: "configure-automatic-generator", path: (l) => configurePath(l, ENDPOINT.home, "windows"), ready: (p) => expect(dialog(p).getByTestId("copy-block")).toBeVisible()},
  {
    name: "configure-apple-builder",
    path: (l) => configurePath(l, ENDPOINT.home, "ios"),
    ready: async (p, l) => {
      await dialog(p).getByRole("button", {name: t(l, "apple.advanced")}).click();
      await expect(dialog(p).getByRole("textbox", {name: t(l, "apple.ssids")})).toBeVisible();
    },
  },
  {
    name: "configure-apple-result",
    path: (l) => configurePath(l, ENDPOINT.home, "mac"),
    ready: async (p, l) => {
      await dialog(p).getByRole("button", {name: t(l, "apple.create")}).click();
      await expect(dialog(p).getByTestId("apple-result")).toBeVisible();
    },
  },
  {name: "wizard-step-values", path: (l) => configurePath(l, ENDPOINT.home, "windows", 3), ready: (p) => expect(dialog(p).getByTestId("wizard")).toBeVisible()},
  {name: "wizard-linux-block", path: (l) => configurePath(l, ENDPOINT.home, "linux", 2), ready: (p) => expect(dialog(p).getByTestId("copy-block")).toBeVisible()},
  {name: "wizard-verify", path: (l) => configurePath(l, ENDPOINT.home, "windows", 6), ready: (p) => expect(dialog(p).getByTestId("verify-manual")).toBeVisible()},
  {
    name: "configure-link",
    path: (l) => configurePath(l),
    ready: async (p, l) => {
      await dialog(p).getByText(t(l, "configure.entries.link.title"), {exact: true}).click();
      await dialog(p).getByRole("button", {name: t(l, "link.create")}).click();
      await expect(dialog(p).getByTestId("share-link-result")).toBeVisible();
    },
  },
];

for (const c of CASES) {
  test(`${c.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    const mock = await openProfiles(context, baseURL, {theme: matrix!.theme, ...c.options});
    if (!c.options?.resolverNotReady) mock.screens.resolver = twoNodeView();
    const response = await page.goto(c.path(matrix!.lang));
    await c.ready(page, matrix!.lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `setup-${c.name}`, libraryDefects: [LIVE_ANNOUNCER]});
  });
}
