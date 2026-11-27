import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import type {LibraryDefect} from "@ctrlz/ui/testing/axeLogic.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import data from "../../../packages/ui/src/docs/publicApi.generated.json";
import type {PublicApi} from "../../../packages/ui/src/docs/apiDocsModel.ts";
import {sharePath} from "./endpoints-support.ts";
import {openProfiles, profilesPath, screen, type Lang} from "./profiles-support.ts";
import {apiDocsPath, apiText, docsPath, openLogoMenu, shellText, statusPath, tokensPath} from "./s8-support.ts";
import {DEAD_SHARE_LINK, VALID_SHARE_LINK, setupText} from "./setup-support.ts";

// The smoke case of the screens of package S8 (spec 17.1, 17.5; p3 11.6) on all 12 projects: the share page in its three states, the API tokens
// page with each of its dialogs, the documentation, the status page, the logo menu and the feedback dialog render in the project's language,
// direction and theme, have no sideways scroll at 375, carry dark text on the accent, and have no serious or critical axe violation with that one
// dialog or menu open.

// React Aria's live announcer, which a Button with `isPending` creates the first time it is pressed: the library's own element, inert.
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
  options?: {resolverNotReady?: boolean; empty?: boolean};
  /** Cases that start the page with no tokens. */
  noTokens?: boolean;
};

const dialog = (page: Page) => page.getByRole("dialog");
const A = apiText;
const S = shellText;
const api = data as unknown as PublicApi;
const first = api.operations.find((op) => op.id === "getLimits")!;

const CASES: Case[] = [
  {name: "share-ready", path: (l) => sharePath(l, VALID_SHARE_LINK), ready: (p) => expect(p.getByTestId("share-setup")).toBeVisible()},
  {name: "share-gone", path: (l) => sharePath(l, DEAD_SHARE_LINK), ready: (p, l) => expect(screen(p, "share")).toContainText(setupText(l, "share.notFoundTitle"))},
  {name: "share-not-ready", path: (l) => sharePath(l, VALID_SHARE_LINK), ready: (p, l) => expect(screen(p, "share")).toContainText(setupText(l, "share.notReadyTitle")), options: {resolverNotReady: true}},
  {name: "tokens", path: (l) => tokensPath(l), ready: (p) => expect(p.locator("li[data-token]")).toHaveCount(4)},
  {name: "tokens-empty", path: (l) => tokensPath(l), ready: (p, l) => expect(p.getByText(A(l, "tokens.emptyTitle"))).toBeVisible(), noTokens: true},
  {
    name: "token-create",
    path: (l) => tokensPath(l),
    ready: async (p, l) => {
      await p.getByRole("button", {name: A(l, "create.open")}).first().click();
      await expect(dialog(p).getByRole("textbox", {name: A(l, "dialog.name")})).toBeVisible();
    },
  },
  {
    name: "token-value",
    path: (l) => tokensPath(l),
    ready: async (p, l) => {
      await p.getByRole("button", {name: A(l, "create.open")}).first().click();
      await dialog(p).getByRole("textbox", {name: A(l, "dialog.name")}).fill("Smoke");
      await dialog(p).getByRole("button", {name: A(l, "create.submit")}).click();
      await expect(p.getByTestId("token-value")).toBeVisible();
    },
  },
  {
    name: "token-edit",
    path: (l) => tokensPath(l),
    ready: async (p, l) => {
      await p.getByRole("button", {name: A(l, "row.edit", {name: "CI"})}).click();
      await expect(dialog(p).getByTestId("allowed-ips-field")).toBeVisible();
    },
  },
  {
    name: "token-delete",
    path: (l) => tokensPath(l),
    ready: async (p, l) => {
      await p.getByRole("button", {name: A(l, "row.delete", {name: "CI"})}).click();
      await expect(p.getByRole("alertdialog")).toBeVisible();
    },
  },
  {name: "docs", path: (l) => docsPath(l), ready: (p) => expect(p.locator("[data-docs-section]")).toHaveCount(2)},
  {
    name: "api-docs",
    path: (l) => apiDocsPath(l),
    ready: async (p) => {
      await p.getByRole("button", {name: new RegExp(`^${first.tag}\\b`)}).first().click();
      await p.getByRole("button", {name: /GET\s*\/account\/limits/}).click();
      await expect(p.locator('[data-operation="getLimits"]')).toBeVisible();
    },
  },
  {name: "status", path: (l) => statusPath(l), ready: (p, l) => expect(p.getByRole("heading", {name: A(l, "statusPage.summary.ok")})).toBeVisible()},
  {
    name: "logo-menu",
    path: (l) => profilesPath(l),
    ready: async (p, l) => {
      await openLogoMenu(p, l);
      await expect(p.getByRole("menuitem", {name: S(l, "logoMenu.docs")})).toBeVisible();
    },
  },
  {
    name: "feedback",
    path: (l) => profilesPath(l),
    ready: async (p, l) => {
      await openLogoMenu(p, l);
      await p.getByRole("menuitem", {name: S(l, "logoMenu.feature")}).click();
      await expect(dialog(p).getByTestId("feedback-body")).toBeVisible();
    },
  },
];

for (const c of CASES) {
  test(`${c.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix, guard}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    guard.allowConsole(/status of (404|409)/);
    const mock = await openProfiles(context, baseURL, {theme: matrix!.theme, ...c.options, handlers: {"POST /auth/reauth": {status: 204}}});
    if (c.noTokens) mock.screens.tokens = [];
    const response = await page.goto(c.path(matrix!.lang));
    await c.ready(page, matrix!.lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `s8-${c.name}`, libraryDefects: [LIVE_ANNOUNCER]});
  });
}
