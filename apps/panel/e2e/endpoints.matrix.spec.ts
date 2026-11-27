import type {Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {screenHandlers} from "@ctrlz/api-client/testing/screenMock.ts";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {menuItem, openList, selectOf, tick} from "./endpoint-screens-support.ts";
import {ENDPOINT, GROUP, endpointsPath, endpointsText, screen, type Lang} from "./endpoints-support.ts";
import {text as profileText} from "./profiles-support.ts";

// The smoke case of the Endpoint list and each of its dialogs (spec p3 11.6, 17.1, 17.5) on all 12 projects (three widths, two languages, two
// themes): the page renders in the project's language, direction and theme, has no sideways scroll, carries dark text on the accent, and
// has no serious or critical axe violation, with one dialog open at a time.

type Case = {
  name: string;
  /** The address, or a function of the language. */
  path: (lang: Lang) => string;
  /** What the case does after the page loaded (open a menu, turn on selection), and the proof that it is ready. */
  ready: (page: Page, lang: Lang) => Promise<void>;
  options?: Parameters<typeof openList>[2];
  /** Registers a handler before the page loads. */
  prepare?: (mock: Awaited<ReturnType<typeof openList>>) => void;
};

const dialogShown = (page: Page) => expect(page.getByRole("dialog")).toBeVisible();
const dev = (lang: Lang, dialog: string, id?: string) => `${endpointsPath(lang)}?deviceDialog=${dialog}${id ? `&deviceId=${id}` : ""}`;

const CASES: Case[] = [
  {name: "list", path: endpointsPath, ready: (p) => expect(p.getByRole("link", {name: "Home router", exact: true})).toBeVisible()},
  {
    name: "list-selecting",
    path: endpointsPath,
    ready: async (p, lang) => {
      await (await menuItem(p, lang, endpointsText(lang, "list.menu.select"))).click();
      await tick(p.getByRole("checkbox", {name: endpointsText(lang, "list.row.selectAria", {name: "Laptop"})}));
      await expect(p.getByRole("toolbar")).toBeVisible();
    },
  },
  {name: "list-empty", path: endpointsPath, options: {empty: true}, ready: (p) => expect(screen(p, "endpoints-list")).toBeVisible()},
  {name: "add-dialog", path: (l) => dev(l, "add"), ready: dialogShown},
  {
    name: "add-dialog-advanced",
    path: (l) => dev(l, "add"),
    ready: async (p, lang) => {
      await p.getByRole("button", {name: endpointsText(lang, "dialogs.fields.advanced")}).click();
      await expect(p.getByRole("switch").first()).toBeVisible();
    },
  },
  {name: "edit-dialog", path: (l) => dev(l, "edit", ENDPOINT.laptop), ready: dialogShown},
  {name: "edit-dialog-pending", path: (l) => dev(l, "edit", ENDPOINT.pending), ready: dialogShown},
  {name: "edit-dialog-held", path: (l) => dev(l, "edit", ENDPOINT.held), ready: dialogShown},
  {name: "delete-dialog", path: (l) => dev(l, "delete", ENDPOINT.soft), ready: dialogShown},
  {name: "group-create-dialog", path: (l) => `${endpointsPath(l)}?endpointGroupDialog=create`, ready: dialogShown},
  {name: "group-rename-dialog", path: (l) => `${endpointsPath(l)}?endpointGroupDialog=rename:${GROUP.home}`, ready: dialogShown},
  {name: "group-delete-dialog", path: (l) => `${endpointsPath(l)}?endpointGroupDialog=delete:${GROUP.home}`, ready: dialogShown},
  {
    name: "batch-move-dialog",
    path: endpointsPath,
    ready: async (p, lang) => {
      await (await menuItem(p, lang, endpointsText(lang, "list.menu.select"))).click();
      await tick(p.getByRole("checkbox", {name: endpointsText(lang, "list.row.selectAria", {name: "Laptop"})}));
      await p.getByRole("toolbar").getByRole("button", {name: new RegExp(`^${endpointsText(lang, "list.selection.move")}`)}).click();
      await dialogShown(p);
    },
  },
  {
    name: "batch-edit-dialog",
    path: endpointsPath,
    ready: async (p, lang) => {
      await (await menuItem(p, lang, endpointsText(lang, "list.menu.select"))).click();
      await tick(p.getByRole("checkbox", {name: endpointsText(lang, "list.row.selectAria", {name: "Laptop"})}));
      await p.getByRole("toolbar").getByRole("button", {name: new RegExp(`^${endpointsText(lang, "list.selection.edit")}`)}).click();
      await dialogShown(p);
    },
  },
  {
    name: "lock-password-dialog",
    path: (l) => dev(l, "edit", ENDPOINT.office),
    ready: async (p, lang) => {
      const dialog = p.getByRole("dialog", {name: endpointsText(lang, "dialogs.edit.title", {name: "Office PC"})});
      await selectOf(dialog, endpointsText(lang, "dialogs.fields.profile")).click();
      await p.getByRole("option", {name: "Home", exact: true}).click();
      await dialog.getByRole("button", {name: endpointsText(lang, "dialogs.edit.submit"), exact: true}).click();
      await expect(p.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")})).toBeVisible();
    },
  },
  {
    name: "destinations-dialog",
    path: (l) => dev(l, "edit", ENDPOINT.laptop),
    prepare: (mock) => {
      const base = screenHandlers(mock.screens)["PATCH /endpoints/{id}"];
      mock.on("PATCH /endpoints/{id}", (call, state) =>
        (call.body as {confirm_destinations?: boolean}).confirm_destinations ? base!(call, state) : {status: 409, body: errorBody("destinations_lost")},
      );
    },
    ready: async (p, lang) => {
      const dialog = p.getByRole("dialog", {name: endpointsText(lang, "dialogs.edit.title", {name: "Laptop"})});
      await dialog.getByRole("textbox", {name: endpointsText(lang, "dialogs.fields.name")}).fill("Laptop two");
      await dialog.getByRole("button", {name: endpointsText(lang, "dialogs.edit.submit"), exact: true}).click();
      await expect(p.getByRole("dialog", {name: endpointsText(lang, "dialogs.destinations.title")})).toBeVisible();
    },
  },
];

// The 409 and the 423 and 401 of the last two cases are answers on purpose.
test.use({allowConsole: [/status of 4\d\d/]});

for (const c of CASES) {
  test(`${c.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    const mock = await openList(context, baseURL, {theme: matrix!.theme, ...c.options});
    c.prepare?.(mock);
    const response = await page.goto(c.path(matrix!.lang));
    await c.ready(page, matrix!.lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `endpoints-${c.name}`});
  });
}
