import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import enCommon from "../../../packages/i18n/messages/en/common.json";
import faCommon from "../../../packages/i18n/messages/fa/common.json";
import {FOLDER, PROFILE, folderPath, openProfiles, profilePath, screen, text, type Lang} from "./profiles-support.ts";

// The smoke case of the Rules screens of P2 (spec 17.1, 17.5) on all 12 projects: the list, the folder page, selection mode and each dialog, in the
// language, direction and theme of the project, with no sideways scroll and no serious or critical axe violation.

type Case = {name: string; path: (lang: Lang) => string; ready: (page: Page, lang: Lang) => Promise<void>; open?: (page: Page, lang: Lang) => Promise<void>};

const COMMON = {fa: faCommon, en: enCommon} as const;
const R = (lang: Lang, path: string, values: Record<string, string | number> = {}) => text(lang, "rules", path, values);
const home = (l: Lang) => profilePath(l, PROFILE.home, "custom-rules");
const list = (p: Page, l: Lang) => p.getByRole("list", {name: R(l, "list.listLabel", {name: "Home"})});
const listReady = async (p: Page, l: Lang) => {
  await expect(list(p, l).getByRole("listitem").first()).toBeVisible();
};
const addTag = async (p: Page, l: Lang, name: string) => {
  const box = p.getByRole("dialog").getByRole("textbox", {name: R(l, "dialog.domains")});
  await box.fill(name);
  await box.press("Enter");
};
/** The row actions that need a pointer are not drawn on a phone (below 640px): the cases that use them go by the selection bar there. */
const phone = (p: Page) => (p.viewportSize()?.width ?? 1280) < 640;
const submitName = (l: Lang) => new RegExp(`${l === "fa" ? "افزودن" : "Add"} `);

const CASES: Case[] = [
  {name: "rules", path: home, ready: listReady},
  {name: "rules-small", path: home, ready: listReady, open: async (p, l) => {
    await p.getByRole("radio", {name: R(l, "view.small")}).click();
    await expect(p.getByRole("radio", {name: R(l, "view.small")})).toBeChecked();
  }},
  {name: "rules-empty", path: (l) => profilePath(l, PROFILE.gaming, "custom-rules"), ready: (p, l) => expect(p.getByText(R(l, "list.emptyTitle"))).toBeVisible()},
  {name: "rules-locked", path: (l) => profilePath(l, PROFILE.office, "custom-rules"), ready: (p, l) => expect(p.getByText(R(l, "list.emptyTitle"))).toBeVisible()},
  {name: "rules-selecting", path: home, ready: listReady, open: async (p, l) => {
    await list(p, l).getByRole("listitem").first().getByRole("button").first().click();
    await expect(p.getByRole("toolbar", {name: COMMON[l].selection.barLabel})).toBeVisible();
  }},
  {name: "rules-delete-in-row", path: home, ready: listReady, open: async (p, l) => {
    const rule = list(p, l).getByRole("listitem").first();
    if (phone(p)) {
      // A phone has no hover: a tap selects the row and its Edit appears; Delete is in the selection bar there.
      await rule.getByRole("button").first().click();
      await expect(rule.getByRole("button", {name: new RegExp(l === "fa" ? "^ویرایش" : "^Edit")})).toBeVisible();
      return;
    }
    await rule.hover();
    await rule.getByRole("button", {name: new RegExp(l === "fa" ? "^حذف" : "^Delete")}).click();
    await expect(rule.getByRole("group")).toBeVisible();
  }},
  {name: "rule-dialog", path: (l) => `${home(l)}?ruleDialog=add-edit-rule`, ready: (p, l) => expect(p.getByRole("dialog", {name: R(l, "dialog.add")})).toBeVisible(), open: async (p, l) => {
    await addTag(p, l, "alpha.test");
    await addTag(p, l, "beta.test");
    await expect(p.getByRole("dialog").getByRole("button", {name: submitName(l)}).last()).toBeEnabled();
  }},
  {name: "rule-dialog-geo", path: (l) => `${home(l)}?ruleDialog=add-edit-rule`, ready: (p, l) => expect(p.getByRole("dialog", {name: R(l, "dialog.add")})).toBeVisible(), open: async (p, l) => {
    await p.getByRole("dialog").getByRole("button", {name: R(l, "geo.add")}).click();
    await expect(p.getByRole("dialog").getByRole("list", {name: R(l, "geo.rowsLabel")})).toBeVisible();
  }},
  {name: "rule-dialog-expiry", path: (l) => `${home(l)}?ruleDialog=add-edit-rule`, ready: (p, l) => expect(p.getByRole("dialog", {name: R(l, "dialog.add")})).toBeVisible(), open: async (p, l) => {
    await p.getByRole("dialog").getByRole("button", {name: R(l, "expiry.open", {subject: R(l, "dialog.newRule")})}).click();
    await p.getByRole("dialog").getByRole("button", {name: R(l, "expiry.pick")}).click();
    await expect(p.getByRole("dialog").getByRole("grid")).toBeVisible();
  }},
  {name: "rule-dialog-edit", path: (l) => home(l), ready: listReady, open: async (p, l) => {
    const rule = list(p, l).getByRole("listitem").first();
    if (phone(p)) await rule.getByRole("button").first().click();
    else await rule.hover();
    await rule.getByRole("button", {name: new RegExp(l === "fa" ? "^ویرایش" : "^Edit")}).click();
    await expect(p.getByRole("dialog", {name: R(l, "dialog.edit")})).toBeVisible();
  }},
  {name: "rule-dialog-redirect-warning", path: (l) => `${home(l)}?ruleDialog=add-edit-rule`, ready: (p, l) => expect(p.getByRole("dialog", {name: R(l, "dialog.add")})).toBeVisible(), open: async (p, l) => {
    await p.getByRole("dialog").getByRole("radio", {name: R(l, "three.set", {action: R(l, "action.redirect"), subject: R(l, "dialog.newRule")})}).click();
    await expect(p.getByRole("dialog", {name: R(l, "redirectWarn.title")})).toBeVisible();
  }},
  {name: "rule-dialog-destination", path: (l) => `${home(l)}?ruleDialog=add-edit-rule`, ready: (p, l) => expect(p.getByRole("dialog", {name: R(l, "dialog.add")})).toBeVisible(), open: async (p, l) => {
    await p.getByRole("dialog").getByRole("radio", {name: R(l, "three.set", {action: R(l, "action.redirect"), subject: R(l, "dialog.newRule")})}).click();
    await p.getByRole("dialog", {name: R(l, "redirectWarn.title")}).getByRole("button", {name: R(l, "redirectWarn.continue")}).click();
    await expect(p.getByRole("dialog", {name: R(l, "dialog.destinationTitle")}).getByRole("radio").first()).toBeVisible();
  }},
  {name: "folder-dialog", path: (l) => `${home(l)}?ruleDialog=folder`, ready: (p, l) => expect(p.getByRole("dialog", {name: R(l, "folderDialog.add")})).toBeVisible(), open: async (p, l) => {
    await p.getByRole("dialog").getByRole("switch", {name: R(l, "folderDialog.ruleSwitch")}).click({force: true});
    await expect(p.getByRole("dialog").getByRole("radiogroup").last()).toBeVisible();
  }},
  {name: "folder-dialog-magic", path: (l) => `${home(l)}?ruleDialog=folder`, ready: (p, l) => expect(p.getByRole("dialog", {name: R(l, "folderDialog.add")})).toBeVisible(), open: async (p, l) => {
    await p.getByRole("dialog").getByRole("radio", {name: new RegExp(R(l, "folderDialog.magic"))}).click({force: true});
    await expect(p.getByText(R(l, "folderDialog.magicNote"))).toBeVisible();
  }},
  {name: "folder-dialog-edit", path: (l) => `${home(l)}?ruleDialog=folder:${FOLDER.work}`, ready: (p, l) => expect(p.getByRole("dialog", {name: R(l, "folderDialog.edit")})).toBeVisible()},
  {name: "folder-page", path: (l) => folderPath(l, PROFILE.home, FOLDER.work), ready: (p) => expect(screen(p, "profile-folder").first()).toBeVisible(), open: async (p, l) => {
    await expect(p.getByRole("list", {name: R(l, "list.listLabel", {name: "Work"})}).getByRole("listitem").first()).toBeVisible();
  }},
  {name: "folder-page-delete", path: (l) => folderPath(l, PROFILE.home, FOLDER.work), ready: (p) => expect(screen(p, "profile-folder").first()).toBeVisible(), open: async (p, l) => {
    await p.getByRole("button", {name: R(l, "folderPage.deleteAria", {name: "Work"})}).click();
    await expect(p.getByRole("alertdialog")).toBeVisible();
  }},
  {name: "upload-dialog", path: (l) => `${folderPath(l, PROFILE.home, FOLDER.streaming)}?ruleDialog=upload`, ready: (p, l) => expect(p.getByRole("dialog", {name: R(l, "upload.title", {name: "Streaming"})})).toBeVisible(), open: async (p) => {
    await p.getByRole("dialog").locator("input[type=file]").setInputFiles({name: "rules.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify({format: "ctrlz-rules", version: 1, rules: []}))});
    await expect(p.getByRole("dialog").getByText("rules.json")).toBeVisible();
  }},
  {name: "transfer-dialog", path: home, ready: listReady, open: async (p, l) => {
    const rule = list(p, l).getByRole("listitem").first();
    if (phone(p)) {
      await rule.getByRole("button").first().click();
      await p.getByRole("toolbar", {name: COMMON[l].selection.barLabel}).getByRole("button", {name: new RegExp(`^${R(l, "batch.move")}`)}).click();
    } else {
      await rule.hover();
      await rule.getByRole("button", {name: new RegExp(l === "fa" ? "^انتقال" : "^Move")}).click();
    }
    await expect(p.getByRole("dialog").getByRole("radiogroup")).toBeVisible();
  }},
  {name: "batch-edit-dialog", path: home, ready: listReady, open: async (p, l) => {
    await list(p, l).getByRole("listitem").first().getByRole("button").first().click();
    await p.getByRole("toolbar", {name: COMMON[l].selection.barLabel}).getByRole("button", {name: new RegExp(`^${R(l, "batch.edit")}`)}).click();
    await expect(p.getByRole("dialog").getByText(R(l, "batchEdit.nothing"))).toBeVisible();
  }},
  {name: "batch-delete-confirm", path: home, ready: listReady, open: async (p, l) => {
    await list(p, l).getByRole("listitem").first().getByRole("button").first().click();
    await p.getByRole("toolbar", {name: COMMON[l].selection.barLabel}).getByRole("button", {name: new RegExp(`^${R(l, "batch.delete")}`)}).click();
    await expect(p.getByRole("alertdialog")).toBeVisible();
  }},
];

for (const c of CASES) {
  test(`${c.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    await openProfiles(context, baseURL, {theme: matrix!.theme, rules: 200});
    const response = await page.goto(c.path(matrix!.lang));
    await c.ready(page, matrix!.lang);
    await c.open?.(page, matrix!.lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `rules-${c.name}`});
  });
}
