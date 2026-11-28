import type {Locator, Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {screenHandlers} from "@ctrlz/api-client/testing/screenMock.ts";
import {uid} from "@ctrlz/api-client/testing/screenFixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {readFileSync} from "node:fs";

import enJobs from "../../../packages/i18n/messages/en/jobs.json";
import faJobs from "../../../packages/i18n/messages/fa/jobs.json";
import enCommon from "../../../packages/i18n/messages/en/common.json";
import faCommon from "../../../packages/i18n/messages/fa/common.json";
import {FOLDER, LANGS, PROFILE, folderPath, lockBanner, openProfiles, profilePath, screen, text, type Lang} from "./profiles-support.ts";

// P2 package S4, Rules and folders, in mock mode (spec p2 10.6 `rules.spec.ts`, 9.6). Every case names its T row. Profile Home has the rules of
// `rulesFixture`: rules 0 to 119 are in the folder Work and the rest at the top level, every 7th is off, every 11th expires, every 13th has a comment,
// every 17th redirects, every 19th is a wildcard, every 23rd is an Iranian name (`site138.ir` is the first at the top level) and every 17th that is
// also a 29th has a destination that left the set (`example493.com`). The profile has 500 rules unless a case asks for another number.

test.use({viewport: {width: 1280, height: 800}});

const COMMON = {fa: faCommon, en: enCommon} as const;
const JOBS = {fa: faJobs, en: enJobs} as const;
const R = (lang: Lang, path: string, values: Record<string, string | number> = {}) => text(lang, "rules", path, values);
const S = (lang: Lang, path: string, values: Record<string, string | number> = {}) => text(lang, "services", path, values);
const DIGITS = "۰۱۲۳۴۵۶۷۸۹";
const num = (lang: Lang, n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => DIGITS[Number(d)]!) : String(n));
const either = (n: number) => new RegExp(`${n}|${num("fa", n)}`);
const action = (lang: Lang, a: string) => R(lang, `action.${a}`);
const COUNTRY = {fa: {germany: "آلمان", france: "فرانسه"}, en: {germany: "Germany", france: "France"}} as const;

const home = (lang: Lang) => profilePath(lang, PROFILE.home, "custom-rules");
const rulesScreen = (page: Page) => screen(page, "profile-rules");
const rulesList = (page: Page, lang: Lang) => page.getByRole("list", {name: R(lang, "list.listLabel", {name: "Home"})});
const folderList = (page: Page, lang: Lang) => page.getByRole("list", {name: R(lang, "folder.listLabel")});
const row = (page: Page, lang: Lang, pattern: string): Locator => rulesList(page, lang).getByRole("listitem").filter({hasText: pattern});
const switchOf = (page: Page, lang: Lang, pattern: string) => row(page, lang, pattern).getByRole("switch", {name: R(lang, "row.switch", {pattern})});
const dialogOf = (page: Page, lang: Lang, title: string) => page.getByRole("dialog", {name: title});
const state = (mock: Awaited<ReturnType<typeof openProfiles>>, id: string = PROFILE.home) => mock.screens.rules.get(id) ?? [];
const byKey = (mock: Awaited<ReturnType<typeof openProfiles>>, key: string, id: string = PROFILE.home) => state(mock, id).find((r) => r.key === key);
/** A control of the toolbar that is a Select: its trigger is a button named by the Select's label. */
const addButton = (lang: Lang) => new RegExp(`${lang === "fa" ? "افزودن" : "Add"} `);
const picker = (page: Page, label: string) => page.getByRole("button", {name: new RegExp(label)}).first();
const listbox = (page: Page) => page.getByRole("listbox");
/**
 * Nothing more is asked for: `read()` keeps its value for `ms`, checked every 100 ms and failing at the first change. A slow runner can only make this
 * pass later, never fail, and it names the request that should not have been sent as soon as it is sent.
 */
async function holds(read: () => number, expected: number, what: string, ms = 1500): Promise<void> {
  for (const end = Date.now() + ms; Date.now() < end; ) {
    expect(read(), what).toBe(expected);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}
const search = (page: Page, lang: Lang) => page.getByRole("searchbox", {name: R(lang, "list.searchLabel")});

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    test("T-179: the folders come first, then the low rows with the action, the A and AAAA capsules and a switch", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      await expect(rulesScreen(page)).toBeVisible();
      await expect(row(page, lang, "example120.com")).toBeVisible();
      const folders = folderList(page, lang).getByRole("listitem");
      await expect(folders).toHaveCount(4);
      await expect(folders.first()).toContainText("No logs");
      await expect(folders.last()).toContainText("Work");
      // The folders are above the rules.
      const above = await folderList(page, lang).boundingBox();
      const below = await rulesList(page, lang).boundingBox();
      expect(above!.y).toBeLessThan(below!.y);
      // A rule: its action in words, both capsules and the switch.
      const rule = row(page, lang, "example120.com");
      await expect(rule).toContainText(action(lang, "block"));
      await expect(rule).toContainText("AAAA");
      await expect(rule.getByText("A", {exact: true})).toBeVisible();
      await expect(switchOf(page, lang, "example120.com")).toBeChecked();
      // A folder says how many rules it holds.
      await expect(folders.last()).toContainText(either(120));
    });

    test("T-179: a name that acts as Bypass and a destination that left the set are marked in words, and a Redirect names where it goes", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      await search(page, lang).fill("site138");
      await expect(row(page, lang, "site138.ir")).toBeVisible();
      await expect(row(page, lang, "site138.ir")).toContainText(R(lang, "row.actsAsBypass"));
      await search(page, lang).fill("example136");
      await expect(row(page, lang, "example136.com")).toContainText(S(lang, "destinations.label.auto"));
      await search(page, lang).fill("example493");
      await expect(row(page, lang, "example493.com")).toContainText(R(lang, "row.unavailable"));
      await search(page, lang).fill("example121");
      // An expiry is a date, and an Iranian-looking name never needs it.
      await expect(row(page, lang, "example121.com")).toBeVisible();
      await expect(row(page, lang, "example121.com").locator("[data-marker=expires], [data-marker=expired]")).toBeVisible();
    });

    test("T-179: the switch writes the rule at once and keeps it after a reload", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      await expect(switchOf(page, lang, "example120.com")).toBeChecked();
      await row(page, lang, "example120.com").locator(".switch__control").click();
      await expect(switchOf(page, lang, "example120.com")).not.toBeChecked();
      await expect.poll(() => byKey(mock, "example120.com")?.enabled).toBe(false);
      await expect(row(page, lang, "example120.com")).toContainText(R(lang, "row.off"));
      await page.reload();
      await expect(switchOf(page, lang, "example120.com")).not.toBeChecked();
    });

    test("T-190: hover shows Copy, Move, Edit and Delete, and the delete is confirmed in the row", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      const rule = row(page, lang, "example122.com");
      await rule.hover();
      for (const key of ["copy", "move", "edit", "delete"]) await expect(rule.getByRole("button", {name: R(lang, `row.${key}`, {pattern: "example122.com"})})).toBeVisible();
      await rule.getByRole("button", {name: R(lang, "row.delete", {pattern: "example122.com"})}).click();
      // The question is in the row and stays when the pointer leaves.
      await expect(rule.getByRole("group", {name: R(lang, "row.confirmGroup", {pattern: "example122.com"})})).toBeVisible();
      await page.mouse.move(5, 5);
      await expect(rule.getByRole("button", {name: R(lang, "row.confirmNoAria", {pattern: "example122.com"})})).toBeFocused();
      await rule.getByRole("button", {name: R(lang, "row.confirmNoAria", {pattern: "example122.com"})}).click();
      await expect(row(page, lang, "example122.com")).toBeVisible();
      expect(byKey(mock, "example122.com")).toBeDefined();
      // Escape takes the question back too.
      await rule.hover();
      await rule.getByRole("button", {name: R(lang, "row.delete", {pattern: "example122.com"})}).click();
      await page.keyboard.press("Escape");
      await expect(rule.getByRole("group")).toHaveCount(0);
      await rule.hover();
      await rule.getByRole("button", {name: R(lang, "row.delete", {pattern: "example122.com"})}).click();
      await rule.getByRole("button", {name: R(lang, "row.confirmYesAria", {pattern: "example122.com"})}).click();
      await expect(row(page, lang, "example122.com")).toHaveCount(0);
      expect(byKey(mock, "example122.com")).toBeUndefined();
    });

    test("T-190: the actions are reached by the keyboard, in the reading order of the language", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      const rule = row(page, lang, "example122.com");
      await rule.getByRole("button").first().focus();
      // The row's own button, then Copy, Move, Edit, Delete, then the switch: the DOM order, which the direction lays out from the start.
      const order: string[] = [];
      for (let i = 0; i < 5; i++) {
        await page.keyboard.press("Tab");
        order.push((await page.evaluate(() => document.activeElement?.getAttribute("aria-label") ?? "")) || "");
      }
      expect(order.slice(0, 4)).toEqual(["copy", "move", "edit", "delete"].map((key) => R(lang, `row.${key}`, {pattern: "example122.com"})));
      expect(order[4]).toBe(R(lang, "row.switch", {pattern: "example122.com"}));
      // The actions show while one of them has the focus.
      await page.keyboard.press("Shift+Tab");
      await expect(rule.getByRole("button", {name: R(lang, "row.delete", {pattern: "example122.com"})})).toBeVisible();
    });

    test("T-190: the toolbar runs from the start of the line: in Persian from the right", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 20});
      await page.goto(home(lang));
      await search(page, lang).focus();
      const folderButton = page.getByRole("button", {name: R(lang, "list.addFolderAria", {name: "Home"})});
      const ruleButton = page.getByRole("button", {name: R(lang, "list.addAria", {name: "Home"})});
      await page.keyboard.press("Tab");
      // The search box has a clear button only when it holds text, so the next stop is the first button.
      await expect(folderButton).toBeFocused();
      await page.keyboard.press("Tab");
      await expect(ruleButton).toBeFocused();
      const a = (await folderButton.boundingBox())!;
      const b = (await ruleButton.boundingBox())!;
      if (dir === "rtl") expect(b.x).toBeLessThan(a.x);
      else expect(b.x).toBeGreaterThan(a.x);
    });

    test.describe("touch", () => {
      test.use({viewport: {width: 375, height: 812}, hasTouch: true, isMobile: true});
      test("T-190: on a touch screen a tap selects the row and its actions take the place of the tags", async ({page, context, baseURL}) => {
        await openProfiles(context, baseURL, {rules: 200});
        await page.goto(home(lang));
        const rule = row(page, lang, "example122.com");
        await expect(rule).toBeVisible();
        await expect(rule.getByRole("button", {name: R(lang, "row.edit", {pattern: "example122.com"})}).locator("..")).toHaveCSS("opacity", "0");
        await rule.getByRole("button").first().tap();
        await expect(rule).toHaveAttribute("data-selected", "true");
        await expect(rule.getByRole("button", {name: R(lang, "row.edit", {pattern: "example122.com"})}).locator("..")).toHaveCSS("opacity", "1");
        await rule.getByRole("button", {name: R(lang, "row.edit", {pattern: "example122.com"})}).tap();
        await expect(dialogOf(page, lang, R(lang, "dialog.edit"))).toBeVisible();
      });
    });

    test("T-191: a click opens selection mode, the bar counts, and Select All is a selector over the filter, not the rows that are loaded", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      await search(page, lang).fill("example1");
      // The search goes out when typing pauses, and the selection ends with the list it was made on: a click on a row of the old list would be lost with it.
      await expect.poll(() => mock.calls.some((c) => c.path === `/profiles/${PROFILE.home}/rules` && c.query.get("q") === "example1")).toBe(true);
      await expect(page.locator(".virtual-rows")).not.toHaveClass(/opacity-60/);
      await expect(rulesList(page, lang).getByRole("listitem").first()).toBeVisible();
      const matching = state(mock).filter((r) => r.key.includes("example1"));
      expect(matching.length).toBeGreaterThan(100);
      await rulesList(page, lang).getByRole("listitem").first().getByRole("button").first().click();
      const bar = page.getByRole("toolbar", {name: COMMON[lang].selection.barLabel});
      await expect(bar).toBeVisible();
      await expect(bar).toContainText(either(1));
      await bar.getByRole("button", {name: new RegExp(COMMON[lang].selection.selectAll)}).first().click();
      await expect(bar).toContainText(COMMON[lang].selection.everyMatching);
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.disable")}`)}).click();
      // Every matching rule is off, well beyond the page of 100 that was loaded; the others were not touched.
      await expect.poll(() => state(mock).filter((r) => r.key.includes("example1") && r.enabled).length).toBe(0);
      expect(state(mock).filter((r) => !r.key.includes("example1") && r.enabled).length).toBeGreaterThan(100);
      await expect(bar).toHaveCount(0);
    });

    test("T-191: ticking rows sends their ids, and one unticked after Select All leaves a smaller selection", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      const first = row(page, lang, "example120.com");
      await first.getByRole("button").first().click();
      await row(page, lang, "example122.com").getByRole("checkbox", {name: R(lang, "row.select", {pattern: "example122.com"})}).check({force: true});
      const bar = page.getByRole("toolbar", {name: COMMON[lang].selection.barLabel});
      await expect(bar).toContainText(either(2));
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.disable")}`)}).click();
      await expect.poll(() => [byKey(mock, "example120.com")?.enabled, byKey(mock, "example122.com")?.enabled]).toEqual([false, false]);
      expect(byKey(mock, "example123.com")?.enabled).toBe(true);
      // Select All, then one row out: the bar no longer claims every rule.
      await row(page, lang, "example124.com").getByRole("button").first().click();
      await bar.getByRole("button", {name: new RegExp(COMMON[lang].selection.selectAll)}).first().click();
      await expect(bar).toContainText(COMMON[lang].selection.allMatching);
      await row(page, lang, "example125.com").getByRole("checkbox", {name: R(lang, "row.select", {pattern: "example125.com"})}).uncheck({force: true});
      await expect(bar).not.toContainText(COMMON[lang].selection.allMatching);
      await expect(bar).toContainText(either(100 - 1));
    });

    test("T-191: Delete in selection mode asks first, then removes the rules", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(home(lang));
      await row(page, lang, "example120.com").getByRole("button").first().click();
      const bar = page.getByRole("toolbar", {name: COMMON[lang].selection.barLabel});
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.delete")}`)}).click();
      const confirm = page.getByRole("alertdialog");
      await expect(confirm).toBeVisible();
      await confirm.getByRole("button", {name: COMMON[lang].cancel}).click();
      expect(byKey(mock, "example120.com")).toBeDefined();
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.delete")}`)}).click();
      await confirm.getByRole("button", {name: R(lang, "batch.deleteConfirm")}).click();
      await expect.poll(() => byKey(mock, "example120.com")).toBeUndefined();
      expect(byKey(mock, "example121.com")).toBeDefined();
    });

    test("T-191: group Edit sets the action and the comment, clears the expiry, and sends only what was chosen", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(home(lang));
      await row(page, lang, "example121.com").getByRole("button").first().click();
      await row(page, lang, "example122.com").getByRole("checkbox", {name: R(lang, "row.select", {pattern: "example122.com"})}).check({force: true});
      const bar = page.getByRole("toolbar", {name: COMMON[lang].selection.barLabel});
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.edit")}`)}).click();
      const edit = page.getByRole("dialog");
      await expect(edit).toBeVisible();
      await expect(edit.getByRole("button", {name: R(lang, "batchEdit.apply")})).toBeDisabled();
      const modes = (field: string) => edit.getByRole("radiogroup", {name: R(lang, "batchEdit.modeLabel", {field})});
      await modes(R(lang, "dialog.action")).getByRole("radio", {name: R(lang, "batchEdit.set")}).click();
      await edit.getByRole("radio", {name: R(lang, "three.set", {action: action(lang, "bypass"), subject: ""}).trim(), exact: false}).first().click();
      await modes(R(lang, "dialog.expiry")).getByRole("radio", {name: R(lang, "batchEdit.clear")}).click();
      await modes(R(lang, "dialog.comment")).getByRole("radio", {name: R(lang, "batchEdit.set")}).click();
      await edit.getByRole("textbox", {name: R(lang, "dialog.comment")}).fill("checked");
      await edit.getByRole("button", {name: R(lang, "batchEdit.apply")}).click();
      await expect(edit).toBeHidden();
      await expect.poll(() => byKey(mock, "example121.com")?.action).toBe("bypass");
      expect(byKey(mock, "example121.com")).toMatchObject({comment: "checked", action: "bypass"});
      expect(byKey(mock, "example121.com")?.expires_at).toBeUndefined();
      expect(byKey(mock, "example122.com")).toMatchObject({comment: "checked", action: "bypass"});
      // A rule that was not selected is as it was.
      expect(byKey(mock, "example123.com")?.comment).toBeUndefined();
    });

    test("T-196: search, status, action and sort go to the list, and the large or small size is kept in the browser", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      await expect(row(page, lang, "example120.com")).toBeVisible();
      await search(page, lang).fill("example493");
      await expect(rulesList(page, lang).getByRole("listitem")).toHaveCount(1);
      await expect(page.getByText(R(lang, "list.searchingAll"))).toBeVisible();
      await expect(folderList(page, lang)).toHaveCount(0);
      await search(page, lang).fill("zzz-none");
      await expect(page.getByText(R(lang, "list.noMatch"))).toBeVisible();
      await search(page, lang).fill("");
      await expect(row(page, lang, "example120.com")).toBeVisible();

      await picker(page, R(lang, "filters.statusLabel")).click();
      await listbox(page).getByRole("option", {name: R(lang, "filters.disabled")}).click();
      await expect(rulesList(page, lang).getByRole("listitem").first().getByRole("switch")).not.toBeChecked();
      await expect(row(page, lang, "example120.com")).toHaveCount(0);
      await picker(page, R(lang, "filters.statusLabel")).click();
      await listbox(page).getByRole("option", {name: R(lang, "filters.allStatuses")}).click();

      await picker(page, R(lang, "filters.actionLabel")).click();
      await listbox(page).getByRole("option", {name: action(lang, "redirect")}).click();
      await expect(rulesList(page, lang).getByRole("listitem").first()).toContainText(action(lang, "redirect"));
      await expect(row(page, lang, "example120.com")).toHaveCount(0);
      await picker(page, R(lang, "filters.actionLabel")).click();
      await listbox(page).getByRole("option", {name: R(lang, "filters.allActions")}).click();

      await picker(page, R(lang, "filters.sortLabel")).click();
      await listbox(page).getByRole("option", {name: R(lang, "filters.sort.pattern")}).click();
      await expect(rulesList(page, lang).getByRole("listitem").first()).toContainText(/\*\.example|example1(00|01)/);

      // The size: Small makes the rows lower, and it is still Small after a reload.
      const large = (await rulesList(page, lang).getByRole("listitem").first().boundingBox())!.height;
      await page.getByRole("radio", {name: R(lang, "view.small")}).click();
      await expect.poll(async () => (await rulesList(page, lang).getByRole("listitem").first().boundingBox())!.height).toBeLessThan(large);
      await page.reload();
      await expect(page.getByRole("radio", {name: R(lang, "view.small")})).toBeChecked();
      void mock;
    });

    test("T-180: the rule dialog makes one rule of each domain tag, with a folder and a comment of 64 characters at most", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 20});
      await page.goto(home(lang));
      await page.getByRole("button", {name: R(lang, "list.addAria", {name: "Home"})}).click();
      await expect(page).toHaveURL(/ruleDialog=add-edit-rule/);
      const dialog = dialogOf(page, lang, R(lang, "dialog.add"));
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole("button", {name: addButton(lang)}).last()).toBeDisabled();
      const box = dialog.getByRole("textbox", {name: R(lang, "dialog.domains")});
      await box.fill("alpha.test");
      await box.press("Enter");
      await box.fill("beta.test gamma.test, delta.test");
      await expect(dialog.getByRole("list", {name: R(lang, "dialog.tagsLabel")}).getByRole("listitem")).toHaveCount(4);
      await expect(dialog.getByText(lang === "fa" ? "۴ از ۱٬۰۰۰" : "4 of 1,000")).toBeVisible();
      await dialog.getByRole("button", {name: R(lang, "dialog.removeTag", {pattern: "delta.test"})}).click();
      await expect(dialog.getByRole("list", {name: R(lang, "dialog.tagsLabel")}).getByRole("listitem")).toHaveCount(3);
      // The comment counts its characters and refuses the 65th.
      const comment = dialog.getByRole("textbox", {name: R(lang, "dialog.comment")});
      await comment.fill("x".repeat(65));
      await expect(dialog.getByText(lang === "fa" ? "۶۵ از ۶۴" : "65 of 64")).toBeVisible();
      await expect(dialog.getByRole("button", {name: addButton(lang)}).last()).toBeDisabled();
      await comment.fill("for the kids");
      // The folder is chosen from the profile's own.
      await picker(page, R(lang, "dialog.folderLabel", {name: R(lang, "dialog.newRule")})).click();
      await listbox(page).getByRole("option", {name: "Streaming"}).click();
      await dialog.getByRole("button", {name: addButton(lang)}).last().click();
      await expect(dialog).toBeHidden();
      await expect(page).not.toHaveURL(/ruleDialog/);
      for (const key of ["alpha.test", "beta.test", "gamma.test"]) expect(byKey(mock, key)).toMatchObject({action: "block", comment: "for the kids", folder_id: FOLDER.streaming, enabled: true});
      expect(byKey(mock, "delta.test")).toBeUndefined();
    });

    test("T-180: a name the API refuses is marked on its tag, with the reason in words", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 422/);
      await openProfiles(context, baseURL, {rules: 20});
      await page.goto(home(lang));
      await page.getByRole("button", {name: R(lang, "list.addAria", {name: "Home"})}).click();
      const dialog = dialogOf(page, lang, R(lang, "dialog.add"));
      const box = dialog.getByRole("textbox", {name: R(lang, "dialog.domains")});
      await box.fill("fine.test");
      await box.press("Enter");
      await box.fill("example1.com");
      await box.press("Enter");
      await dialog.getByRole("button", {name: addButton(lang)}).last().click();
      const alert = dialog.getByRole("alert").filter({hasText: "example1.com"});
      await expect(alert).toBeVisible();
      await expect(dialog).toBeVisible();
    });

    test("T-198: a rule over the profile's limit shows the capacity notice in the dialog, and nothing is written", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 422/);
      const mock = await openProfiles(context, baseURL, {rules: 20, limits: {max_rules_per_profile: 20}});
      await page.goto(`${home(lang)}?ruleDialog=add-edit-rule`);
      const dialog = dialogOf(page, lang, R(lang, "dialog.add"));
      const box = dialog.getByRole("textbox", {name: R(lang, "dialog.domains")});
      await box.fill("over.test");
      await box.press("Enter");
      await dialog.getByRole("button", {name: addButton(lang)}).last().click();
      await expect(dialog.getByText(either(20))).toBeVisible();
      await expect(dialog).toBeVisible();
      expect(byKey(mock, "over.test")).toBeUndefined();
    });

    test("T-181: a Geo Rule row is one rule, and an existing Geo Rule is edited in a row of its own", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 20});
      await page.goto(home(lang));
      await page.getByRole("button", {name: R(lang, "list.addAria", {name: "Home"})}).click();
      const dialog = dialogOf(page, lang, R(lang, "dialog.add"));
      await dialog.getByRole("button", {name: R(lang, "geo.add"), exact: true}).click();
      await expect(dialog.getByRole("list", {name: R(lang, "geo.rowsLabel")}).getByRole("listitem")).toHaveCount(1);
      // The row is not complete until it has a country: Add stays off.
      await expect(dialog.getByRole("button", {name: addButton(lang)}).last()).toBeDisabled();
      await dialog.getByRole("combobox", {name: R(lang, "geo.countryLabel", {number: 1})}).fill(COUNTRY[lang].germany);
      await page.getByRole("option", {name: COUNTRY[lang].germany, exact: true}).click();
      await dialog.getByRole("button", {name: R(lang, "geo.add"), exact: true}).click();
      await picker(page, R(lang, "geo.formLabel", {number: 2})).click();
      await listbox(page).getByRole("option", {name: R(lang, "geo.form.srcNot")}).click();
      await dialog.getByRole("combobox", {name: R(lang, "geo.countryLabel", {number: 2})}).fill(COUNTRY[lang].france);
      await page.getByRole("option", {name: COUNTRY[lang].france, exact: true}).click();
      await dialog.getByRole("button", {name: addButton(lang)}).last().click();
      await expect(dialog).toBeHidden();
      expect(byKey(mock, "@DE")).toMatchObject({match_kind: "dest_cc", negated: false});
      expect(byKey(mock, "!#FR")).toMatchObject({match_kind: "src_cc", negated: true});
      // The list says each in a sentence with the country's name, and Edit opens the same row.
      const geo = rulesList(page, lang).getByRole("listitem").filter({hasText: COUNTRY[lang].germany});
      await expect(geo).toBeVisible();
      await geo.hover();
      await geo.getByRole("button", {name: new RegExp(lang === "fa" ? "ویرایش" : "Edit")}).click();
      const edit = dialogOf(page, lang, R(lang, "dialog.edit"));
      await expect(edit.getByRole("combobox", {name: R(lang, "geo.countryLabel", {number: 1})})).toHaveValue(COUNTRY[lang].germany);
      await edit.getByRole("combobox", {name: R(lang, "geo.countryLabel", {number: 1})}).fill(COUNTRY[lang].france);
      await page.getByRole("option", {name: COUNTRY[lang].france, exact: true}).click();
      await edit.getByRole("button", {name: COMMON[lang].save}).click();
      await expect(edit).toBeHidden();
      await expect.poll(() => state(mock).some((r) => r.pattern === "@FR")).toBe(true);
    });

    test("T-184: the clock opens four shortcuts and a calendar with the time, in the language's calendar", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 20});
      await page.goto(`${home(lang)}?ruleDialog=add-edit-rule`);
      const dialog = dialogOf(page, lang, R(lang, "dialog.add"));
      const box = dialog.getByRole("textbox", {name: R(lang, "dialog.domains")});
      await box.fill("timed.test");
      await box.press("Enter");
      await dialog.getByRole("button", {name: R(lang, "expiry.open", {subject: R(lang, "dialog.newRule")})}).click();
      const shortcuts = dialog.getByRole("group", {name: R(lang, "expiry.shortcutsLabel")});
      for (const s of ["in1h", "in1d", "in1w", "in1m"]) await expect(shortcuts.getByRole("button", {name: R(lang, `expiry.${s}`)})).toBeVisible();
      await shortcuts.getByRole("button", {name: R(lang, "expiry.pick")}).click();
      // The month grid is Jalali in Persian, with the year in Persian digits.
      const year = dialog.locator("[data-slot='calendar-year-picker-trigger-heading'], .calendar__year-picker-trigger-heading").first();
      const heading = (await year.textContent()) ?? "";
      if (lang === "fa") expect(heading).toMatch(/[۰-۹]{4}/);
      else expect(heading).toMatch(/20\d\d/);
      await expect(dialog.getByRole("grid")).toBeVisible();
      await dialog.getByRole("gridcell").filter({hasNot: page.locator("[data-disabled]")}).last().click();
      await dialog.getByRole("button", {name: COMMON[lang].calendar.apply}).click();
      await expect(dialog.getByText(lang === "fa" ? /^تا / : /^Until /)).toBeVisible();
      await dialog.getByRole("button", {name: addButton(lang)}).last().click();
      await expect(dialog).toBeHidden();
      const made = byKey(mock, "timed.test");
      expect(Date.parse(made!.expires_at!)).toBeGreaterThan(Date.now());
    });

    test("T-184: a shortcut is sent as expires_in, and Remove clears an expiry on an edit", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(home(lang));
      await search(page, lang).fill("example121");
      // The search goes out when typing pauses (S4-r1-2) and the row moves to the top of the new list: the pointer is put on it after that, or it rests on empty space.
      await expect(rulesList(page, lang).getByRole("listitem")).toHaveCount(1);
      const rule = row(page, lang, "example121.com");
      await rule.hover();
      await rule.getByRole("button", {name: R(lang, "row.edit", {pattern: "example121.com"})}).click();
      const dialog = dialogOf(page, lang, R(lang, "dialog.edit"));
      await expect(dialog.getByText(lang === "fa" ? /^تا / : /^Until /)).toBeVisible();
      await dialog.getByRole("button", {name: R(lang, "expiry.clear", {subject: "example121.com"})}).click();
      await dialog.getByRole("button", {name: COMMON[lang].save}).click();
      await expect(dialog).toBeHidden();
      await expect.poll(() => byKey(mock, "example121.com")?.expires_at).toBeUndefined();
    });

    test("T-197: the first Redirect a person chooses shows a warning once, then asks for its destination", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 20});
      await page.goto(`${home(lang)}?ruleDialog=add-edit-rule`);
      const dialog = dialogOf(page, lang, R(lang, "dialog.add"));
      const box = dialog.getByRole("textbox", {name: R(lang, "dialog.domains")});
      await box.fill("proxied.test");
      await box.press("Enter");
      await dialog.getByRole("radio", {name: R(lang, "three.set", {action: action(lang, "redirect"), subject: R(lang, "dialog.newRule")})}).click();
      const warning = dialogOf(page, lang, R(lang, "redirectWarn.title"));
      await expect(warning).toBeVisible();
      await warning.getByRole("button", {name: R(lang, "redirectWarn.continue")}).click();
      const where = dialogOf(page, lang, R(lang, "dialog.destinationTitle"));
      await expect(where).toBeVisible();
      await where.getByRole("radio", {name: S(lang, "destinations.auto")}).click({force: true});
      await where.getByRole("button", {name: R(lang, "dialog.destinationDone")}).click();
      await dialog.getByRole("button", {name: addButton(lang)}).last().click();
      await expect(dialog).toBeHidden();
      expect(byKey(mock, "proxied.test")).toMatchObject({action: "redirect", target: {kind: "auto"}});
      // The second time there is no warning: it goes to the destination at once.
      await page.getByRole("button", {name: R(lang, "list.addAria", {name: "Home"})}).click();
      const again = dialogOf(page, lang, R(lang, "dialog.add"));
      await again.getByRole("radio", {name: R(lang, "three.set", {action: action(lang, "redirect"), subject: R(lang, "dialog.newRule")})}).click();
      await expect(dialogOf(page, lang, R(lang, "dialog.destinationTitle"))).toBeVisible();
      await expect(page.getByRole("dialog", {name: R(lang, "redirectWarn.title")})).toHaveCount(0);
    });

    test("T-186: a Standard folder has the Folder Rule switch that shows its action, and a Magic folder has only Do Not Log", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 20});
      await page.goto(home(lang));
      await page.getByRole("button", {name: R(lang, "list.addFolderAria", {name: "Home"})}).click();
      await expect(page).toHaveURL(/ruleDialog=folder/);
      const dialog = dialogOf(page, lang, R(lang, "folderDialog.add"));
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole("radio", {name: new RegExp(R(lang, "folderDialog.standard"))})).toBeChecked();
      await expect(dialog.getByRole("radiogroup", {name: new RegExp(R(lang, "three.group", {subject: ".*"}).replace(/\{.*/, ""))})).toHaveCount(0);
      await dialog.getByRole("switch", {name: R(lang, "folderDialog.ruleSwitch")}).click({force: true});
      await expect(dialog.getByRole("radio", {name: R(lang, "three.set", {action: action(lang, "bypass"), subject: R(lang, "folderDialog.newFolder")}), exact: false})).toBeVisible();
      // Bypass is not offered on a Magic folder, nor any action.
      await dialog.getByRole("radio", {name: new RegExp(R(lang, "folderDialog.magic"))}).click({force: true});
      await expect(dialog.getByRole("switch")).toHaveCount(0);
      await expect(dialog.getByText(R(lang, "folderDialog.magicNote"))).toBeVisible();
      await dialog.getByRole("textbox", {name: R(lang, "folderDialog.name")}).fill("Hidden things");
      await dialog.getByRole("button", {name: COMMON[lang].create}).click();
      await expect(dialog).toBeHidden();
      expect((mock.screens.folders.get(PROFILE.home) ?? []).find((f) => f.name === "Hidden things")).toMatchObject({kind: "do_not_log"});
      await expect(folderList(page, lang).getByRole("listitem").filter({hasText: "Hidden things"})).toContainText(R(lang, "folder.magicTag"));
    });

    test("T-189: the folder name is under 32 characters, and a Folder Rule is written with its action", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 20});
      await page.goto(`${home(lang)}?ruleDialog=folder`);
      const dialog = dialogOf(page, lang, R(lang, "folderDialog.add"));
      const name = dialog.getByRole("textbox", {name: R(lang, "folderDialog.name")});
      await name.fill("x".repeat(32));
      await expect(dialog.getByRole("button", {name: COMMON[lang].create})).toBeDisabled();
      await name.fill("y".repeat(31));
      await expect(dialog.getByRole("button", {name: COMMON[lang].create})).toBeEnabled();
      await name.fill("Gaming sites");
      await dialog.getByRole("switch", {name: R(lang, "folderDialog.ruleSwitch")}).click({force: true});
      await dialog.getByRole("radio", {name: R(lang, "three.set", {action: action(lang, "bypass"), subject: "Gaming sites"})}).click();
      await dialog.getByRole("button", {name: COMMON[lang].create}).click();
      await expect(dialog).toBeHidden();
      expect((mock.screens.folders.get(PROFILE.home) ?? []).find((f) => f.name === "Gaming sites")).toMatchObject({kind: "standard", action: "bypass"});
    });

    test("T-189: Edit renames a folder and takes its Folder Rule away, unless a rule follows it", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 422/);
      const mock = await openProfiles(context, baseURL, {rules: 20});
      await page.goto(home(lang));
      const streaming = folderList(page, lang).getByRole("listitem").filter({hasText: "Streaming"});
      await streaming.hover();
      await streaming.getByRole("button", {name: R(lang, "folder.edit", {name: "Streaming"})}).click();
      const dialog = dialogOf(page, lang, R(lang, "folderDialog.edit"));
      await expect(dialog.getByRole("radio", {name: new RegExp(R(lang, "folderDialog.magic"))})).toBeDisabled();
      await dialog.getByRole("textbox", {name: R(lang, "folderDialog.name")}).fill("Video");
      await dialog.getByRole("switch", {name: R(lang, "folderDialog.ruleSwitch")}).click({force: true});
      await dialog.getByRole("button", {name: COMMON[lang].save}).click();
      await expect(dialog).toBeHidden();
      expect((mock.screens.folders.get(PROFILE.home) ?? []).find((f) => f.id === FOLDER.streaming)).toMatchObject({name: "Video"});
      expect((mock.screens.folders.get(PROFILE.home) ?? []).find((f) => f.id === FOLDER.streaming)?.action).toBeUndefined();
    });

    test("T-188: the folder page has back, the count, edit, Export Rules, Upload Folder and a delete that asks first", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(home(lang));
      await folderList(page, lang).getByRole("listitem").filter({hasText: "Work"}).getByRole("link").first().click();
      await expect(page).toHaveURL(new RegExp(`custom-rules/${FOLDER.work}`));
      const folder = screen(page, "profile-folder");
      await expect(folder.first()).toBeVisible();
      await expect(page.getByRole("heading", {name: new RegExp("Work")})).toContainText(either(120));
      await expect(page.getByRole("link", {name: R(lang, "folderPage.back")})).toBeVisible();
      await expect(page.getByRole("list", {name: R(lang, "list.listLabel", {name: "Work"})}).getByRole("listitem").first()).toBeVisible();
      // Export Rules saves the folder's document.
      const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", {name: R(lang, "folderPage.exportAria", {name: "Work"})}).click()]);
      expect(download.suggestedFilename()).toMatch(/\.json$/);
      const doc = JSON.parse(readFileSync((await download.path())!, "utf8")) as {format: string; version: number; rules: {pattern: string}[]};
      expect(doc).toMatchObject({format: "ctrlz-rules", version: 1});
      expect(doc.rules.length).toBe(120);
      // Delete asks, and takes the folder with its rules back to the list.
      await page.getByRole("button", {name: R(lang, "folderPage.deleteAria", {name: "Work"})}).click();
      const confirm = page.getByRole("alertdialog");
      await expect(confirm).toBeVisible();
      await confirm.getByRole("button", {name: COMMON[lang].cancel}).click();
      expect((mock.screens.folders.get(PROFILE.home) ?? []).length).toBe(4);
      await page.getByRole("button", {name: R(lang, "folderPage.deleteAria", {name: "Work"})}).click();
      // The refreshed folder list no longer has the folder: the page must not show its 404 on the way back (S4-r1-5).
      await page.evaluate(() => {
        const w = window as unknown as {__notFound: boolean};
        w.__notFound = false;
        new MutationObserver(() => {
          if (document.querySelector(".not-found")) w.__notFound = true;
        }).observe(document.body, {childList: true, subtree: true});
      });
      await confirm.getByRole("button", {name: R(lang, "folderPage.deleteConfirm")}).click();
      await expect(page).toHaveURL(/custom-rules$/);
      expect(await page.evaluate(() => (window as unknown as {__notFound: boolean}).__notFound), "404 shown after the delete").toBe(false);
      expect((mock.screens.folders.get(PROFILE.home) ?? []).some((f) => f.id === FOLDER.work)).toBe(false);
      expect(state(mock).some((r) => r.folder_id === FOLDER.work)).toBe(false);
    });

    test("T-188: a folder that is not in the profile, or an id that is not one, is a page that does not exist", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 20});
      await page.goto(folderPath(lang, PROFILE.home, FOLDER.unknown));
      await expect(page.locator(".not-found")).toBeVisible();
      await expect(screen(page, "profile-folder")).toHaveCount(0);
      await page.goto(folderPath(lang, PROFILE.home, "not-an-id"));
      await expect(screen(page, "profile-folder")).toHaveCount(0);
    });

    test("T-195: Upload Folder takes a file and a mode, and says what was created, updated and left", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(`${folderPath(lang, PROFILE.home, FOLDER.streaming)}?ruleDialog=upload`);
      const dialog = dialogOf(page, lang, R(lang, "upload.title", {name: "Streaming"}));
      await expect(dialog).toBeVisible();
      const body = {format: "ctrlz-rules", version: 1, rules: [{pattern: "up-one.test", action: "block"}, {pattern: "up-two.test", action: "bypass", comment: "from file"}, {pattern: "example150.com", action: "block"}]};
      await dialog.locator("input[type=file]").setInputFiles({name: "rules.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(body))});
      await expect(dialog.getByText("rules.json")).toBeVisible();
      await expect(dialog.getByRole("radio", {name: new RegExp(R(lang, "upload.newOnly"))})).toBeChecked();
      await dialog.getByRole("button", {name: R(lang, "upload.do"), exact: true}).click();
      await expect(dialog.getByText(R(lang, "upload.done"))).toBeVisible();
      // example150.com lives at the top level, so it is a conflict, and the two others are created in the folder.
      await expect(dialog.getByRole("listitem")).toHaveCount(2);
      expect(byKey(mock, "up-one.test")).toMatchObject({folder_id: FOLDER.streaming});
      expect(byKey(mock, "up-two.test")).toMatchObject({folder_id: FOLDER.streaming, comment: "from file"});
      expect(byKey(mock, "example150.com")?.folder_id).toBeUndefined();
      await dialog.getByRole("button", {name: COMMON[lang].done}).click();
      await expect(dialog).toBeHidden();
      await expect(page.getByRole("list", {name: R(lang, "list.listLabel", {name: "Streaming"})}).getByRole("listitem")).toHaveCount(2);
    });

    test("T-195: a file that is not a rules file is refused with the place that is wrong, and a large one is a job", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 422/);
      const mock = await openProfiles(context, baseURL, {rules: 20});
      await page.goto(`${folderPath(lang, PROFILE.home, FOLDER.streaming)}?ruleDialog=upload`);
      const dialog = dialogOf(page, lang, R(lang, "upload.title", {name: "Streaming"}));
      await dialog.locator("input[type=file]").setInputFiles({name: "bad.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify({format: "ctrlz-rules", version: 1, rules: [{pattern: "fine.test", action: "block"}, {pattern: "not a name", action: "block"}]}))});
      await dialog.getByRole("button", {name: R(lang, "upload.do"), exact: true}).click();
      const problems = dialog.getByRole("list", {name: R(lang, "upload.problems")});
      await expect(problems).toContainText("/rules/1/pattern");
      expect(byKey(mock, "fine.test")).toBeUndefined();
      // More than a thousand rules is queued on the server, and the job dialog follows it to its end.
      const many = {format: "ctrlz-rules", version: 1, rules: Array.from({length: 1200}, (_, i) => ({pattern: `bulk${i}.test`, action: "block"}))};
      await dialog.locator("input[type=file]").setInputFiles({name: "many.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(many))});
      await dialog.getByRole("button", {name: R(lang, "upload.do"), exact: true}).click();
      const job = page.getByRole("dialog").filter({has: page.getByRole("status", {name: JOBS[lang].progressLabel})});
      await expect(job).toBeVisible();
      await expect(job.getByText(JOBS[lang].state.done).first()).toBeVisible({timeout: 15_000});
    });

    test("T-189: Copy sends a rule to another profile, and Move changes its folder or makes a new folder for it", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(home(lang));
      // Copy to Travel.
      let rule = row(page, lang, "example122.com");
      await rule.hover();
      await rule.getByRole("button", {name: R(lang, "row.copy", {pattern: "example122.com"})}).click();
      let dialog = dialogOf(page, lang, R(lang, "transfer.copyTitle", {subject: "example122.com"}));
      await expect(dialog).toBeVisible();
      await picker(page, R(lang, "transfer.profileLabel", {subject: "example122.com"})).click();
      await listbox(page).getByRole("option", {name: "Travel"}).click();
      await dialog.getByRole("button", {name: R(lang, "transfer.copyDo")}).click();
      await expect(dialog).toBeHidden();
      expect(state(mock, PROFILE.travel).some((r) => r.key === "example122.com")).toBe(true);
      expect(byKey(mock, "example122.com")).toBeDefined();
      // Move into the folder Streaming.
      rule = row(page, lang, "example123.com");
      await rule.hover();
      await rule.getByRole("button", {name: R(lang, "row.move", {pattern: "example123.com"})}).click();
      dialog = dialogOf(page, lang, R(lang, "transfer.moveTitle", {subject: "example123.com"}));
      await dialog.getByRole("radio", {name: R(lang, "transfer.folder")}).click({force: true});
      await picker(page, R(lang, "transfer.folderLabel", {subject: "example123.com"})).click();
      await listbox(page).getByRole("option", {name: "Streaming"}).click();
      await dialog.getByRole("button", {name: R(lang, "transfer.moveDo")}).click();
      await expect(dialog).toBeHidden();
      await expect.poll(() => byKey(mock, "example123.com")?.folder_id).toBe(FOLDER.streaming);
      await expect(row(page, lang, "example123.com")).toHaveCount(0);
      // Create Folder and Add Rules.
      rule = row(page, lang, "example124.com");
      await rule.hover();
      await rule.getByRole("button", {name: R(lang, "row.move", {pattern: "example124.com"})}).click();
      dialog = dialogOf(page, lang, R(lang, "transfer.moveTitle", {subject: "example124.com"}));
      await dialog.getByRole("radio", {name: R(lang, "transfer.createFolder")}).click({force: true});
      await dialog.getByRole("textbox", {name: R(lang, "transfer.newName")}).fill("x".repeat(32));
      await expect(dialog.getByRole("button", {name: R(lang, "transfer.moveDo")})).toBeDisabled();
      await dialog.getByRole("textbox", {name: R(lang, "transfer.newName")}).fill("Fresh folder");
      await dialog.getByRole("button", {name: R(lang, "transfer.moveDo")}).click();
      await expect(dialog).toBeHidden();
      const fresh = (mock.screens.folders.get(PROFILE.home) ?? []).find((f) => f.name === "Fresh folder");
      expect(fresh).toBeDefined();
      expect(byKey(mock, "example124.com")?.folder_id).toBe(fresh!.id);
    });

    test("T-193: a Copy to a locked profile is refused again by the API, and the dialog says so", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 423/);
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(home(lang));
      const rule = row(page, lang, "example122.com");
      await rule.hover();
      await rule.getByRole("button", {name: R(lang, "row.copy", {pattern: "example122.com"})}).click();
      const dialog = dialogOf(page, lang, R(lang, "transfer.copyTitle", {subject: "example122.com"}));
      await picker(page, R(lang, "transfer.profileLabel", {subject: "example122.com"})).click();
      await listbox(page).getByRole("option", {name: "Office"}).click();
      await expect(dialog.getByText(R(lang, "transfer.locked", {name: "Office"}))).toBeVisible();
      await dialog.getByRole("button", {name: R(lang, "transfer.copyDo")}).click();
      await expect(dialog.getByRole("alert")).toBeVisible();
      await expect(dialog).toBeVisible();
      expect(state(mock, PROFILE.office).length).toBe(0);
    });

    test("T-191: Copy and Move from selection mode work on the selection", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(home(lang));
      await row(page, lang, "example122.com").getByRole("button").first().click();
      await row(page, lang, "example123.com").getByRole("checkbox", {name: R(lang, "row.select", {pattern: "example123.com"})}).check({force: true});
      const bar = page.getByRole("toolbar", {name: COMMON[lang].selection.barLabel});
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.move")}`)}).click();
      const dialog = page.getByRole("dialog").filter({has: page.getByRole("radiogroup")});
      await dialog.getByRole("radio", {name: R(lang, "transfer.folder")}).click({force: true});
      await dialog.getByRole("button", {name: new RegExp(R(lang, "transfer.folderLabel", {subject: ""}).trim().replace(/ .*/, ""))}).click();
      await listbox(page).getByRole("option", {name: "Work"}).click();
      await dialog.getByRole("button", {name: R(lang, "transfer.moveDo")}).click();
      await expect(dialog).toBeHidden();
      await expect.poll(() => [byKey(mock, "example122.com")?.folder_id, byKey(mock, "example123.com")?.folder_id]).toEqual([FOLDER.work, FOLDER.work]);
      await expect(bar).toHaveCount(0);
    });

    test("T-192: a batch of more than 1,000 rules is a job that the dialog follows, and a second one while it runs resumes the first", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 409/);
      const mock = await openProfiles(context, baseURL, {rules: 1500});
      await page.goto(home(lang));
      await expect(rulesList(page, lang).getByRole("listitem").first()).toBeVisible();
      await rulesList(page, lang).getByRole("listitem").first().getByRole("button").first().click();
      const bar = page.getByRole("toolbar", {name: COMMON[lang].selection.barLabel});
      await bar.getByRole("button", {name: new RegExp(COMMON[lang].selection.selectAll)}).first().click();
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.disable")}`)}).click();
      const job = page.getByRole("dialog").filter({has: page.getByRole("status", {name: JOBS[lang].progressLabel})});
      await expect(job).toBeVisible();
      await expect(job.getByText(JOBS[lang].state.done).first()).toBeVisible({timeout: 15_000});
      await job.getByRole("button", {name: lang === "fa" ? "بستن" : "Close"}).first().click();
      await expect.poll(() => state(mock).filter((r) => !r.folder_id && r.enabled).length).toBe(0);
      // A job that runs when a second batch is asked: the 409 opens the dialog on the running job.
      mock.screens.job = {id: uid("jb", 777), kind: "rules_batch", state: "running", progress: 0, total: 1500, profile_id: PROFILE.home};
      mock.screens.jobReads = 1;
      await page.reload();
      await rulesList(page, lang).getByRole("listitem").first().getByRole("button").first().click();
      await bar.getByRole("button", {name: new RegExp(COMMON[lang].selection.selectAll)}).first().click();
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.enable")}`)}).click();
      await expect(page.getByRole("dialog").getByText(JOBS[lang].dialog.resumeTitle)).toBeVisible();
    });

    test("T-140: a locked profile shows the rules and disables every write, but Copy stays", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 20});
      mock.screens.rules.set(PROFILE.office, mock.screens.rules.get(PROFILE.home)!.slice(0, 5).map((r, i) => ({...r, id: uid("ru", 900 + i), folder_id: undefined})));
      await page.goto(profilePath(lang, PROFILE.office, "custom-rules"));
      await expect(lockBanner(page)).toBeVisible();
      const list = page.getByRole("list", {name: R(lang, "list.listLabel", {name: "Office"})});
      await expect(list.getByRole("listitem").first()).toBeVisible();
      await expect(page.getByRole("button", {name: R(lang, "list.addAria", {name: "Office"})})).toBeDisabled();
      await expect(list.getByRole("switch").first()).toBeDisabled();
      await list.getByRole("listitem").first().hover();
      await expect(list.getByRole("button", {name: new RegExp(lang === "fa" ? "ویرایش" : "Edit")})).toHaveCount(0);
      await expect(list.getByRole("button", {name: new RegExp(lang === "fa" ? "کپی" : "Copy")}).first()).toBeVisible();
    });

    test("S4-r1-1: an edit by address that meets a failed look-up page says so, asks once, and goes on only at Retry", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 429/);
      const mock = await openProfiles(context, baseURL, {rules: 500});
      const base = screenHandlers(mock.screens)["GET /profiles/{id}/rules"]!;
      let failing = true;
      // The look-up walks the list of every rule (no folder in the query) by cursor, so only its pages after the first fail.
      const lookupPage = (c: {query: URLSearchParams}) => !c.query.has("folder") && c.query.has("cursor");
      mock.on("GET /profiles/{id}/rules", (c, s) => (failing && lookupPage(c) ? {status: 429, body: errorBody("rate_limited")} : base(c, s)));
      await page.goto(`${home(lang)}?ruleDialog=add-edit-rule:${uid("ru", 451)}`);
      const dialog = dialogOf(page, lang, R(lang, "dialog.edit"));
      await expect(dialog.getByText(R(lang, "dialog.lookupFailed"))).toBeVisible();
      // A failure is not "the rule is gone", and nothing asks again by itself.
      await expect(dialog.getByText(R(lang, "dialog.notFound"))).toHaveCount(0);
      const asked = () => mock.calls.filter((c) => c.path === `/profiles/${PROFILE.home}/rules` && !c.query.has("folder") && c.query.has("cursor")).length;
      const first = asked();
      expect(first).toBeGreaterThan(0);
      await holds(asked, first, "look-up pages asked for after the failure");
      failing = false;
      await dialog.getByRole("button", {name: COMMON[lang].retry}).click();
      await expect(dialog.getByText("example450.com")).toBeVisible();
      await expect(dialog.getByText(R(lang, "dialog.lookupFailed"))).toHaveCount(0);
    });

    test("S4-r1-2, S4-r1-3: a search is sent when typing pauses, the list stays while it loads, and the header never says 0 rules", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      const base = screenHandlers(mock.screens)["GET /profiles/{id}/rules"]!;
      mock.on("GET /profiles/{id}/rules", async (c, s) => {
        if (c.query.has("q")) await new Promise((resolve) => setTimeout(resolve, 700));
        return base(c, s);
      });
      await page.goto(home(lang));
      await expect(row(page, lang, "example120.com")).toBeVisible();
      await search(page, lang).pressSequentially("example49", {delay: 40});
      // The request is sent after the pause (250 ms) and answers 700 ms later: look once it is on its way.
      const searched = () => mock.calls.filter((c) => c.path === `/profiles/${PROFILE.home}/rules` && c.query.has("q")).length;
      await expect.poll(searched).toBeGreaterThan(0);
      expect(await page.getByRole("status", {name: R(lang, "list.loading")}).count(), "skeleton rows while the next list loads").toBe(0);
      expect(await rulesList(page, lang).getByRole("listitem").count(), "the previous list stays").toBeGreaterThan(0);
      expect(await rulesScreen(page).locator("h2").innerText()).not.toMatch(/(^|\s)[0۰](\s|$)/);
      await expect(rulesList(page, lang).getByRole("listitem").first()).toContainText("example49");
      const searches = mock.calls.filter((c) => c.path === `/profiles/${PROFILE.home}/rules` && c.query.has("q"));
      expect(searches.length, "requests for nine keystrokes").toBeLessThanOrEqual(2);
      expect(searches.at(-1)?.query.get("q")).toBe("example49");
    });

    test("S4-r1-6: cancelling the first Redirect warning gives back the action that was chosen before it", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 20});
      await page.goto(`${home(lang)}?ruleDialog=add-edit-rule`);
      const dialog = dialogOf(page, lang, R(lang, "dialog.add"));
      const choose = (a: string) => dialog.getByRole("radio", {name: R(lang, "three.set", {action: action(lang, a), subject: R(lang, "dialog.newRule")})});
      await choose("bypass").click();
      await expect(choose("bypass")).toBeChecked();
      await choose("redirect").click();
      const warning = dialogOf(page, lang, R(lang, "redirectWarn.title"));
      // The warning is about every Iranian site, not the names that end in .ir (S4-r1-9).
      await expect(warning.getByText(R(lang, "redirectWarn.text"))).toBeVisible();
      await warning.getByRole("button", {name: COMMON[lang].cancel}).click();
      await expect(choose("bypass")).toBeChecked();
      await expect(choose("redirect")).not.toBeChecked();
    });

    test("S4-r1-7: an untouched Redirect folder has nothing to save, and a rename does not send its destination again", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 20});
      await page.goto(`${home(lang)}?ruleDialog=folder:${FOLDER.streaming}`);
      const dialog = dialogOf(page, lang, R(lang, "folderDialog.edit"));
      const save = dialog.getByRole("button", {name: COMMON[lang].save});
      await expect(save).toBeDisabled();
      await dialog.getByRole("textbox", {name: R(lang, "folderDialog.name")}).fill("Video");
      await expect(save).toBeEnabled();
      await save.click();
      await expect(dialog).toBeHidden();
      const patch = mock.calls.filter((c) => c.method === "PATCH" && c.path === `/profiles/${PROFILE.home}/folders/${FOLDER.streaming}`).at(-1);
      expect(patch?.body).toEqual({name: "Video"});
      expect((mock.screens.folders.get(PROFILE.home) ?? []).find((f) => f.id === FOLDER.streaming)).toMatchObject({name: "Video", action: "redirect", target: {kind: "auto"}});
    });

    test("S4-r2-1: a failed next page keeps the rows and says so under them with its own Retry", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 429/);
      const mock = await openProfiles(context, baseURL, {rules: 500});
      const base = screenHandlers(mock.screens)["GET /profiles/{id}/rules"]!;
      let failing = true;
      mock.on("GET /profiles/{id}/rules", (c, s) => (failing && c.query.has("cursor") ? {status: 429, body: errorBody("rate_limited")} : base(c, s)));
      await page.goto(home(lang));
      const list = rulesList(page, lang);
      await expect(list.getByRole("listitem").first()).toBeVisible();
      const area = page.locator(".virtual-rows");
      await area.evaluate((el) => (el.scrollTop = el.scrollHeight));
      const footer = area.getByRole("alert");
      await expect(footer.getByText(R(lang, "list.loadMoreFailed"))).toBeVisible();
      // The rows that were read stay, with no error block in their place, and nothing asks again by itself.
      expect(await list.getByRole("listitem").count()).toBeGreaterThan(0);
      await expect(rulesScreen(page).getByText(R(lang, "list.refreshFailed"))).toHaveCount(0);
      const asked = () => mock.calls.filter((c) => c.path === `/profiles/${PROFILE.home}/rules` && c.query.has("cursor")).length;
      const first = asked();
      await holds(asked, first, "next pages asked for after the failure");
      failing = false;
      await footer.getByRole("button", {name: COMMON[lang].retry}).click();
      await expect(footer).toHaveCount(0);
      await expect.poll(() => list.getAttribute("style")).not.toContain("height: 5600px");
    });

    test("S4-r2-1: a failed refetch after a write keeps the rows, says the list may be old, and Retry reads it again", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 429/);
      const mock = await openProfiles(context, baseURL, {rules: 500});
      const base = screenHandlers(mock.screens)["GET /profiles/{id}/rules"]!;
      let failing = false;
      mock.on("GET /profiles/{id}/rules", (c, s) => (failing ? {status: 429, body: errorBody("rate_limited")} : base(c, s)));
      await page.goto(home(lang));
      await expect(row(page, lang, "example120.com")).toBeVisible();
      failing = true;
      await row(page, lang, "example120.com").getByRole("button").first().click();
      const bar = page.getByRole("toolbar", {name: COMMON[lang].selection.barLabel});
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.disable")}`)}).click();
      const notice = rulesScreen(page).locator("[data-refresh-failed]");
      await expect(notice.getByText(R(lang, "list.refreshFailed"))).toBeVisible();
      expect(await rulesList(page, lang).getByRole("listitem").count()).toBeGreaterThan(0);
      failing = false;
      await notice.getByRole("button", {name: COMMON[lang].retry}).click();
      await expect(notice).toHaveCount(0);
      await expect(switchOf(page, lang, "example120.com")).not.toBeChecked();
    });

    test("S4-r2-2: a switch after a deep scroll asks for no page of the list again", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      const list = rulesList(page, lang);
      await expect(list.getByRole("listitem").first()).toBeVisible();
      const area = page.locator(".virtual-rows");
      const listCalls = () => mock.calls.filter((c) => c.method === "GET" && c.path === `/profiles/${PROFILE.home}/rules`).length;
      // Three pages are loaded when the person flips switches.
      await expect
        .poll(async () => {
          await area.evaluate((el) => (el.scrollTop = el.scrollHeight));
          return list.getAttribute("style");
        })
        .toContain("height: 16800px");
      await expect(list.getByRole("listitem").first()).toBeVisible();
      const before = listCalls();
      // A Redirect row to an Iranian name is refused by the API (and a refused write does read the list again, rightly): the switches are of other rows.
      const plain = list.getByRole("listitem").filter({hasNotText: action(lang, "redirect")});
      for (const n of [2, 3, 4]) await plain.nth(n).locator(".switch__control").click();
      await expect.poll(() => mock.calls.filter((c) => c.method === "PATCH").length).toBe(3);
      await holds(listCalls, before, "pages of the list asked for after three switches");
    });

    test("S4-r2-3: the header count follows a delete, because the profile's own count is read again", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      await expect(row(page, lang, "example120.com")).toBeVisible();
      const topLevel = state(mock).filter((r) => !r.folder_id).length;
      await expect(rulesScreen(page).locator("h2")).toContainText(either(topLevel));
      await row(page, lang, "example120.com").getByRole("button").first().click();
      const bar = page.getByRole("toolbar", {name: COMMON[lang].selection.barLabel});
      await bar.getByRole("button", {name: new RegExp(`^${R(lang, "batch.delete")}`)}).click();
      await page.getByRole("alertdialog").getByRole("button", {name: R(lang, "batch.deleteConfirm")}).click();
      await expect.poll(() => byKey(mock, "example120.com")).toBeUndefined();
      await expect(rulesScreen(page).locator("h2")).toContainText(either(topLevel - 1));
    });

    test("S4-r2-4: another filter shows its list from the first row, not at the offset of the old one", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      const list = rulesList(page, lang);
      await expect(list.getByRole("listitem").first()).toBeVisible();
      const area = page.locator(".virtual-rows");
      await area.evaluate((el) => (el.scrollTop = 3000));
      await expect.poll(async () => Number(await list.getByRole("listitem").first().getAttribute("aria-posinset"))).toBeGreaterThan(20);
      await picker(page, R(lang, "filters.statusLabel")).click();
      await listbox(page).getByRole("option", {name: R(lang, "filters.disabled")}).click();
      await expect(list.getByRole("listitem").first().getByRole("switch")).not.toBeChecked();
      await expect(list.getByRole("listitem").first()).toHaveAttribute("aria-posinset", "1");
      expect(await page.locator(".virtual-rows").evaluate((el) => el.scrollTop)).toBe(0);
    });

    test("S4-r3-1: a switch in a view filtered by state takes the row out of it, and asks for no page of the list", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      await expect(row(page, lang, "example120.com")).toBeVisible();
      await picker(page, R(lang, "filters.statusLabel")).click();
      await listbox(page).getByRole("option", {name: R(lang, "filters.enabled")}).click();
      const listCalls = () => mock.calls.filter((c) => c.method === "GET" && c.path === `/profiles/${PROFILE.home}/rules`).length;
      await expect.poll(() => mock.calls.filter((c) => c.path === `/profiles/${PROFILE.home}/rules` && c.query.get("status") === "enabled").length).toBeGreaterThan(0);
      await expect(page.locator(".virtual-rows")).not.toHaveClass(/opacity-60/);
      await expect(row(page, lang, "example1.com")).toBeVisible();
      const before = listCalls();
      await row(page, lang, "example1.com").locator(".switch__control").click();
      // The row is not in the view of the enabled rules any more, and the next rows moved up.
      await expect(row(page, lang, "example1.com")).toHaveCount(0);
      await expect.poll(() => byKey(mock, "example1.com")?.enabled).toBe(false);
      await expect(rulesList(page, lang).getByRole("listitem").first().getByRole("switch")).toBeChecked();
      await holds(listCalls, before, "pages of the list asked for after a switch", 1000);
    });

    test("S4-r3-2: deleting a folder does not ask for the rules of the folder that is gone", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(folderPath(lang, PROFILE.home, FOLDER.work));
      await expect(page.getByRole("list", {name: R(lang, "list.listLabel", {name: "Work"})}).getByRole("listitem").first()).toBeVisible();
      const forFolder = () => mock.calls.filter((c) => c.method === "GET" && c.path === `/profiles/${PROFILE.home}/rules` && c.query.get("folder") === FOLDER.work).length;
      const before = forFolder();
      expect(before).toBeGreaterThan(0);
      await page.getByRole("button", {name: R(lang, "folderPage.deleteAria", {name: "Work"})}).click();
      await page.getByRole("alertdialog").getByRole("button", {name: R(lang, "folderPage.deleteConfirm")}).click();
      await expect(page).toHaveURL(/custom-rules$/);
      await expect(rulesScreen(page)).toBeVisible();
      await holds(forFolder, before, "lists of the deleted folder asked for after its delete", 1000);
      await expect(page.locator("[data-refresh-failed]")).toHaveCount(0);
    });

    test("S4-r3-3: on a phone the small view still says the action and the marked states in words", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      await page.setViewportSize({width: 375, height: 800});
      await page.goto(home(lang));
      await page.getByRole("radio", {name: R(lang, "view.small")}).click({force: true});
      await expect(page.getByRole("radio", {name: R(lang, "view.small")})).toBeChecked();
      // A name that acts as Bypass.
      await search(page, lang).fill("site138");
      let rule = row(page, lang, "site138.ir");
      await expect(rule.locator("[data-marker=iranian]")).toBeVisible();
      await expect(rule.locator("[data-marker=iranian]")).toContainText(R(lang, "row.actsAsBypass"));
      // A rule that is off: the state and the action are in the row's words, and the row is still one line high (h-10, 42.5px).
      const off = state(mock).find((r) => !r.enabled && !r.folder_id && r.action !== "inherit")!;
      await search(page, lang).fill(off.pattern);
      rule = row(page, lang, off.pattern);
      await expect(rule).toBeVisible();
      await expect.poll(() => rule.innerText()).toContain(R(lang, "row.off"));
      expect(await rule.innerText()).toContain(action(lang, off.action));
      const box = (await rule.boundingBox())!;
      expect(box.height).toBeLessThanOrEqual(43);
      const line = (await rule.locator("span.sm\\:hidden").last().boundingBox())!;
      expect(line.y + line.height).toBeLessThanOrEqual(box.y + box.height + 1);
    });

    test("S4-r3-4: a delete question whose row scrolled out of the window is gone when it comes back", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {rules: 500});
      await page.goto(home(lang));
      const rule = row(page, lang, "example122.com");
      await rule.hover();
      await rule.getByRole("button", {name: R(lang, "row.delete", {pattern: "example122.com"})}).click();
      await expect(rule.getByRole("group", {name: R(lang, "row.confirmGroup", {pattern: "example122.com"})})).toBeVisible();
      // The focus leaves the row, so the row is not kept drawn when the window moves away.
      await search(page, lang).focus();
      const area = page.locator(".virtual-rows");
      await area.evaluate((el) => (el.scrollTop = 3000));
      await expect(row(page, lang, "example122.com")).toHaveCount(0);
      await area.evaluate((el) => (el.scrollTop = 0));
      await expect(row(page, lang, "example122.com")).toBeVisible();
      await expect(row(page, lang, "example122.com").getByRole("group")).toHaveCount(0);
    });

    test("S4-r3-5: an open rule dialog keeps its form when a read of the list no longer has the rule", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 200});
      await page.goto(home(lang));
      await expect(row(page, lang, "example122.com")).toBeVisible();
      // A switch marks the loaded lists stale without asking for them; the next reconnect reads them.
      await row(page, lang, "example123.com").locator(".switch__control").click();
      await expect.poll(() => mock.calls.filter((c) => c.method === "PATCH").length).toBe(1);
      const rule = row(page, lang, "example122.com");
      await rule.hover();
      await rule.getByRole("button", {name: R(lang, "row.edit", {pattern: "example122.com"})}).click();
      const dialog = dialogOf(page, lang, R(lang, "dialog.edit"));
      const comment = dialog.getByRole("textbox", {name: R(lang, "dialog.comment")});
      await comment.fill("keep me");
      // Another tab deletes the rule, and the list is read again.
      mock.screens.rules.set(PROFILE.home, state(mock).filter((r) => r.key !== "example122.com"));
      const listCalls = () => mock.calls.filter((c) => c.method === "GET" && c.path === `/profiles/${PROFILE.home}/rules`).length;
      const before = listCalls();
      await page.evaluate(() => {
        window.dispatchEvent(new Event("offline"));
        window.dispatchEvent(new Event("online"));
      });
      await expect.poll(listCalls).toBeGreaterThan(before);
      await expect(dialog.getByText(R(lang, "dialog.notFound"))).toHaveCount(0);
      await expect(comment).toHaveValue("keep me");
    });

    test("S4-r3-6: a page of fewer than fifty rows is followed by the next one without a scroll", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {rules: 500});
      const base = screenHandlers(mock.screens)["GET /profiles/{id}/rules"]!;
      mock.on("GET /profiles/{id}/rules", (c, s) => {
        c.query.set("limit", "30");
        return base(c, s);
      });
      await page.goto(home(lang));
      await expect(rulesList(page, lang).getByRole("listitem").first()).toBeVisible();
      const next = () => mock.calls.filter((c) => c.method === "GET" && c.path === `/profiles/${PROFILE.home}/rules` && c.query.has("cursor")).length;
      await expect.poll(next).toBeGreaterThan(0);
    });

    test("T-487: 10,000 rules keep the DOM small and settle after a 2,000px scroll", async ({page, context, baseURL}) => {
      test.setTimeout(120_000);
      const mock = await openProfiles(context, baseURL);
      await page.goto(home(lang));
      const list = rulesList(page, lang);
      await expect(list.getByRole("listitem").first()).toBeVisible();
      const rows = () => list.getByRole("listitem").count();
      expect(await rows()).toBeGreaterThan(0);
      expect(await rows(), "rows in the DOM").toBeLessThan(100);
      // A row knows its place in the whole list, which is the count of the top level (10,000 rules, 120 in Work), not the 100 that are loaded (S4-r1-4).
      const topLevel = state(mock).filter((r) => !r.folder_id).length;
      expect(topLevel).toBeGreaterThan(100);
      await expect(list.getByRole("listitem").first()).toHaveAttribute("aria-setsize", String(topLevel));
      const area = page.locator(".virtual-rows");
      const box = (await area.boundingBox())!;
      await page.mouse.move(box.x + box.width / 2, box.y + Math.min(box.height, 400) / 2);
      await page.evaluate(() => {
        const w = window as unknown as {__lastScroll: number; __lastMutation: number; __wired?: boolean};
        w.__lastScroll = 0;
        w.__lastMutation = 0;
        if (w.__wired) return;
        w.__wired = true;
        document.addEventListener("scroll", () => (w.__lastScroll = performance.now()), {capture: true, passive: true});
        const tasks: string[] = [];
        (w as unknown as {__tasks: string[]}).__tasks = tasks;
        new PerformanceObserver((list) => {
          for (const e of list.getEntries()) tasks.push(`${Math.round(e.startTime)}+${Math.round(e.duration)}`);
        }).observe({entryTypes: ["longtask"]});
        const seen: {t: number; what: string}[] = [];
        (w as unknown as {__seen: typeof seen}).__seen = seen;
        new MutationObserver((records) => {
          w.__lastMutation = performance.now();
          for (const r of records) seen.push({t: w.__lastMutation, what: `${(r.target as HTMLElement).outerHTML.slice(0, 90)} +${r.addedNodes.length} -${[...r.removedNodes].map((n) => (n as HTMLElement).outerHTML?.slice(0, 120)).join("|")}`});
        }).observe(document.body, {childList: true, subtree: true});
      });
      await page.mouse.wheel(0, 2000);
      // The page is quiet when 400 ms have passed since the last scroll event and the last change of the page.
      await page.waitForFunction(() => {
        const w = window as unknown as {__lastScroll: number; __lastMutation: number};
        return w.__lastScroll > 0 && performance.now() - Math.max(w.__lastScroll, w.__lastMutation) > 400;
      });
      const settle = await page.evaluate(() => {
        const w = window as unknown as {__lastScroll: number; __lastMutation: number};
        return {scrolled: w.__lastScroll > 0, gap: w.__lastMutation - w.__lastScroll};
      });
      expect(settle.scrolled).toBe(true);
      const late = await page.evaluate(() => {
        const w = window as unknown as {__lastScroll: number; __seen: {t: number; what: string}[]};
        return w.__seen.filter((m) => m.t > w.__lastScroll + 300).map((m) => m.what).slice(0, 5);
      });
      const info = await page.evaluate(() => {
        const w = window as unknown as {__lastScroll: number; __lastMutation: number; __tasks: string[]};
        return `lastScroll=${Math.round(w.__lastScroll)} lastMutation=${Math.round(w.__lastMutation)} longtasks=${w.__tasks.join(" ")}`;
      });
      expect(late, `what changed more than 300ms after the last scroll event; ${info}`).toEqual([]);
      expect(settle.gap, "ms from the last scroll event to the last DOM change").toBeLessThanOrEqual(300);
      expect(await rows()).toBeLessThan(100);
      // The first row drawn is far down the list now.
      const first = (await list.getByRole("listitem").first().getAttribute("aria-posinset")) ?? "0";
      expect(Number(first)).toBeGreaterThan(20);
      // The window reaches the end of what is loaded and asks for the next page: the list grows.
      await area.evaluate((el) => (el.scrollTop = el.scrollHeight));
      await expect.poll(() => list.getAttribute("style")).not.toContain("height: 5600px");
    });
  });
}
