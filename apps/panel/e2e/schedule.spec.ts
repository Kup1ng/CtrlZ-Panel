import type {Page} from "@playwright/test";
import {screenHandlers} from "@ctrlz/api-client/testing/screenMock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {callsTo, openList} from "./endpoint-screens-support.ts";
import {centerOf, dragCells, gridCell, lockedUntilPassword, nf, tapCell, text as endpointText} from "./endpoint-pages-support.ts";
import {ENDPOINT, endpointPath} from "./endpoints-support.ts";
import {LANGS, LOCK_PASSWORD, PROFILE, text as profileText} from "./profiles-support.ts";

// The Schedule page, spec p3 10 (T-252 to T-254, T-488), in mock mode and in both languages. The week has the 7 days of the data
// counted from Sunday (cell number = day * 48 + half hour), whatever order a language draws them in. Office PC has a window of Sunday 09:00
// to 17:00 on its own (locked) profile; Home router has none.

test.use({viewport: {width: 1280, height: 900}, allowConsole: [/status of 4\d\d/]});

type Window = {start: number; end: number; profile_id: string; profile2_id?: string};
const cellMinutes = (day: number, row: number) => (day * 48 + row) * 30;

for (const {lang, dir} of LANGS) {
  const text = (path: string, values: Record<string, string | number> = {}) => endpointText(lang, path, values);
  const save = (page: Page) => page.getByRole("button", {name: text("schedule.save"), exact: true});
  const editor = (page: Page) => page.getByRole("dialog", {name: text("schedule.window.title")});

  test.describe(`${lang} (${dir})`, () => {
    test("T-252: a drag with the mouse makes a window of 30-minute cells, opens its editor, and Save sends the whole set", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "schedule"));
      await expect(page.locator("[data-screen=endpoint-schedule]")).toBeVisible();
      await expect(save(page)).toBeDisabled();

      // Tuesday (day 2) from 09:00 to 11:30: rows 18 to 22, five cells.
      await dragCells(page, 2, 18, 22);
      await expect(editor(page)).toBeVisible();
      await editor(page).getByRole("button", {name: lang === "fa" ? "انجام شد" : "Done"}).click();
      await expect(editor(page)).toBeHidden();
      await expect(page.getByRole("status").filter({hasText: text("schedule.unsaved", {count: nf(lang, 1)})})).toBeVisible();

      await save(page).click();
      await expect.poll(() => callsTo(mock.calls, "PUT", `/endpoints/${ENDPOINT.home}/schedule`).length).toBe(1);
      const body = callsTo(mock.calls, "PUT", `/endpoints/${ENDPOINT.home}/schedule`)[0]!.body as {timezone: string; windows: Window[]};
      expect(body.timezone).toBe("Asia/Tehran");
      expect(body.windows).toHaveLength(1);
      expect(body.windows[0]).toMatchObject({start: cellMinutes(2, 18), end: cellMinutes(2, 23)});
      // A new window starts on a profile other than the Endpoint's own, so it does something.
      expect(body.windows[0]!.profile_id).not.toBe(PROFILE.home);
      await expect(save(page)).toBeDisabled();
      expect(mock.screens.schedules.get(ENDPOINT.home)!.windows).toHaveLength(1);
    });

    test("T-253: a window that would cover another is refused, a click on a window selects it, and its editor changes it, with no overlap", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.office, "schedule"));
      // The window of the fixture: Sunday (day 0) 09:00 to 17:00, rows 18 to 33.
      await expect(gridCell(page, 0, 20)).toHaveAttribute("aria-label", /Office/);
      await dragCells(page, 0, 14, 20);
      await expect(page.getByRole("status").filter({hasText: text("schedule.blocked")})).toBeAttached();
      await expect(editor(page)).toBeHidden();
      await expect(save(page)).toBeDisabled();

      await gridCell(page, 0, 20).click();
      await expect(editor(page)).toBeVisible();
      // End at 12:00: the boundary after row 23, which the end-time select names 12:00.
      await editor(page).getByRole("button", {name: text("schedule.window.endTime")}).click();
      await page.getByRole("option", {name: new RegExp(lang === "fa" ? "۱۲:۰۰" : "12:00")}).first().click();
      await editor(page).getByRole("button", {name: lang === "fa" ? "انجام شد" : "Done"}).click();
      await save(page).click();
      await expect.poll(() => callsTo(mock.calls, "PUT", `/endpoints/${ENDPOINT.office}/schedule`).length).toBeGreaterThan(0);
      const sent = callsTo(mock.calls, "PUT", `/endpoints/${ENDPOINT.office}/schedule`)[0]!;
      expect((sent.body as {windows: Window[]}).windows).toEqual([expect.objectContaining({start: cellMinutes(0, 18), end: cellMinutes(0, 24)})]);
    });

    test("T-253: a window can be given a second profile that differs from the first, and deleted", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "schedule"));
      await dragCells(page, 3, 10, 12);
      const dialog = editor(page);
      // The selects are the start day and time, the end day and time, Profile and Profile 2, in that order.
      const selects = dialog.locator("[data-slot=select-trigger]");
      await selects.nth(5).click();
      await page.getByRole("option", {name: "Gaming", exact: true}).click();
      await selects.nth(4).click();
      await page.getByRole("option", {name: "Gaming", exact: true}).click();
      // Choosing the second one as the first drops the second: the two never name one profile.
      await expect(selects.nth(5)).toContainText(text("schedule.window.noSecond"));
      await dialog.getByRole("button", {name: text("schedule.window.deleteAria")}).click();
      await expect(dialog).toBeHidden();
      await expect(save(page)).toBeDisabled();
      expect(callsTo(mock.calls, "PUT", /schedule$/)).toHaveLength(0);
    });

    test("S6-r1-2: changing the start time of a window keeps the same dialog and the focus on the select", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "schedule"));
      await dragCells(page, 4, 10, 12);
      const dialog = editor(page);
      await expect(dialog).toBeVisible();
      const handle = await dialog.elementHandle();
      const start = dialog.locator("[data-slot=select-trigger]").nth(1);
      await start.click();
      await page.getByRole("option", {name: new RegExp(lang === "fa" ? "۰۴:۰۰" : "04:00")}).first().click();
      await expect(start).toContainText(lang === "fa" ? "۰۴:۰۰" : "04:00");
      // A remount would drop the element and move the focus to the first control of a new dialog.
      expect(await handle!.evaluate((el) => el.isConnected)).toBe(true);
      await expect(start).toBeFocused();
    });

    test("S6-r1-4: giving a window the pair of its neighbour merges them, and the editor and Delete then act on the whole window", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "schedule"));
      const dialog = editor(page);
      const selects = dialog.locator("[data-slot=select-trigger]");
      const done = dialog.getByRole("button", {name: lang === "fa" ? "انجام شد" : "Done"});
      // Thursday 05:00 to 06:00 on Gaming, then 06:00 to 07:00 on the default pair: two windows side by side.
      await dragCells(page, 4, 10, 11);
      await selects.nth(4).click();
      await page.getByRole("option", {name: "Gaming", exact: true}).click();
      await done.click();
      await dragCells(page, 4, 12, 13);
      await selects.nth(4).click();
      await page.getByRole("option", {name: "Gaming", exact: true}).click();
      // The grid shows one window from 05:00; the editor says so too, and not the 06:00 it was opened on.
      await expect(selects.nth(1)).toContainText(lang === "fa" ? "۰۵:۰۰" : "05:00");
      await expect(selects.nth(3)).toContainText(lang === "fa" ? "۰۷:۰۰" : "07:00");
      await dialog.getByRole("button", {name: text("schedule.window.deleteAria")}).click();
      await expect(dialog).toBeHidden();
      // Nothing is left of either part.
      await expect(save(page)).toBeDisabled();
    });

    test("T-253: Copy day puts one day's windows on the days ticked, and Clear all empties the week; both are drafts until Save", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.office, "schedule"));
      await page.getByRole("button", {name: text("schedule.copy.button"), exact: true}).click();
      const dialog = page.getByRole("dialog", {name: text("schedule.copy.title")});
      // The source starts on the first day drawn (Saturday in Persian, Sunday in English): choose Sunday, where the window is.
      await dialog.getByRole("button", {name: text("schedule.copy.from")}).click();
      await page.getByRole("option", {name: text(`schedule.days.long.0`)}).click();
      await dialog.getByRole("checkbox", {name: text("schedule.days.long.1")}).check({force: true});
      await dialog.getByRole("checkbox", {name: text("schedule.days.long.2")}).check({force: true});
      await dialog.getByRole("button", {name: text("schedule.copy.apply")}).click();
      expect(callsTo(mock.calls, "PUT", /schedule$/)).toHaveLength(0);
      await expect(gridCell(page, 1, 20)).toHaveAttribute("aria-label", /Office/);
      await expect(gridCell(page, 2, 20)).toHaveAttribute("aria-label", /Office/);
      await expect(gridCell(page, 3, 20)).not.toHaveAttribute("aria-label", /Office/);
      await save(page).click();
      await expect.poll(() => callsTo(mock.calls, "PUT", /schedule$/).length).toBeGreaterThan(0);
      const sent = callsTo(mock.calls, "PUT", /schedule$/)[0]!.body as {windows: Window[]};
      expect(sent.windows.map((w) => w.start)).toEqual([cellMinutes(0, 18), cellMinutes(1, 18), cellMinutes(2, 18)]);

      await page.getByRole("button", {name: text("schedule.clearAria")}).click();
      await expect(gridCell(page, 0, 20)).not.toHaveAttribute("aria-label", /Office/);
      await save(page).click();
      await expect.poll(() => callsTo(mock.calls, "PUT", /schedule$/).length).toBeGreaterThan(1);
      expect((callsTo(mock.calls, "PUT", /schedule$/)[1]!.body as {windows: Window[]}).windows).toEqual([]);
      await expect(page.getByRole("status").filter({hasText: text("schedule.none")})).toBeVisible();
    });

    test("T-253: the 65th window is not made", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      // 64 windows of one cell, every other cell of the first 128.
      mock.screens.schedules.set(ENDPOINT.home, {timezone: "Asia/Tehran", windows: Array.from({length: 64}, (_, i) => ({id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, start: i * 60, end: i * 60 + 30, profile_id: PROFILE.office}))});
      await page.goto(endpointPath(lang, ENDPOINT.home, "schedule"));
      await expect(gridCell(page, 0, 0)).toHaveAttribute("aria-label", /Office/);
      await dragCells(page, 5, 30, 31);
      await expect(page.getByText(text("schedule.tooMany", {max: nf(lang, 64)}))).toBeVisible();
      await expect(editor(page)).toBeHidden();
    });

    test("T-254: the time zone is Asia/Tehran at first, is searched by name, shows its offset from UTC, and is saved", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "schedule"));
      const zone = page.getByRole("combobox", {name: text("schedule.tz.label")});
      await expect(zone).toHaveValue("Asia/Tehran");
      await expect(page.getByTestId("tz-offset")).toHaveText(`UTC+${nf(lang, 3)}:${nf(lang, 30)}`);
      await zone.click();
      await zone.fill("kath");
      await page.getByRole("option", {name: /Asia\/Kathmandu/}).click();
      await expect(page.getByTestId("tz-offset")).toHaveText(`UTC+${nf(lang, 5)}:${nf(lang, 45)}`);
      await save(page).click();
      await expect.poll(() => callsTo(mock.calls, "PUT", /schedule$/).length).toBe(1);
      expect(callsTo(mock.calls, "PUT", /schedule$/)[0]!.body).toMatchObject({timezone: "Asia/Kathmandu", windows: []});
      await zone.click();
      await zone.fill("zzzz");
      await expect(page.getByText(text("schedule.tz.empty"))).toBeVisible();
    });

    test("T-488: the keyboard moves over the cells by what is drawn, Enter sets the start and the end, Escape drops the start", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "schedule"));
      const tab = page.locator("[role=gridcell][tabindex='0']");
      await tab.focus();
      // The first column drawn is Saturday in Persian and Sunday in English, row 18 (09:00).
      const first = lang === "fa" ? 6 : 0;
      await expect(tab).toHaveAttribute("data-cell", String(first * 48 + 18));
      // Left and Right follow the drawing: the next day is to the left in Persian and to the right in English.
      await page.keyboard.press(lang === "fa" ? "ArrowLeft" : "ArrowRight");
      const second = lang === "fa" ? 0 : 1;
      await expect(page.locator(":focus")).toHaveAttribute("data-cell", String(second * 48 + 18));
      await page.keyboard.press("Enter");
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("Escape");
      await expect(editor(page)).toBeHidden();
      await page.keyboard.press("Enter");
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("Enter");
      await expect(editor(page)).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(editor(page)).toBeHidden();
      await save(page).click();
      await expect.poll(() => callsTo(mock.calls, "PUT", /schedule$/).length).toBe(1);
      const w = (callsTo(mock.calls, "PUT", /schedule$/)[0]!.body as {windows: Window[]}).windows;
      expect(w).toEqual([expect.objectContaining({start: cellMinutes(second, 20), end: cellMinutes(second, 22)})]);
    });

    test("T-488: Delete on a cell of a window removes the window", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.office, "schedule"));
      await gridCell(page, 0, 20).focus();
      await page.keyboard.press("Delete");
      await expect(gridCell(page, 0, 20)).not.toHaveAttribute("aria-label", /Office/);
      await expect(save(page)).toBeEnabled();
    });

    test("T-488: the week is mirrored in Persian: the first day is at the start edge, so at the right, and time runs down", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "schedule"));
      const headers = page.getByRole("columnheader");
      await expect(headers).toHaveCount(8);
      const a = await centerOf(gridCell(page, lang === "fa" ? 6 : 0, 0));
      const b = await centerOf(gridCell(page, lang === "fa" ? 0 : 1, 0));
      // Persian: Saturday is to the right of Sunday. English: Sunday is to the left of Monday.
      if (lang === "fa") expect(a.x).toBeGreaterThan(b.x);
      else expect(a.x).toBeLessThan(b.x);
      const c = await centerOf(gridCell(page, 0, 40));
      const d = await centerOf(gridCell(page, 0, 4));
      expect(c.y).toBeGreaterThan(d.y);
      await expect(page.locator("html")).toHaveAttribute("dir", dir);
    });

    test("T-142, T-253: a window of a locked profile asks for its password when the schedule is saved; a wrong one stays, the right one saves", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      const base = screenHandlers(mock.screens)["PUT /endpoints/{id}/schedule"]!;
      mock.on("PUT /endpoints/{id}/schedule", (call, state) => {
        const asked = lockedUntilPassword(PROFILE.office, LOCK_PASSWORD, () => ({status: 200}))(call);
        return asked.status === 200 ? base(call, state) : asked;
      });
      await page.goto(endpointPath(lang, ENDPOINT.office, "schedule"));
      await page.getByRole("button", {name: text("schedule.clearAria")}).click();
      await save(page).click();
      const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
      await expect(needed).toBeVisible();
      const field = needed.getByLabel(/Office/);
      await field.fill("not the password");
      await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
      await expect(needed).toBeVisible();
      await field.fill(LOCK_PASSWORD);
      await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
      await expect(needed).toBeHidden();
      await expect(save(page)).toBeDisabled();
      expect(mock.screens.schedules.get(ENDPOINT.office)!.windows).toEqual([]);
      expect(page.url()).not.toContain(LOCK_PASSWORD);
      await expectNoSecretResidue(page, [LOCK_PASSWORD, "not the password"], "the lock password of a schedule save");
    });
  });
}

test.describe("on a touch screen at 375 pixels", () => {
  test.use({hasTouch: true, viewport: {width: 375, height: 812}});

  for (const {lang} of LANGS) {
    test(`T-252, T-488: tap the start and then the end makes a window, with no drag (${lang})`, async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "schedule"));
      await expect(gridCell(page, 4, 20)).toBeVisible();
      await tapCell(page, 4, 20);
      await tapCell(page, 4, 23);
      await expect(page.getByRole("dialog", {name: endpointText(lang, "schedule.window.title")})).toBeVisible();
      await page.getByRole("dialog").getByRole("button", {name: lang === "fa" ? "انجام شد" : "Done"}).click();
      await page.getByRole("button", {name: endpointText(lang, "schedule.save"), exact: true}).click();
      await expect.poll(() => callsTo(mock.calls, "PUT", /schedule$/).length).toBe(1);
      const w = (callsTo(mock.calls, "PUT", /schedule$/)[0]!.body as {windows: Window[]}).windows;
      expect(w).toEqual([expect.objectContaining({start: cellMinutes(4, 20), end: cellMinutes(4, 24)})]);
      // Seven columns fit the width of a phone.
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow).toBeLessThanOrEqual(0);
    });
  }
});
