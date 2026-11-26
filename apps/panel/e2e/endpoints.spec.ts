import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {screenHandlers} from "@ctrlz/api-client/testing/screenMock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {endpointsMessage, callsTo, endpointRow, menuItem, message, nf, selectOf, tick, untick, openList} from "./endpoint-screens-support.ts";
import {ENDPOINT, GROUP, endpointsPath} from "./endpoints-support.ts";
import {LANGS, PROFILE} from "./profiles-support.ts";

// The Endpoint list, spec p3 10 and WF "Endpoints", in mock mode, in both languages (the specs loop over language themselves; the 12-project
// cases are endpoints.matrix.spec.ts). Each case names the row of Plan.md it covers.
//
// The fixture (`endpointsFixture()`): Home router and Laptop in the group Home; Office PC (a locked profile, a schedule, a waiting claim),
// New phone (Not Configured), Held router (an administrator holds it), Soft off and Hard off; types router 2, windows 2, android 1, tv 2.

test.use({viewport: {width: 1280, height: 800}});

for (const {lang, dir} of LANGS) {
  const text = (path: string, values: Record<string, string | number> = {}) => endpointsMessage(lang, path, values);

  test.describe(`${lang} (${dir})`, () => {
    test("T-216: the chips count each type and Not Configured, and pick the view", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      await expect(endpointRow(page, "Home router")).toBeVisible();
      const chips = page.getByTestId("endpoint-chips");
      await expect(chips.getByRole("button", {name: text("list.chipAria", {name: text("list.chipAll"), count: nf(lang, 7)})})).toHaveAttribute("aria-pressed", "true");

      const windows = lang === "fa" ? "ویندوز" : "Windows";
      await chips.getByRole("button", {name: text("list.chipAria", {name: windows, count: nf(lang, 2)})}).click();
      await expect(endpointRow(page, "Laptop")).toBeVisible();
      await expect(endpointRow(page, "Office PC")).toBeVisible();
      await expect(endpointRow(page, "Home router")).toHaveCount(0);
      expect(callsTo(mock.calls, "GET", "/endpoints").some((c) => c.query.get("type") === "windows")).toBe(true);

      await chips.getByRole("button", {name: text("list.chipAria", {name: text("list.chipNotConfigured"), count: nf(lang, 1)})}).click();
      await expect(endpointRow(page, "New phone")).toBeVisible();
      await expect(endpointRow(page, "Laptop")).toHaveCount(0);
      expect(callsTo(mock.calls, "GET", "/endpoints").some((c) => c.query.get("status") === "pending")).toBe(true);

      await chips.getByRole("button", {name: text("list.chipAria", {name: text("list.chipAll"), count: nf(lang, 7)})}).click();
      await expect(endpointRow(page, "Home router")).toBeVisible();
    });

    test("T-216: the sort is in the menu, the search narrows the list, and an empty answer says so", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      await expect(endpointRow(page, "Home router")).toBeVisible();
      await (await menuItem(page, lang, text("list.menu.sortName"))).click();
      await expect.poll(() => callsTo(mock.calls, "GET", "/endpoints").some((c) => c.query.get("sort") === "name")).toBe(true);
      // The current choice is said in words, not by a mark alone.
      await page.getByRole("button", {name: lang === "fa" ? "گزینه‌های بیشتر" : "More options"}).click();
      await expect(page.getByRole("menuitem", {name: text("list.menu.sortCurrent", {label: text("list.menu.sortName")})})).toBeVisible();
      await page.keyboard.press("Escape");

      await page.getByRole("button", {name: message(lang, "shell", "header.search")}).click();
      await page.getByRole("searchbox").last().fill("Laptop");
      await expect(endpointRow(page, "Home router")).toHaveCount(0);
      await expect(endpointRow(page, "Laptop")).toBeVisible();
      await page.getByRole("searchbox").last().fill("no such endpoint");
      await expect(page.getByText(text("list.emptyFiltered"))).toBeVisible();
    });

    test("T-217, T-232: a row has the type, the name, the profile, Clients, IPs, statistics, Edit and Resolvers, and the last query", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      const row = endpointRow(page, "Home router");
      await expect(row).toBeVisible();
      await expect(row).toContainText(lang === "fa" ? "روتر" : "Router");
      await expect(row.getByRole("link", {name: "Home", exact: true})).toHaveAttribute("href", new RegExp(`/profiles/${PROFILE.home}/`));
      await expect(row.getByRole("link", {name: new RegExp(text("list.row.clients"))})).toHaveAttribute("href", new RegExp(`/endpoints/${ENDPOINT.home}/clients$`));
      await expect(row.getByRole("link", {name: new RegExp(text("list.row.ips"))})).toHaveAttribute("href", new RegExp(`/endpoints/${ENDPOINT.home}/ips$`));
      await expect(row.getByRole("link", {name: text("list.row.statistics", {name: "Home router"})})).toBeVisible();
      await expect(row.getByRole("button", {name: text("list.row.editAria", {name: "Home router"})})).toBeVisible();
      await expect(row.getByRole("button", {name: text("frame.resolversAria", {name: "Home router"})})).toBeVisible();
      // T-232: Last query is on the row, in words.
      await expect(row).toContainText(text("lastQuery", {when: ""}).trim().split(" ")[0]!);
      // The counters carry their numbers.
      await expect(row).toContainText(nf(lang, 1000));
      // Status is words: Soft Disabled, Hard Disabled, Held and the schedule are chips with text.
      await expect(endpointRow(page, "Soft off")).toContainText(text("state.soft_disabled"));
      await expect(endpointRow(page, "Hard off")).toContainText(text("state.hard_disabled"));
      await expect(endpointRow(page, "Held router")).toContainText(text("list.row.heldChip"));
      await expect(endpointRow(page, "Office PC")).toContainText(text("list.row.schedule"));
    });

    test("T-217: the whole row opens the Clients page, and Edit opens its dialog in the address with the id", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      await endpointRow(page, "Laptop").getByRole("button", {name: text("list.row.editAria", {name: "Laptop"})}).click();
      await expect(page).toHaveURL(new RegExp(`deviceDialog=edit&deviceId=${ENDPOINT.laptop}`));
      await expect(page.getByRole("dialog", {name: text("dialogs.edit.title", {name: "Laptop"})})).toBeVisible();
      await page.goBack();
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await endpointRow(page, "Laptop").getByRole("link", {name: "Laptop", exact: true}).click();
      await expect(page).toHaveURL(new RegExp(`/endpoints/${ENDPOINT.laptop}/clients$`));
    });

    test("T-218: a new Endpoint says Not Configured and offers Configure in place of Resolvers", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      const row = endpointRow(page, "New phone");
      await expect(row).toContainText(text("status.pending"));
      await expect(row).toContainText(text("noQuery"));
      await expect(row.getByRole("button", {name: text("frame.resolversAria", {name: "New phone"})})).toHaveCount(0);
      await row.getByRole("button", {name: text("frame.configureAria", {name: "New phone"})}).click();
      await expect(page).toHaveURL(new RegExp(`deviceDialog=configure&deviceId=${ENDPOINT.pending}`));
    });

    test("T-229: the groups are sections that close; the menu of a group renames and deletes it, and the Endpoints stay", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      const toggle = page.getByRole("button", {name: text("list.groups.toggleAria", {name: "Home"})});
      await expect(toggle).toHaveAttribute("aria-expanded", "true");
      await expect(page.getByRole("button", {name: text("list.groups.toggleAria", {name: text("list.groups.ungrouped")})})).toBeVisible();
      await toggle.click();
      await expect(toggle).toHaveAttribute("aria-expanded", "false");
      await expect(endpointRow(page, "Home router")).toBeHidden();
      await toggle.click();
      await expect(endpointRow(page, "Home router")).toBeVisible();

      // Rename.
      await page.getByRole("button", {name: text("list.groups.actionsAria", {name: "Home"})}).click();
      await page.getByRole("menuitem", {name: text("list.groups.rename")}).click();
      await expect(page).toHaveURL(new RegExp(`endpointGroupDialog=rename%3A${GROUP.home}|endpointGroupDialog=rename:${GROUP.home}`));
      const rename = page.getByRole("dialog", {name: text("dialogs.group.renameTitle")});
      await rename.getByRole("textbox", {name: text("dialogs.group.name")}).fill("Family");
      await rename.getByRole("button", {name: text("dialogs.group.rename")}).click();
      await expect(rename).toBeHidden();
      await expect(page.getByRole("button", {name: text("list.groups.toggleAria", {name: "Family"})})).toBeVisible();
      expect(mock.screens.groups[0]?.name).toBe("Family");

      // Delete: the group goes, its Endpoints stay without a group.
      await page.getByRole("button", {name: text("list.groups.actionsAria", {name: "Family"})}).click();
      await page.getByRole("menuitem", {name: text("list.groups.delete")}).click();
      const del = page.getByRole("dialog", {name: text("dialogs.group.deleteTitle", {name: "Family"})});
      await expect(del).toContainText(text("dialogs.group.deleteText"));
      await del.getByRole("button", {name: text("dialogs.group.deleteConfirm")}).click();
      await expect(del).toBeHidden();
      expect(mock.screens.groups).toHaveLength(0);
      expect(mock.screens.endpoints).toHaveLength(7);
      await expect(endpointRow(page, "Home router")).toBeVisible();
      await expect(endpointRow(page, "Laptop")).toBeVisible();
    });

    test("T-229: New group takes a name and the Endpoints ticked in the list, with their count", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      await (await menuItem(page, lang, text("list.menu.newGroup"))).click();
      await expect(page).toHaveURL(/endpointGroupDialog=create/);
      const dialog = page.getByRole("dialog", {name: text("dialogs.group.createTitle")});
      await dialog.getByRole("textbox", {name: text("dialogs.group.name")}).fill("Office");
      await tick(dialog.getByRole("checkbox", {name: "Office PC"}));
      await tick(dialog.getByRole("checkbox", {name: "New phone"}));
      await expect(dialog).toContainText(text("dialogs.group.selected", {count: nf(lang, 2)}));
      await dialog.getByRole("button", {name: text("dialogs.group.create")}).click();
      await expect(dialog).toBeHidden();
      const office = mock.screens.groups.find((g) => g.name === "Office");
      expect(office).toBeTruthy();
      expect(mock.screens.endpoints.filter((e) => e.group_id === office!.id).map((e) => e.name).sort()).toEqual(["New phone", "Office PC"]);
      await expect(page.getByRole("button", {name: text("list.groups.toggleAria", {name: "Office"})})).toBeVisible();
    });

    test("T-229: an empty group name is refused in the dialog, with no request", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?endpointGroupDialog=create`);
      const dialog = page.getByRole("dialog", {name: text("dialogs.group.createTitle")});
      await dialog.getByRole("button", {name: text("dialogs.group.create")}).click();
      await expect(dialog.getByText(lang === "fa" ? "این مقدار الزامی است." : "This value is required.")).toBeVisible();
      expect(callsTo(mock.calls, "POST", "/endpoint-groups")).toHaveLength(0);
    });

    test.describe("a stale address", () => {
    test.use({allowConsole: [/status of 404/]});
    test("an address that names a group or an Endpoint that is not the tenant's shows a dialog that says so and closes", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?endpointGroupDialog=rename:${GROUP.unknown}`);
      await expect(page.getByRole("dialog")).toContainText(text("dialogs.group.gone"));
      await page.keyboard.press("Escape");
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.unknown}`);
      await expect(page.getByRole("dialog")).toContainText(text("dialogs.missing.text"));
      // A value that is not one of the dialogs, and an edit with no id, open nothing.
      await page.goto(`${endpointsPath(lang)}?deviceDialog=nonsense`);
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit`);
      await expect(page.getByRole("dialog")).toHaveCount(0);
    });
    });

    test("T-230: the selection mode has Select All and the bar with Move, Edit and Delete; Move puts the Endpoints in a group", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      await (await menuItem(page, lang, text("list.menu.select"))).click();
      const bar = page.getByRole("toolbar");
      await expect(bar).toBeVisible();
      await tick(page.getByRole("checkbox", {name: text("list.row.selectAria", {name: "Soft off"})}));
      await tick(page.getByRole("checkbox", {name: text("list.row.selectAria", {name: "Hard off"})}));
      // In selection mode the boxes select, and the row's buttons are gone.
      await expect(endpointRow(page, "Soft off").getByRole("button")).toHaveCount(0);
      await bar.getByRole("button", {name: new RegExp(`^${text("list.selection.move")}`)}).click();
      const dialog = page.getByRole("dialog", {name: text("dialogs.move.title", {count: nf(lang, 2)})});
      // S5-r1-5: no group is chosen at first, and Move is off, so a plain press cannot ungroup the selection.
      await expect(dialog.getByRole("button", {name: text("dialogs.move.submit"), exact: true})).toBeDisabled();
      await dialog.getByRole("button", {name: text("dialogs.move.choose")}).click();
      await page.getByRole("option", {name: "Home", exact: true}).click();
      await dialog.getByRole("button", {name: text("dialogs.move.submit")}).click();
      await expect(dialog).toBeHidden();
      const body = callsTo(mock.calls, "POST", "/endpoints:batch").at(-1)?.body as {op: string; ids: string[]; group_id: string};
      expect(body).toMatchObject({op: "move", group_id: GROUP.home});
      expect(body.ids).toHaveLength(2);
      // The mode ends with the action.
      await expect(page.getByRole("toolbar")).toHaveCount(0);
    });

    test("S5-r1-5: Move to No group is a choice of its own, and it clears the group", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      await (await menuItem(page, lang, text("list.menu.select"))).click();
      await tick(page.getByRole("checkbox", {name: text("list.row.selectAria", {name: "Laptop"})}));
      await page.getByRole("toolbar").getByRole("button", {name: new RegExp(`^${text("list.selection.move")}`)}).click();
      const dialog = page.getByRole("dialog", {name: text("dialogs.move.title", {count: nf(lang, 1)})});
      await dialog.getByRole("button", {name: text("dialogs.move.choose")}).click();
      await page.getByRole("option", {name: text("dialogs.fields.noGroup")}).click();
      await dialog.getByRole("button", {name: text("dialogs.move.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      expect(callsTo(mock.calls, "POST", "/endpoints:batch").at(-1)?.body).toMatchObject({op: "move", clear: ["group_id"]});
      expect(mock.screens.endpoints.find((e) => e.id === ENDPOINT.laptop)!.group_id).toBeUndefined();
    });

    test("S5-r1-2: the counters of a row name their Endpoint, and the name starts with the number and the label that are drawn", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      const row = endpointRow(page, "Home router");
      const clients = text("list.row.countAria", {label: text("list.row.clients"), name: "Home router", count: nf(lang, 1000)});
      const ips = text("list.row.countAria", {label: text("list.row.ips"), name: "Home router", count: nf(lang, 3)});
      await expect(row.getByRole("link", {name: clients, exact: true})).toHaveAttribute("href", new RegExp(`/endpoints/${ENDPOINT.home}/clients$`));
      await expect(row.getByRole("link", {name: ips, exact: true})).toHaveAttribute("href", new RegExp(`/endpoints/${ENDPOINT.home}/ips$`));
      // No two links of the list share a name.
      const names = await page.getByRole("link", {name: new RegExp(text("list.row.clients"))}).evaluateAll((els) => els.map((el) => el.getAttribute("aria-label")));
      expect(new Set(names).size).toBe(names.length);
    });

    test.describe("a page that fails", () => {
      test.use({allowConsole: [/status of 500/]});

      test("S5-r1-4, S5-r1-11: a failed later page says the list is partial, offers a retry, and keeps Select All off until the list is whole", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        const base = screenHandlers(mock.screens)["GET /endpoints"]!;
        let failing = true;
        // Three rows to a page (the real page is 100), so the seven of the fixture come in three pages and the second one fails.
        mock.on("GET /endpoints", (call, state) => {
          if (call.query.get("limit")) call.query.set("limit", "3");
          return failing && call.query.get("cursor") ? {status: 500, body: errorBody("internal")} : base(call, state);
        });
        await page.goto(endpointsPath(lang));
        await expect(endpointRow(page, "Home router")).toBeVisible();
        const notice = page.getByTestId("endpoints-partial");
        await expect(notice).toContainText(text("list.partial.title"));
        await expect(endpointRow(page, "Hard off")).toHaveCount(0);
        await (await menuItem(page, lang, text("list.menu.select"))).click();
        const bar = page.getByRole("toolbar");
        await expect(bar).toBeVisible();
        const selectAll = bar.getByRole("button", {name: new RegExp(`^${lang === "fa" ? "انتخاب همه" : "Select all"}`, "i")});
        await expect(selectAll).toHaveCount(0);

        failing = false;
        await notice.getByRole("button", {name: text("list.partial.retryAria")}).click();
        // In selection mode a row's name is a button, so the box is what finds it.
        await expect(page.getByRole("checkbox", {name: text("list.row.selectAria", {name: "Hard off"})})).toBeVisible();
        await expect(notice).toHaveCount(0);
        await expect(selectAll).toBeVisible();
      });
    });

    test("T-230: Select All selects every Endpoint of the view, Edit changes a profile for all of them, and Delete asks first", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      await (await menuItem(page, lang, text("list.menu.select"))).click();
      const bar = page.getByRole("toolbar");
      await bar.getByRole("button", {name: new RegExp(`^${lang === "fa" ? "انتخاب همه" : "Select all"}`, "i")}).click();
      await expect(bar).toContainText(message(lang, "common", "selection.allMatching"));

      await bar.getByRole("button", {name: new RegExp(`^${text("list.selection.edit")}`)}).click();
      const edit = page.getByRole("dialog", {name: text("dialogs.batch.title", {count: nf(lang, 7)})});
      // Nothing chosen: nothing is sent.
      await edit.getByRole("button", {name: text("dialogs.batch.submit")}).click();
      await expect(edit.getByText(text("dialogs.batch.nothing"))).toBeVisible();
      expect(callsTo(mock.calls, "POST", "/endpoints:batch")).toHaveLength(0);
      await selectOf(edit, text("dialogs.fields.analytics")).click();
      await page.getByRole("option", {name: text("dialogs.fields.analyticsNone")}).click();
      await edit.getByRole("button", {name: text("dialogs.batch.submit")}).click();
      await expect(edit).toBeHidden();
      const body = callsTo(mock.calls, "POST", "/endpoints:batch").at(-1)?.body as {op: string; ids: string[]; set: {analytics_level: string}};
      expect(body).toMatchObject({op: "edit", set: {analytics_level: "none"}});
      expect(body.ids).toHaveLength(7);
      expect(mock.screens.endpoints.every((e) => e.analytics_level === "none")).toBe(true);
    });

    test("T-230, T-233: a batch delete names the Endpoint an administrator holds and stays off until it is taken out of the selection", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      await (await menuItem(page, lang, text("list.menu.select"))).click();
      await tick(page.getByRole("checkbox", {name: text("list.row.selectAria", {name: "Held router"})}));
      await tick(page.getByRole("checkbox", {name: text("list.row.selectAria", {name: "Soft off"})}));
      await page.getByRole("toolbar").getByRole("button", {name: new RegExp(`^${text("list.selection.delete")}`)}).click();
      const dialog = page.getByRole("dialog", {name: text("dialogs.delete.batchTitle", {count: nf(lang, 2)})});
      await expect(dialog).toContainText("Held router");
      await tick(dialog.getByRole("checkbox"));
      await expect(dialog.getByRole("button", {name: text("dialogs.delete.submit")})).toBeDisabled();
      await dialog.getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
      await untick(page.getByRole("checkbox", {name: text("list.row.selectAria", {name: "Held router"})}));
      await page.getByRole("toolbar").getByRole("button", {name: new RegExp(`^${text("list.selection.delete")}`)}).click();
      const again = page.getByRole("dialog", {name: text("dialogs.delete.title", {name: "Soft off"})});
      await tick(again.getByRole("checkbox"));
      await again.getByRole("button", {name: text("dialogs.delete.submit")}).click();
      await expect(again).toBeHidden();
      expect(mock.screens.endpoints.map((e) => e.name)).not.toContain("Soft off");
      await expect(endpointRow(page, "Soft off")).toHaveCount(0);
    });

    test("T-231: Export CSV saves the file the server made, with a name that has no path in it", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      // The mock answers every body as JSON; the real route answers text/csv with a byte order mark of its own (p3 9.3).
      // The page reads the body as text, which drops a byte order mark, and writes its own: the file has exactly one whether the server sent one or not.
      let bom = true;
      await page.route("**/api/v1/endpoints/export", (route) => route.fulfill({status: 200, contentType: "text/csv; charset=utf-8", body: `${bom ? "\ufeff" : ""}name,type\r\nHome router,router\r\n`}));
      await page.goto(endpointsPath(lang));
      await expect(endpointRow(page, "Home router")).toBeVisible();
      for (const sent of [true, false]) {
        bom = sent;
        const item = await menuItem(page, lang, text("list.menu.export"));
        const [download] = await Promise.all([page.waitForEvent("download"), item.click()]);
        expect(download.suggestedFilename()).toBe("endpoints.csv");
        const stream = await download.createReadStream();
        const chunks: Buffer[] = [];
        for await (const chunk of stream) chunks.push(chunk as Buffer);
        const bytes = Buffer.concat(chunks);
        // One byte order mark first, so a spreadsheet reads Persian as UTF-8, and never a second one after it.
        expect([...bytes.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
        expect([...bytes.subarray(3, 6)]).not.toEqual([0xef, 0xbb, 0xbf]);
        expect(bytes.subarray(3).toString("utf8")).toContain("name,type");
      }
    });

    test("an empty tenant sees how to start, and the button opens Add", async ({page, context, baseURL}) => {
      await openList(context, baseURL, {empty: true});
      await page.goto(endpointsPath(lang));
      await expect(page.getByText(text("list.empty"))).toBeVisible();
      await page.getByRole("button", {name: text("list.emptyAction")}).last().click();
      await expect(page).toHaveURL(/deviceDialog=add/);
      await expect(page.getByRole("dialog", {name: text("dialogs.add.title")})).toBeVisible();
    });

    test("S5-r2-3: a tenant with groups and no Endpoint still sees its groups, and can rename or delete them", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      mock.screens.endpoints = [];
      await page.goto(endpointsPath(lang));
      await expect(page.getByText(text("list.empty"))).toBeVisible();
      await expect(page.getByRole("button", {name: text("list.groups.toggleAria", {name: "Home"})})).toBeVisible();
      await page.getByRole("button", {name: text("list.groups.actionsAria", {name: "Home"})}).click();
      await expect(page.getByRole("menuitem", {name: text("list.groups.rename")})).toBeVisible();
      await expect(page.getByRole("menuitem", {name: text("list.groups.delete")})).toBeVisible();
    });

    test("the keyboard reaches a row in reading order: the name, the profile, Clients, IPs, then the buttons", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      const row = endpointRow(page, "Home router");
      await row.getByRole("link", {name: "Home router", exact: true}).focus();
      const seen: string[] = [];
      for (let i = 0; i < 7; i++) {
        seen.push(await page.evaluate(() => (document.activeElement?.getAttribute("aria-label") ?? document.activeElement?.textContent ?? "").trim()));
        await page.keyboard.press("Tab");
      }
      expect(seen[0]).toBe("Home router");
      expect(seen[1]).toBe("Home");
      expect(seen[2]).toContain(text("list.row.clients"));
      expect(seen[3]).toContain(text("list.row.ips"));
      expect(seen[4]).toBe(text("list.row.statistics", {name: "Home router"}));
      expect(seen[5]).toBe(text("list.row.editAria", {name: "Home router"}));
      expect(seen[6]).toBe(text("frame.resolversAria", {name: "Home router"}));
    });
  });
}
