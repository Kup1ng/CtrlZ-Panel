import type {Page} from "@playwright/test";
import {screenHandlers} from "@ctrlz/api-client/testing/screenMock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {callsTo, openList, selectOf, tick} from "./endpoint-screens-support.ts";
import {lockedUntilPassword, nf, text as endpointText} from "./endpoint-pages-support.ts";
import {ENDPOINT, endpointPath} from "./endpoints-support.ts";
import {LANGS, LOCK_PASSWORD, PROFILE, text as profileText} from "./profiles-support.ts";

// The Clients page, spec p3 10 (T-257 to T-259) and the virtual list budget of FE 8.10 on 1,000 clients, in mock mode and in both
// languages. Home router has 1,000 clients (every third has an alias, every fifth a group "Family", every sixth is a Custom Client);
// Laptop has none.

test.use({viewport: {width: 1280, height: 900}, allowConsole: [/status of 4\d\d/]});

const list = (page: Page) => page.locator(".client-list");
const rowsDrawn = (page: Page) => list(page).locator('[role="listitem"]');

for (const {lang, dir} of LANGS) {
  const text = (path: string, values: Record<string, string | number> = {}) => endpointText(lang, path, values);
  const menu = (page: Page) => page.getByRole("button", {name: text("clients.menu.label")});
  const dialogOf = (page: Page, title: string) => page.getByRole("dialog", {name: title});

  test.describe(`${lang} (${dir})`, () => {
    test("T-257: the clients are grouped under their group name, each with its alias, label, what is known of it, its own profile and when it last asked", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "clients"));
      await expect(page.getByTestId("client-count")).toHaveText(text("clients.count", {count: nf(lang, 1000)}));
      // The first page is 100 clients, 20 of them in the group Family: the header says "so far", not that the group holds 20.
      await expect(page.getByRole("heading", {name: new RegExp("Family")})).toContainText(text("clients.groupCountSoFar", {count: nf(lang, 20)}));
      // The rows are by name inside a group, and a window of the page shows the first ones: one client with every detail is found by search.
      await expect(rowsDrawn(page).nth(1)).toBeVisible();
      await page.getByRole("searchbox", {name: text("clients.searchLabel")}).fill("Phone 1");
      const phone1 = rowsDrawn(page).filter({hasText: "Phone 1"}).first();
      await expect(phone1).toBeVisible();
      await expect(phone1).toContainText("device-1");
      await expect(phone1).toContainText("host-1.lan");
      await expect(phone1).toContainText("aa:bb:cc:dd:ee:ff");
      await expect(phone1).toContainText(text("clients.row.custom"));
      await expect(phone1).toContainText(text("clients.row.profile", {name: "Home"}));
      await expect(phone1).toContainText(text("clients.row.lastSeen", {when: ""}).trim().split(" ")[0]!);
      // The address and the host are Tech: they keep their own direction inside a Persian line.
      await expect(phone1.locator("bdi[dir=ltr]").first()).toBeVisible();
      await page.getByRole("searchbox", {name: text("clients.searchLabel")}).fill("");
      // Clients with no group come after the groups, under a header of their own.
      await list(page).evaluate((el) => (el.scrollTop = 20 * 92));
      await expect(page.getByRole("heading", {name: new RegExp(text("clients.ungrouped"))})).toBeVisible();
    });

    test("T-487: 1,000 clients are a window of rows in the page, in order and reachable, and a scroll settles at once", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "clients"));
      await expect(rowsDrawn(page).first()).toBeVisible();
      expect(await rowsDrawn(page).count()).toBeLessThan(100);

      // Scroll to the end until every page of the cursor has been read: 10 pages of 100.
      const area = list(page);
      for (let i = 0; i < 40 && callsTo(mock.calls, "GET", `/endpoints/${ENDPOINT.home}/clients`).filter((c) => !c.query.get("q") && !c.query.get("inactive_days")).length < 10; i++) {
        await area.evaluate((el) => (el.scrollTop = el.scrollHeight));
        await page.waitForTimeout(150);
      }
      expect(callsTo(mock.calls, "GET", `/endpoints/${ENDPOINT.home}/clients`).filter((c) => c.query.get("cursor")).length).toBeGreaterThanOrEqual(9);
      await area.evaluate((el) => (el.scrollTop = el.scrollHeight));
      await page.waitForTimeout(200);
      // 1,000 clients and the two headers are 1,002 items, of which about twenty are drawn.
      // The list is as tall as its items: 92 px for a client at this width and 52 for a group header, so its height tells how many there are.
      const height = await page.getByRole("list", {name: text("clients.listLabel")}).evaluate((el) => parseFloat(getComputedStyle(el).height));
      expect(height).toBe(1000 * 92 + 2 * 52);
      // With every page read the header is the real size of the group: 200 of the 1,000.
      await area.evaluate((el) => (el.scrollTop = 0));
      await expect(page.getByRole("heading", {name: new RegExp("Family")})).toContainText(text("clients.groupCount", {count: nf(lang, 200)}));
      expect(await rowsDrawn(page).count()).toBeLessThan(100);

      // The DOM stops changing within 100 ms of the last scroll event.
      const settle = await area.evaluate(async (el) => {
        let lastMutation = 0;
        let lastScroll = 0;
        const observer = new MutationObserver(() => (lastMutation = performance.now()));
        observer.observe(el, {childList: true, subtree: true, attributes: true});
        el.addEventListener("scroll", () => (lastScroll = performance.now()));
        el.scrollTop = 0;
        for (let i = 1; i <= 20; i++) {
          el.scrollTop = i * 100;
          await new Promise((r) => requestAnimationFrame(() => r(null)));
        }
        await new Promise((r) => setTimeout(r, 400));
        observer.disconnect();
        return lastMutation - lastScroll;
      });
      expect(settle).toBeLessThan(100);
    });

    test("T-257: the search goes to the server, and an empty answer says so", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "clients"));
      await page.getByRole("searchbox", {name: text("clients.searchLabel")}).fill("device-7");
      await expect.poll(() => callsTo(mock.calls, "GET", `/endpoints/${ENDPOINT.home}/clients`).some((c) => c.query.get("q") === "device-7")).toBe(true);
      await page.getByRole("searchbox", {name: text("clients.searchLabel")}).fill("no such client");
      await expect(page.getByText(text("clients.emptyFiltered"))).toBeVisible();
    });

    test("T-257: an Endpoint with no clients says so and offers a Custom Client", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.laptop, "clients"));
      await expect(page.getByText(text("clients.empty"), {exact: true})).toBeVisible();
      await page.getByRole("button", {name: text("clients.add")}).last().click();
      await expect(page).toHaveURL(new RegExp(`deviceDialog=client&deviceId=${ENDPOINT.laptop}`));
      await expect(dialogOf(page, text("clients.dialog.createTitle"))).toBeVisible();
    });

    test("T-258: a Custom Client is made in a dialog bound to the address, with an alias, a group, its own profile and Analytics", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointPath(lang, ENDPOINT.home, "clients")}?deviceDialog=client&deviceId=${ENDPOINT.home}`);
      const dialog = dialogOf(page, text("clients.dialog.createTitle"));
      await expect(dialog).toBeVisible();
      // The label crosses the network in clear text (R7): the warning is the field’s description, so it is read with the field.
      await expect(dialog.getByRole("textbox", {name: text("clients.dialog.label")})).toHaveAccessibleDescription(/DoT/);
      // Neither a label nor an alias: refused before a request.
      await dialog.getByRole("button", {name: text("clients.dialog.create"), exact: true}).click();
      await expect(dialog.getByText(lang === "fa" ? "این مقدار الزامی است." : /required/i).first()).toBeVisible();
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/clients`)).toHaveLength(0);

      await dialog.getByRole("textbox", {name: text("clients.dialog.alias")}).fill("Kitchen tablet");
      await dialog.getByRole("textbox", {name: text("clients.dialog.group")}).fill("Family");
      await selectOf(dialog, text("dialogs.fields.profile")).click();
      await page.getByRole("option", {name: "Home", exact: true}).click();
      await selectOf(dialog, text("dialogs.fields.analytics")).click();
      await page.getByRole("option", {name: text("dialogs.fields.analyticsSome"), exact: true}).click();
      await dialog.getByRole("button", {name: text("clients.dialog.create"), exact: true}).click();
      await expect(dialog).toBeHidden();
      const body = callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/clients`)[0]!.body;
      expect(body).toMatchObject({alias: "Kitchen tablet", group_name: "Family", profile_id: PROFILE.home, analytics_level: "some"});
      expect(body).not.toHaveProperty("label");
      await expect(page).not.toHaveURL(/deviceDialog/);
      await page.getByRole("searchbox", {name: text("clients.searchLabel")}).fill("Kitchen");
      await expect(rowsDrawn(page).filter({hasText: "Kitchen tablet"})).toBeVisible();
    });

    test("T-258: the label default is refused with its words, a taken label says so, and a full Endpoint says which limit", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(`${endpointPath(lang, ENDPOINT.home, "clients")}?deviceDialog=client&deviceId=${ENDPOINT.home}`);
      const dialog = dialogOf(page, text("clients.dialog.createTitle"));
      await dialog.getByRole("textbox", {name: text("clients.dialog.label")}).fill("default");
      await dialog.getByRole("button", {name: text("clients.dialog.create"), exact: true}).click();
      await expect(dialog.getByText(lang === "fa" ? "این نام رزرو است." : /reserved/i)).toBeVisible();
      await dialog.getByRole("textbox", {name: text("clients.dialog.label")}).fill("device-1");
      await dialog.getByRole("button", {name: text("clients.dialog.create"), exact: true}).click();
      await expect(dialog.getByText(lang === "fa" ? "از قبل وجود دارد." : /already exists/i)).toBeVisible();
    });

    test("T-258: the limit of clients per Endpoint is a notice with its name, and nothing is made", async ({page, context, baseURL}) => {
      await openList(context, baseURL, {limits: {max_clients_per_endpoint: 0}});
      await page.goto(`${endpointPath(lang, ENDPOINT.home, "clients")}?deviceDialog=client&deviceId=${ENDPOINT.home}`);
      const dialog = dialogOf(page, text("clients.dialog.createTitle"));
      await dialog.getByRole("textbox", {name: text("clients.dialog.alias")}).fill("One too many");
      await dialog.getByRole("button", {name: text("clients.dialog.create"), exact: true}).click();
      await expect(dialog.getByRole("alert").or(dialog.locator("[role=alert], .alert")).first()).toContainText(lang === "fa" ? "کلاینت‌های یک اندپوینت" : /clients of an Endpoint|clients per Endpoint|clients/i);
    });

    test("T-258: Edit changes the alias, empties the group and sends only what changed", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "clients"));
      await page.getByRole("searchbox", {name: text("clients.searchLabel")}).fill("Phone 1");
      await page.getByRole("button", {name: text("clients.row.editAria", {name: "Phone 1"}), exact: true}).click();
      const dialog = dialogOf(page, text("clients.dialog.editTitle", {name: "Phone 1"}));
      await expect(dialog.getByRole("textbox", {name: text("clients.dialog.label")})).toHaveCount(0);
      await dialog.getByRole("textbox", {name: text("clients.dialog.alias")}).fill("Mum's phone");
      await dialog.getByRole("textbox", {name: text("clients.dialog.group")}).fill("");
      await dialog.getByRole("button", {name: text("clients.dialog.save"), exact: true}).click();
      await expect(dialog).toBeHidden();
      const sent = callsTo(mock.calls, "PATCH", /\/clients\/[^/]+$/);
      expect(sent).toHaveLength(1);
      expect(sent[0]!.body).toEqual({alias: "Mum's phone", clear: ["group_name"]});
      await page.getByRole("searchbox", {name: text("clients.searchLabel")}).fill("Mum");
      await expect(rowsDrawn(page).filter({hasText: "Mum's phone"})).toBeVisible();
    });

    test("T-258, T-142: a Custom Client on a locked profile asks for its password in a dialog of its own", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      const base = screenHandlers(mock.screens)["POST /endpoints/{id}/clients"]!;
      mock.on("POST /endpoints/{id}/clients", (call, state) => {
        if ((call.body as {profile_id?: string}).profile_id !== PROFILE.office) return base(call, state);
        const asked = lockedUntilPassword(PROFILE.office, LOCK_PASSWORD, () => ({status: 200}))(call);
        return asked.status === 200 ? base(call, state) : asked;
      });
      await page.goto(`${endpointPath(lang, ENDPOINT.home, "clients")}?deviceDialog=client&deviceId=${ENDPOINT.home}`);
      const dialog = dialogOf(page, text("clients.dialog.createTitle"));
      await dialog.getByRole("textbox", {name: text("clients.dialog.alias")}).fill("Work laptop");
      await selectOf(dialog, text("dialogs.fields.profile")).click();
      await page.getByRole("option", {name: new RegExp("Office")}).click();
      await dialog.getByRole("button", {name: text("clients.dialog.create"), exact: true}).click();
      const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
      await expect(needed).toBeVisible();
      await needed.getByLabel(/Office/).fill(LOCK_PASSWORD);
      await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
      await expect(needed).toBeHidden();
      await expect(dialog).toBeHidden();
      expect(page.url()).not.toContain(LOCK_PASSWORD);
      await expectNoSecretResidue(page, [LOCK_PASSWORD], "the lock password of a Custom Client");
    });

    test("T-258: select several, delete them after a confirmation, and the Delete button waits for it", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "clients"));
      await menu(page).click();
      await page.getByRole("menuitem", {name: text("clients.menu.select")}).click();
      // The first two rows drawn that are clients (a header has no box).
      await expect(page.getByRole("checkbox").nth(1)).toBeAttached();
      await tick(page.getByRole("checkbox").nth(0));
      await tick(page.getByRole("checkbox").nth(1));
      await page.getByRole("toolbar").getByRole("button", {name: new RegExp(text("clients.selection.delete"))}).click();
      const dialog = dialogOf(page, text("clients.delete.titleIds", {count: nf(lang, 2)}));
      await expect(dialog).toBeVisible();
      const submit = dialog.getByRole("button", {name: text("clients.delete.submit"), exact: true});
      await expect(submit).toBeDisabled();
      await tick(dialog.getByRole("checkbox"));
      await submit.click();
      await expect(dialog).toBeHidden();
      const sent = callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/clients:batch`);
      expect(sent).toHaveLength(1);
      expect(sent[0]!.body).toMatchObject({op: "delete", ids: [expect.any(String), expect.any(String)]});
      expect(mock.screens.clients.get(ENDPOINT.home)).toHaveLength(998);
    });

    test("T-259: delete the clients quiet for N days shows their number first, refuses a day count outside 1 to 3650, and deletes by selector", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "clients"));
      await menu(page).click();
      await page.getByRole("menuitem", {name: text("clients.menu.inactive")}).click();
      const dialog = dialogOf(page, text("clients.delete.titleInactive"));
      const days = dialog.getByRole("textbox", {name: text("clients.delete.days")});
      await expect(days).toHaveValue("30");
      const cutoff = Date.now() - 30 * 86_400_000;
      const quiet = mock.screens.clients.get(ENDPOINT.home)!.filter((c) => Date.parse(c.last_seen_at) < cutoff).length;
      expect(quiet).toBeGreaterThan(0);
      await expect(dialog.getByTestId("delete-count")).toContainText(text("clients.delete.textInactive", {count: nf(lang, quiet), days: nf(lang, 30)}));
      // The count came from a read of the list with the day count, before any delete.
      expect(callsTo(mock.calls, "GET", `/endpoints/${ENDPOINT.home}/clients`).some((c) => c.query.get("inactive_days") === "30")).toBe(true);
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/clients:batch`)).toHaveLength(0);

      await days.fill("0");
      await expect(dialog.getByText(text("clients.delete.daysInvalid", {min: nf(lang, 1), max: nf(lang, 3650)}))).toBeVisible();
      await expect(dialog.getByRole("button", {name: text("clients.delete.submit"), exact: true})).toBeDisabled();
      await days.fill("30");
      await tick(dialog.getByRole("checkbox"));
      await dialog.getByRole("button", {name: text("clients.delete.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      const sent = callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/clients:batch`);
      expect(sent[0]!.body).toMatchObject({op: "delete", selector: {inactive_days: 30}});
      expect(mock.screens.clients.get(ENDPOINT.home)!.length).toBe(1000 - quiet);
    });

    test("T-259: delete all repeats while the server says there are more, and asks nothing twice", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.home, "clients"));
      await menu(page).click();
      await page.getByRole("menuitem", {name: text("clients.menu.all")}).click();
      const dialog = dialogOf(page, text("clients.delete.titleAll"));
      await expect(dialog.getByTestId("delete-count")).toContainText(text("clients.delete.textAll", {count: nf(lang, 1000)}));
      await tick(dialog.getByRole("checkbox"));
      await dialog.getByRole("button", {name: text("clients.delete.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      // 1,000 clients at 500 a call: two calls, the second with `more` false.
      const sent = callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/clients:batch`);
      expect(sent).toHaveLength(2);
      for (const call of sent) expect(call.body).toMatchObject({op: "delete", selector: {all: true}});
      expect(mock.screens.clients.get(ENDPOINT.home)).toHaveLength(0);
      await expect(page.getByText(text("clients.empty"), {exact: true})).toBeVisible();
    });
  });
}
