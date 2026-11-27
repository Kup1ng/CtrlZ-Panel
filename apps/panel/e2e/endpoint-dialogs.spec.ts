import type {Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {screenHandlers} from "@ctrlz/api-client/testing/screenMock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {endpointsMessage, callsTo, endpointRow, flip, message, nf, selectOf, tick, openList} from "./endpoint-screens-support.ts";
import {ENDPOINT, endpointPath, endpointsPath, GROUP} from "./endpoints-support.ts";
import {LANGS, LOCK_PASSWORD, PROFILE, profilePath, text as profileText} from "./profiles-support.ts";

// The URL dialogs of the Endpoint list (`deviceDialog=add|edit|delete`), their lock password dialog, the confirmation of lost
// destinations, the hold notice and Rotate, in mock mode and in both languages. Each case names the row of Plan.md it covers. The fixtures
// are those of `endpointsFixture()`: Laptop has two profiles, Office PC a locked one, Held router is held by an administrator.

test.use({viewport: {width: 1280, height: 800}});

type Body = Record<string, unknown>;

/**
 * What the mutation cache of the page holds as variables, as text. React Query keeps the last variables of a mutation while its observer is
 * mounted, and a lock password is among them, so closing the password dialog is not enough to take it out of memory (S5-r3-9). The cache
 * is reached from the fiber of an open dialog up to the QueryClientProvider, which holds the client in its props. A page where no client is
 * found fails the test, so the check cannot pass for having looked nowhere.
 */
async function mutationVariables(page: Page): Promise<string> {
  return page.evaluate(() => {
    const node = document.querySelector("[role=dialog]") ?? document.body;
    const key = Object.keys(node).find((k) => k.startsWith("__reactFiber$"));
    type Fiber = {return: Fiber | null; memoizedProps?: {client?: {getMutationCache: () => {getAll: () => {state: {variables: unknown}}[]}}}};
    let fiber = key ? ((node as unknown as Record<string, Fiber>)[key] ?? null) : null;
    while (fiber) {
      const client = fiber.memoizedProps?.client;
      if (client && typeof client.getMutationCache === "function") return JSON.stringify(client.getMutationCache().getAll().map((m) => m.state.variables ?? null));
      fiber = fiber.return;
    }
    throw new Error("no QueryClient above the dialog");
  });
}

for (const {lang, dir} of LANGS) {
  const text = (path: string, values: Record<string, string | number> = {}) => endpointsMessage(lang, path, values);
  const cancel = message(lang, "common", "cancel");
  const required = message(lang, "errors", "fields.required");
  const dialogOf = (page: Page, title: string) => page.getByRole("dialog", {name: title});

  test.describe(`${lang} (${dir})`, () => {
    test("T-220: Add makes several Endpoints from one box of names, and the Resolvers dialog of the first opens by itself (T-218)", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(endpointsPath(lang));
      await page.getByRole("button", {name: text("dialogs.add.title"), exact: true}).click();
      const dialog = dialogOf(page, text("dialogs.add.title"));
      await expect(dialog).toBeVisible();
      await expect(page).toHaveURL(/deviceDialog=add$/);
      await dialog.getByRole("textbox", {name: text("dialogs.fields.names")}).fill("Alpha, Beta\nGamma");
      await expect(dialog).toContainText(text("dialogs.fields.namesCount", {count: nf(lang, 3)}));
      await dialog.getByRole("button", {name: text("dialogs.add.submit"), exact: true}).click();
      await expect.poll(() => mock.screens.endpoints.length).toBe(10);
      expect(mock.screens.endpoints.slice(0, 3).map((e) => e.name).sort()).toEqual(["Alpha", "Beta", "Gamma"]);
      const sent = callsTo(mock.calls, "POST", "/endpoints").at(-1)!;
      expect(sent.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
      expect(sent.body).toMatchObject({names: ["Alpha", "Beta", "Gamma"], profile_id: PROFILE.home, analytics_level: "full"});
      // T-218: the first one's Resolvers dialog replaces this one, in the same history entry.
      const first = mock.screens.endpoints.find((e) => e.name === "Alpha")!;
      await expect(page).toHaveURL(new RegExp(`deviceDialog=resolvers&deviceId=${first.id}`));
      await expect(dialog).toBeHidden();
    });

    test("T-220: the type is a menu with search over the catalogue, and Profile 2 is added with + and has to differ", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=add`);
      const dialog = dialogOf(page, text("dialogs.add.title"));
      const type = dialog.getByRole("combobox", {name: text("dialogs.fields.type")});
      await type.click();
      await type.fill(lang === "fa" ? "تلویزیون" : "TV");
      await page.getByRole("option", {name: lang === "fa" ? "تلویزیون" : "TV"}).click();
      await dialog.getByRole("textbox", {name: text("dialogs.fields.names")}).fill("Living room");
      await dialog.getByRole("button", {name: text("dialogs.fields.addProfileTwo")}).click();
      await expect(dialog.getByRole("button", {name: text("dialogs.fields.removeProfileTwo")})).toBeVisible();
      await dialog.getByRole("button", {name: text("dialogs.add.submit"), exact: true}).click();
      await expect.poll(() => callsTo(mock.calls, "POST", "/endpoints").length).toBe(1);
      expect(callsTo(mock.calls, "POST", "/endpoints")[0]!.body).toMatchObject({type: "other_tv", names: ["Living room"], profile_id: PROFILE.home});
      expect((callsTo(mock.calls, "POST", "/endpoints")[0]!.body as Body).profile2_id).toBeTruthy();
      expect((callsTo(mock.calls, "POST", "/endpoints")[0]!.body as Body).profile2_id).not.toBe(PROFILE.home);
    });

    test("T-220: a name is needed, 50 at most, and 64 characters each, all checked before a request", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=add`);
      const dialog = dialogOf(page, text("dialogs.add.title"));
      const names = dialog.getByRole("textbox", {name: text("dialogs.fields.names")});
      const submit = dialog.getByRole("button", {name: text("dialogs.add.submit"), exact: true});
      await submit.click();
      await expect(dialog.getByText(required)).toBeVisible();
      await names.fill("x".repeat(65));
      await submit.click();
      await expect(dialog.getByText(message(lang, "errors", "fields.too_long")).first()).toBeVisible();
      await names.fill(Array.from({length: 51}, (_, i) => `n${i}`).join(","));
      await expect(dialog).toContainText(text("dialogs.fields.namesTooMany"));
      await submit.click();
      await expect(dialog.getByText(message(lang, "errors", "fields.exceeded")).first()).toBeVisible();
      expect(callsTo(mock.calls, "POST", "/endpoints")).toHaveLength(0);
    });

    test("T-221: Analytics is None, Some or Full with its sentence, and the comment counts up to 255 and refuses 256", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=add`);
      const dialog = dialogOf(page, text("dialogs.add.title"));
      await dialog.getByRole("textbox", {name: text("dialogs.fields.names")}).fill("Counter");
      await expect(dialog).toContainText(text("dialogs.fields.analyticsHint.full"));
      await dialog.getByRole("radio", {name: text("dialogs.fields.analyticsSome")}).click();
      await expect(dialog).toContainText(text("dialogs.fields.analyticsHint.some"));
      const comment = dialog.getByRole("textbox", {name: new RegExp(text("dialogs.fields.comment"))});
      await comment.fill("c".repeat(256));
      await expect(dialog).toContainText(text("dialogs.fields.commentCount", {count: nf(lang, 256), max: nf(lang, 255)}));
      const submit = dialog.getByRole("button", {name: text("dialogs.add.submit"), exact: true});
      await submit.click();
      await expect(dialog.getByText(message(lang, "errors", "fields.too_long")).first()).toBeVisible();
      expect(callsTo(mock.calls, "POST", "/endpoints")).toHaveLength(0);
      await comment.fill("c".repeat(255));
      await submit.click();
      await expect.poll(() => callsTo(mock.calls, "POST", "/endpoints").length).toBe(1);
      expect(callsTo(mock.calls, "POST", "/endpoints")[0]!.body).toMatchObject({analytics_level: "some", comment: "c".repeat(255)});
    });

    test("T-220: Add starts on the profile a profile's own page offers, and the group can be made inside the dialog", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(profilePath(lang, PROFILE.gaming, "filters"));
      await page.getByTestId("profile-actions").getByRole("button", {name: profileText(lang, "profiles", "frame.addEndpointAria", {name: "Gaming"})}).click();
      const dialog = dialogOf(page, text("dialogs.add.title"));
      await expect(dialog).toBeVisible();
      // T-137: the profile is the open one, not the first of the list.
      await expect(dialog).toContainText("Gaming");
      await dialog.getByRole("textbox", {name: text("dialogs.fields.names")}).fill("Console");
      await selectOf(dialog, text("dialogs.fields.group")).click();
      await page.getByRole("option", {name: text("dialogs.fields.newGroup")}).click();
      await dialog.getByRole("textbox", {name: text("dialogs.fields.newGroupName")}).fill("Games");
      await dialog.getByRole("button", {name: text("dialogs.fields.newGroupCreate")}).click();
      await expect(selectOf(dialog, text("dialogs.fields.group"))).toContainText("Games");
      await dialog.getByRole("button", {name: text("dialogs.add.submit"), exact: true}).click();
      await expect.poll(() => callsTo(mock.calls, "POST", "/endpoints").length).toBe(1);
      const body = callsTo(mock.calls, "POST", "/endpoints")[0]!.body as Body;
      expect(body.profile_id).toBe(PROFILE.gaming);
      expect(body.group_id).toBe(mock.screens.groups.find((g) => g.name === "Games")!.id);
    });

    test.describe("a limit", () => {
      test("T-220: over the limit of Endpoints the dialog says which limit and nothing is made", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL, {limits: {max_endpoints: 7}});
        mock.on("POST /endpoints", {status: 422, body: {...errorBody("validation_failed"), fields: [{name: "max_endpoints", code: "exceeded"}]}});
        await page.goto(`${endpointsPath(lang)}?deviceDialog=add`);
        const dialog = dialogOf(page, text("dialogs.add.title"));
        await dialog.getByRole("textbox", {name: text("dialogs.fields.names")}).fill("One more");
        await dialog.getByRole("button", {name: text("dialogs.add.submit"), exact: true}).click();
        await expect(dialog).toContainText(message(lang, "errors", "limits.names.max_endpoints"));
        await expect(dialog).toBeVisible();
        expect(mock.screens.endpoints).toHaveLength(7);
      });
      test.use({allowConsole: [/status of 422/]});
    });

    test("T-228: Edit has the Schedule icon, Delete and Save, and saves only what changed", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
      const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
      await expect(dialog.getByRole("textbox", {name: text("dialogs.fields.name")})).toHaveValue("Laptop");
      await expect(dialog.getByRole("link", {name: text("dialogs.edit.scheduleAria", {name: "Laptop"})})).toHaveAttribute("href", new RegExp(`/endpoints/${ENDPOINT.laptop}/schedule$`));
      await expect(dialog.getByRole("button", {name: text("dialogs.edit.deleteAria", {name: "Laptop"})})).toBeVisible();
      // Nothing changed: Save closes with no request.
      await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      expect(callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.laptop}`)).toHaveLength(0);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
      await dialog.getByRole("textbox", {name: text("dialogs.fields.name")}).fill("Work laptop");
      await dialog.getByRole("textbox", {name: new RegExp(text("dialogs.fields.comment"))}).fill("");
      await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      const sent = callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.laptop}`);
      expect(sent).toHaveLength(1);
      expect(sent[0]!.body).toEqual({name: "Work laptop", clear: ["comment"]});
      await expect(endpointRow(page, "Work laptop")).toBeVisible();
    });

    test("T-222: Status is only in Edit: Not Configured before the first query, Active after, and Soft and Hard Disabled with their sentences", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=add`);
      await expect(dialogOf(page, text("dialogs.add.title")).getByRole("button", {name: text("dialogs.fields.status")})).toHaveCount(0);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.pending}`);
      let dialog = dialogOf(page, text("dialogs.edit.title", {name: "New phone"}));
      const status = selectOf(dialog, text("dialogs.fields.status"));
      await expect(status).toContainText(text("status.pending"));
      await expect(dialog).toContainText(text("dialogs.fields.statusHint.pending"));
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
      dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
      await expect(selectOf(dialog, text("dialogs.fields.status"))).toContainText(text("status.active"));
      await selectOf(dialog, text("dialogs.fields.status")).click();
      await page.getByRole("option", {name: text("state.hard_disabled")}).click();
      await expect(dialog).toContainText(text("dialogs.fields.statusHint.hard_disabled"));
      await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      expect(callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.laptop}`)[0]!.body).toEqual({admin_state: "hard_disabled"});
      await expect(endpointRow(page, "Laptop")).toContainText(text("state.hard_disabled"));
    });

    test("T-223 to T-227: the five switches are in Advanced and each one round-trips; Prevent Deactivation is not drawn", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
      const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
      await expect(dialog.getByRole("switch", {name: text("dialogs.fields.legacy")})).toBeHidden();
      await dialog.getByRole("button", {name: text("dialogs.fields.advanced")}).click();
      const legacy = dialog.getByRole("switch", {name: text("dialogs.fields.legacy")});
      await expect(legacy).toBeChecked();
      await flip(dialog, text("dialogs.fields.legacy"), false);
      await flip(dialog, text("dialogs.fields.secureDns"), true);
      await flip(dialog, text("dialogs.fields.ddns"), true);
      await flip(dialog, text("dialogs.fields.exposeIp"), true);
      await flip(dialog, text("dialogs.fields.requireIps"), true);
      await expect(dialog).not.toContainText(/prevent|جلوگیری از غیرفعال/i);
      await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      expect(callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.laptop}`)[0]!.body).toEqual({
        legacy_dns: false,
        authorize_secure_dns: true,
        authorize_ddns: true,
        expose_ip: true,
        require_authorized_ips: true,
      });
      const saved = mock.screens.endpoints.find((e) => e.id === ENDPOINT.laptop)!;
      expect([saved.legacy_dns, saved.authorize_secure_dns, saved.authorize_ddns, saved.expose_ip, saved.require_authorized_ips]).toEqual([false, true, true, true, true]);
      // Add has four of them: Require Authorized IPs is off at birth and is only in Edit.
      await page.goto(`${endpointsPath(lang)}?deviceDialog=add`);
      const add = dialogOf(page, text("dialogs.add.title"));
      await add.getByRole("button", {name: text("dialogs.fields.advanced")}).click();
      await expect(add.getByRole("switch")).toHaveCount(4);
      await expect(add.getByRole("switch", {name: text("dialogs.fields.requireIps")})).toHaveCount(0);
    });

    test.describe("Require Authorized IPs with no address", () => {
      test.use({allowConsole: [/status of 422/]});
      test("T-227: the answer needs_authorized_ip is shown under the switch and the dialog stays", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        mock.on("PATCH /endpoints/{id}", {status: 422, body: {...errorBody("validation_failed"), fields: [{name: "/require_authorized_ips", code: "needs_authorized_ip"}]}});
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
        await dialog.getByRole("button", {name: text("dialogs.fields.advanced")}).click();
        await flip(dialog, text("dialogs.fields.requireIps"), true);
        await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();
        await expect(dialog.getByText(message(lang, "errors", "fields.needs_authorized_ip"))).toBeVisible();
        await expect(dialog).toBeVisible();
      });
    });

    test("T-233: Delete warns that the devices lose DNS, waits for the box, and goes; the page of a deleted Endpoint goes back to the list", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointPath(lang, ENDPOINT.soft, "clients")}?deviceDialog=delete&deviceId=${ENDPOINT.soft}`);
      const dialog = dialogOf(page, text("dialogs.delete.title", {name: "Soft off"}));
      await expect(dialog).toContainText(text("dialogs.delete.text", {name: "Soft off"}));
      const submit = dialog.getByRole("button", {name: text("dialogs.delete.submit"), exact: true});
      await expect(submit).toBeDisabled();
      await tick(dialog.getByRole("checkbox", {name: text("dialogs.delete.confirm")}));
      await submit.click();
      await expect(page).toHaveURL(new RegExp(`${endpointsPath(lang)}$`));
      expect(mock.screens.endpoints.map((e) => e.id)).not.toContain(ENDPOINT.soft);
    });

    test("T-233: Delete from Edit replaces the Edit dialog, and a held Endpoint's Delete is off", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.hard}`);
      await dialogOf(page, text("dialogs.edit.title", {name: "Hard off"})).getByRole("button", {name: text("dialogs.edit.deleteAria", {name: "Hard off"})}).click();
      await expect(page).toHaveURL(new RegExp(`deviceDialog=delete&deviceId=${ENDPOINT.hard}`));
      await expect(dialogOf(page, text("dialogs.delete.title", {name: "Hard off"}))).toBeVisible();
      expect(callsTo(mock.calls, "POST", /:delete$/)).toHaveLength(0);

      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.held}`);
      const held = dialogOf(page, text("dialogs.edit.title", {name: "Held router"}));
      await expect(held).toContainText(text("dialogs.edit.held"));
      await expect(held.getByRole("button", {name: text("dialogs.edit.deleteAria", {name: "Held router"})})).toBeDisabled();
    });

    test.describe("a hold that came in after the dialog opened", () => {
      test.use({allowConsole: [/status of 409/]});
      test("T-233: endpoint_held names the Endpoint and nothing is deleted", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        mock.on("POST /endpoints/{id}:delete", {status: 409, body: {...errorBody("endpoint_held"), fields: [{name: "/ids/0", code: "invalid"}]}});
        await page.goto(`${endpointsPath(lang)}?deviceDialog=delete&deviceId=${ENDPOINT.soft}`);
        const dialog = dialogOf(page, text("dialogs.delete.title", {name: "Soft off"}));
        await tick(dialog.getByRole("checkbox", {name: text("dialogs.delete.confirm")}));
        const submit = dialog.getByRole("button", {name: text("dialogs.delete.submit"), exact: true});
        await expect(submit).toBeEnabled();
        // The administrator's hold came in after the Endpoint was read.
        mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.soft ? {...e, admin_hold: true} : e));
        await submit.click();
        await expect(dialog).toContainText(text("dialogs.delete.heldRefused", {names: "Soft off"}));
        expect(mock.screens.endpoints).toHaveLength(7);
        // S5-r1-6: the refusal read the Endpoint again, so the dialog knows the hold, the button is off, and a second press cannot repeat the 409.
        await expect(dialog).toContainText(text("dialogs.delete.heldTitle"));
        await expect(submit).toBeDisabled();
        expect(callsTo(mock.calls, "POST", /:delete$/)).toHaveLength(1);
      });
    });

    test.describe("a locked profile", () => {
      test.use({allowConsole: [/status of 4\d\d/]});

      test("T-142: taking a locked profile off an Endpoint asks for its password in a dialog; a wrong one stays, the right one saves, and no password is in the address", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.office}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Office PC"}));
        await selectOf(dialog, text("dialogs.fields.profile")).click();
        await page.getByRole("option", {name: "Home", exact: true}).click();
        await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();

        const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
        await expect(needed).toBeVisible();
        await expect(needed).toContainText("Office");
        const field = needed.getByLabel(/Office/);
        await field.fill("not the password");
        await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
        await expect(needed).toBeVisible();
        await expect(needed.getByText(/Office/).first()).toBeVisible();
        await field.fill(LOCK_PASSWORD);
        await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
        await expect(needed).toBeHidden();
        await expect(dialog).toBeHidden();
        const sent = callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.office}`);
        expect(sent).toHaveLength(3);
        expect(sent[0]!.body).toEqual({profile_id: PROFILE.home});
        expect(sent[2]!.body).toMatchObject({profile_id: PROFILE.home, lock_passwords: [{profile_id: PROFILE.office, password: LOCK_PASSWORD}]});
        expect(page.url()).not.toContain(LOCK_PASSWORD);
        await expectNoSecretResidue(page, [LOCK_PASSWORD, "not the password"], "the lock password of an Edit");
        expect(mock.screens.endpoints.find((e) => e.id === ENDPOINT.office)!.profile_id).toBe(PROFILE.home);
      });

      test("T-142: Cancel on the password dialog ends the save and leaves the Endpoint as it was", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.office}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Office PC"}));
        await selectOf(dialog, text("dialogs.fields.profile")).click();
        await page.getByRole("option", {name: "Home", exact: true}).click();
        await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();
        const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
        await needed.getByRole("button", {name: cancel}).click();
        await expect(needed).toBeHidden();
        // The form is still there, not failed, and can be tried again.
        await expect(dialog).toBeVisible();
        await expect(dialog.getByRole("alert")).toHaveCount(0);
        expect(mock.screens.endpoints.find((e) => e.id === ENDPOINT.office)!.profile_id).toBe(PROFILE.office);
      });
    });

    test.describe("a second 423", () => {
      test.use({allowConsole: [/status of 4\d\d/]});

      test("T-142, S5-r1-1: the passwords of the slots are not enough, so the same dialog asks again for the other locked profiles and keeps what was typed", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        // Home is locked as well, and only a request that carries both passwords is accepted (Home sits in a schedule window the slots do not show).
        mock.screens.profiles = mock.screens.profiles.map((p) => (p.id === PROFILE.home ? {...p, locked: true} : p));
        const base = screenHandlers(mock.screens)["PATCH /endpoints/{id}"]!;
        mock.on("PATCH /endpoints/{id}", (call, state) => {
          const given = new Set(((call.body as {lock_passwords?: {profile_id: string}[]}).lock_passwords ?? []).map((p) => p.profile_id));
          return given.has(PROFILE.office) && given.has(PROFILE.home) ? base(call, state) : {status: 423, body: {...errorBody("profile_locked"), fields: [{name: "/lock_passwords", code: "required"}]}};
        });
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.office}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Office PC"}));
        await selectOf(dialog, text("dialogs.fields.status")).click();
        await page.getByRole("option", {name: text("state.soft_disabled")}).click();
        await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();

        const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
        await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needText"));
        await expect(needed.getByLabel(/Home/)).toHaveCount(0);
        await needed.getByLabel(/Office/).fill(LOCK_PASSWORD);
        const next = needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")});
        await next.click();
        // The second 423 widens the ask: the dialog stays, Office keeps its password, and Home has a field now.
        await expect(needed.getByLabel(/Home/)).toBeVisible();
        await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needMoreText"));
        await expect(needed.getByLabel(/Office/)).toHaveValue(LOCK_PASSWORD);
        await needed.getByLabel(/Home/).fill(LOCK_PASSWORD);
        await next.click();
        await expect(needed).toBeHidden();
        await expect(dialog).toBeHidden();
        const sent = callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.office}`);
        expect(sent).toHaveLength(3);
        expect((sent[1]!.body as {lock_passwords: {profile_id: string}[]}).lock_passwords.map((p) => p.profile_id)).toEqual([PROFILE.office]);
        expect((sent[2]!.body as {lock_passwords: {profile_id: string}[]}).lock_passwords.map((p) => p.profile_id)).toEqual([PROFILE.office, PROFILE.home]);
        expect(page.url()).not.toContain(LOCK_PASSWORD);
        await expectNoSecretResidue(page, [LOCK_PASSWORD], "the widened lock password ask");
      });

      test("T-142, S5-r1-10: with no locked profile in a slot the fields are optional, and only the ones filled in are sent", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        mock.screens.profiles = mock.screens.profiles.map((p) => (p.id === PROFILE.gaming ? {...p, locked: true} : p));
        const base = screenHandlers(mock.screens)["PATCH /endpoints/{id}"]!;
        mock.on("PATCH /endpoints/{id}", (call, state) => {
          const given = ((call.body as {lock_passwords?: {profile_id: string}[]}).lock_passwords ?? []).map((p) => p.profile_id);
          return given.includes(PROFILE.gaming) ? base(call, state) : {status: 423, body: {...errorBody("profile_locked"), fields: [{name: "/lock_passwords", code: "required"}]}};
        });
        // New phone is on Home, which is not locked, so no slot holds a locked profile: Office and Gaming (locked here) are the guess.
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.pending}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "New phone"}));
        await selectOf(dialog, text("dialogs.fields.status")).click();
        await page.getByRole("option", {name: text("state.soft_disabled")}).click();
        await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();
        const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
        await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needAnyText"));
        const next = needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")});
        // At least one is needed.
        await next.click();
        await expect(needed.getByText(required)).toBeVisible();
        await needed.getByLabel(/Gaming/).fill(LOCK_PASSWORD);
        await next.click();
        await expect(needed).toBeHidden();
        const sent = callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.pending}`);
        expect((sent.at(-1)!.body as {lock_passwords: {profile_id: string}[]}).lock_passwords.map((p) => p.profile_id)).toEqual([PROFILE.gaming]);
        await expectNoSecretResidue(page, [LOCK_PASSWORD], "the optional lock password ask");
      });

      test("T-142, S5-r2-1: an edit of one slot of two locked profiles asks for the one it takes away, and the other field may stay empty", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        // Laptop sits on Home and Gaming. Both are locked here, and only a request that carries the password of Gaming is accepted.
        mock.screens.profiles = mock.screens.profiles.map((p) => (p.id === PROFILE.home || p.id === PROFILE.gaming ? {...p, locked: true} : p));
        const base = screenHandlers(mock.screens)["PATCH /endpoints/{id}"]!;
        mock.on("PATCH /endpoints/{id}", (call, state) => {
          const given = ((call.body as {lock_passwords?: {profile_id: string}[]}).lock_passwords ?? []).map((p) => p.profile_id);
          return given.includes(PROFILE.gaming) ? base(call, state) : {status: 423, body: {...errorBody("profile_locked"), fields: [{name: "/lock_passwords", code: "required"}]}};
        });
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
        await dialog.getByRole("button", {name: text("dialogs.fields.removeProfileTwo")}).click();
        await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();
        const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
        await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needAnyText"));
        await expect(needed.getByLabel(/Home/)).toBeVisible();
        await needed.getByLabel(/Gaming/).fill(LOCK_PASSWORD);
        await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
        await expect(needed).toBeHidden();
        const sent = callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.laptop}`);
        expect((sent.at(-1)!.body as {lock_passwords: {profile_id: string}[]}).lock_passwords.map((p) => p.profile_id)).toEqual([PROFILE.gaming]);
        await expectNoSecretResidue(page, [LOCK_PASSWORD], "the lock password of one slot");
      });
    });

    test.describe("the other guarded writes", () => {
      test.use({allowConsole: [/status of 4\d\d/]});

      test("T-142, S5-r1-8: Delete of an Endpoint on a locked profile asks for the password and sends it with the delete", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        const base = screenHandlers(mock.screens)["POST /endpoints/{id}:delete"]!;
        mock.on("POST /endpoints/{id}:delete", (call, state) =>
          (call.body as {lock_passwords?: unknown[]}).lock_passwords?.length ? base(call, state) : {status: 423, body: {...errorBody("profile_locked"), fields: [{name: "/lock_passwords", code: "required"}]}},
        );
        await page.goto(`${endpointsPath(lang)}?deviceDialog=delete&deviceId=${ENDPOINT.office}`);
        const dialog = dialogOf(page, text("dialogs.delete.title", {name: "Office PC"}));
        await tick(dialog.getByRole("checkbox", {name: text("dialogs.delete.confirm")}));
        await dialog.getByRole("button", {name: text("dialogs.delete.submit"), exact: true}).click();
        const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
        await needed.getByLabel(/Office/).fill(LOCK_PASSWORD);
        await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
        await expect(needed).toBeHidden();
        await expect(dialog).toBeHidden();
        const sent = callsTo(mock.calls, "POST", /:delete$/);
        expect(sent).toHaveLength(2);
        expect(sent[1]!.body).toMatchObject({lock_passwords: [{profile_id: PROFILE.office, password: LOCK_PASSWORD}]});
        expect(mock.screens.endpoints.map((e) => e.id)).not.toContain(ENDPOINT.office);
        await expectNoSecretResidue(page, [LOCK_PASSWORD], "the lock password of a Delete");
      });

      test("T-142, S5-r1-8: a batch Edit asks for the password too, and a 422 exceeded after it closes that dialog and says so in the Edit dialog", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        mock.on("POST /endpoints:batch", (call) =>
          (call.body as {lock_passwords?: unknown[]}).lock_passwords?.length
            ? {status: 422, body: {...errorBody("validation_failed"), fields: [{name: "/lock_passwords", code: "exceeded"}]}}
            : {status: 423, body: {...errorBody("profile_locked"), fields: [{name: "/lock_passwords", code: "required"}]}},
        );
        await page.goto(endpointsPath(lang));
        await page.getByRole("button", {name: message(lang, "shell", "header.more")}).click();
        await page.getByRole("menuitem", {name: text("list.menu.select")}).click();
        await tick(page.getByRole("checkbox", {name: text("list.row.selectAria", {name: "Office PC"})}));
        await page.getByRole("toolbar").getByRole("button", {name: new RegExp(`^${text("list.selection.edit")}`)}).click();
        const edit = page.getByRole("dialog", {name: text("dialogs.batch.title", {count: nf(lang, 1)})});
        await selectOf(edit, text("dialogs.fields.status")).click();
        await page.getByRole("option", {name: text("state.hard_disabled")}).click();
        await edit.getByRole("button", {name: text("dialogs.batch.submit")}).click();
        const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
        await needed.getByLabel(/Office/).fill(LOCK_PASSWORD);
        await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
        await expect(needed).toBeHidden();
        await expect(edit).toContainText(text("dialogs.locks.tooMany"));
        expect(callsTo(mock.calls, "POST", "/endpoints:batch")).toHaveLength(2);
        await expectNoSecretResidue(page, [LOCK_PASSWORD], "the lock password of a batch Edit");
      });
    });

    test.describe("round 3 of S5", () => {
      // One pattern (the offline case loads nothing): Playwright reads a two-element array given to test.use as a fixture value and its options.
      test.use({allowConsole: [/status of [45]\d\d|ERR_INTERNET_DISCONNECTED/]});

      test("S5-r3-1: the switch is called Plain DNS, the name the Plan gives the interface", async ({page, context, baseURL}) => {
        await openList(context, baseURL);
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
        await dialog.getByRole("button", {name: text("dialogs.fields.advanced")}).click();
        await expect(dialog.getByRole("switch", {name: "Plain DNS"})).toBeVisible();
        await expect(dialog).not.toContainText("Legacy");
      });

      test("S5-r3-4: a read that failed says it failed and offers Retry, not that the Endpoint or the group is gone", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        mock.on("GET /endpoints/{id}", {status: 500, body: errorBody("internal")});
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
        const dialog = page.getByRole("dialog");
        await expect(dialog.getByRole("button", {name: message(lang, "common", "retry")})).toBeVisible();
        await expect(dialog).not.toContainText(text("dialogs.missing.text"));
        mock.on("GET /endpoint-groups", {status: 500, body: errorBody("internal")});
        await page.goto(`${endpointsPath(lang)}?endpointGroupDialog=rename:${GROUP.home}`);
        await expect(page.getByRole("dialog").getByRole("button", {name: message(lang, "common", "retry")})).toBeVisible();
        await expect(page.getByRole("dialog")).not.toContainText(text("dialogs.group.gone"));
      });

      test("S5-r3-6: Delete is off while the browser is offline", async ({page, context, baseURL}) => {
        await openList(context, baseURL);
        await page.goto(`${endpointsPath(lang)}?deviceDialog=delete&deviceId=${ENDPOINT.soft}`);
        const dialog = dialogOf(page, text("dialogs.delete.title", {name: "Soft off"}));
        await tick(dialog.getByRole("checkbox", {name: text("dialogs.delete.confirm")}));
        const submit = dialog.getByRole("button", {name: text("dialogs.delete.submit"), exact: true});
        await expect(submit).toBeEnabled();
        await context.setOffline(true);
        try {
          await expect(submit).toBeDisabled();
        } finally {
          await context.setOffline(false);
        }
        await expect(submit).toBeEnabled();
      });

      test("S5-r3-10: Hard to Soft Disabled and Require Authorized IPs on carry the warning of a change that empties the stack", async ({page, context, baseURL}) => {
        await openList(context, baseURL);
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.hard}`);
        let dialog = dialogOf(page, text("dialogs.edit.title", {name: "Hard off"}));
        await expect(dialog.locator(".alert")).toHaveCount(0);
        await selectOf(dialog, text("dialogs.fields.status")).click();
        await page.getByRole("option", {name: text("state.soft_disabled")}).click();
        await expect(dialog.locator(".alert")).toContainText(text("dialogs.fields.statusHint.soft_disabled"));
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
        dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
        await dialog.getByRole("button", {name: text("dialogs.fields.advanced")}).click();
        await expect(dialog.locator(".alert")).toHaveCount(0);
        await flip(dialog, text("dialogs.fields.requireIps"), true);
        await expect(dialog.locator(".alert")).toContainText(text("dialogs.fields.requireIpsWarning"));
      });

      test("S5-r3-9, S5-r3-10: Cancel on the widened ask leaves no lock password in the mutations of the page; with nothing left to ask the dialog says to fill in every password", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        mock.screens.profiles = mock.screens.profiles.map((p) => (p.id === PROFILE.home ? {...p, locked: true} : p));
        // Nothing the person can type is enough: every request is refused again.
        mock.on("PATCH /endpoints/{id}", {status: 423, body: {...errorBody("profile_locked"), fields: [{name: "/lock_passwords", code: "required"}]}});
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.office}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Office PC"}));
        await selectOf(dialog, text("dialogs.fields.status")).click();
        await page.getByRole("option", {name: text("state.soft_disabled")}).click();
        await dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true}).click();
        const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
        const next = needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")});
        await needed.getByLabel(/Office/).fill(LOCK_PASSWORD);
        await next.click();
        // The second 423 widens the ask to Home too.
        await expect(needed.getByLabel(/Home/)).toBeVisible();
        expect(await mutationVariables(page), "the helper sees the mutation that carried the password").toContain(LOCK_PASSWORD);
        await needed.getByLabel(/Home/).fill(LOCK_PASSWORD);
        await next.click();
        // Both were asked, so there is nothing wider: the dialog says what to do instead of sending the person to unlock the profile.
        await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needText"));
        await expect(needed).not.toContainText(message(lang, "errors", "profile_locked"));
        await needed.getByRole("button", {name: cancel}).click();
        await expect(needed).toBeHidden();
        await expect(dialog).toBeVisible();
        await expect.poll(() => mutationVariables(page)).not.toContain(LOCK_PASSWORD);
        await expectNoSecretResidue(page, [LOCK_PASSWORD], "a cancelled lock password ask");
      });
    });

    test.describe("destinations", () => {
      test.use({allowConsole: [/status of 409/]});

      test("T-066: destinations_lost asks to confirm, and the request goes again with confirm_destinations; Cancel sends nothing more", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        const base = screenHandlers(mock.screens)["PATCH /endpoints/{id}"];
        mock.on("PATCH /endpoints/{id}", (call, state) =>
          (call.body as {confirm_destinations?: boolean}).confirm_destinations ? base!(call, state) : {status: 409, body: errorBody("destinations_lost")},
        );
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
        await dialog.getByRole("textbox", {name: text("dialogs.fields.name")}).fill("Laptop two");
        const save = dialog.getByRole("button", {name: text("dialogs.edit.submit"), exact: true});
        await save.click();
        const ask = dialogOf(page, text("dialogs.destinations.title"));
        await expect(ask).toContainText(text("dialogs.destinations.text"));
        await ask.getByRole("button", {name: cancel}).click();
        await expect(ask).toBeHidden();
        expect(callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.laptop}`)).toHaveLength(1);

        await save.click();
        await dialogOf(page, text("dialogs.destinations.title")).getByRole("button", {name: text("dialogs.destinations.continue")}).click();
        await expect(dialog).toBeHidden();
        const sent = callsTo(mock.calls, "PATCH", `/endpoints/${ENDPOINT.laptop}`);
        expect(sent.at(-1)!.body).toMatchObject({name: "Laptop two", confirm_destinations: true});
      });
    });

    test("the hold notice: an Endpoint an administrator holds says so in Edit, and its page says so under the tabs (D34)", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(`${endpointPath(lang, ENDPOINT.held, "clients")}?deviceDialog=edit&deviceId=${ENDPOINT.held}`);
      await expect(page.getByRole("dialog")).toContainText(text("dialogs.edit.held"));
      await expect(page.getByText(text("frame.held"))).toBeVisible();
    });

    test("Rotate asks first, says what it ends, and a new Resolver ID is made; Cancel keeps the old one", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      const before = mock.screens.endpoints.find((e) => e.id === ENDPOINT.laptop)!.resolver_id;
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
      const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
      await dialog.getByRole("button", {name: text("dialogs.edit.rotate.buttonAria", {name: "Laptop"})}).click();
      const confirm = dialogOf(page, text("dialogs.edit.rotate.confirmTitle", {name: "Laptop"}));
      await expect(confirm).toContainText(text("dialogs.edit.rotate.confirmText"));
      await confirm.getByRole("button", {name: cancel}).click();
      expect(mock.screens.endpoints.find((e) => e.id === ENDPOINT.laptop)!.resolver_id).toBe(before);
      await dialog.getByRole("button", {name: text("dialogs.edit.rotate.buttonAria", {name: "Laptop"})}).click();
      await confirm.getByRole("button", {name: text("dialogs.edit.rotate.confirm")}).click();
      await expect(confirm).toBeHidden();
      await expect.poll(() => mock.screens.endpoints.find((e) => e.id === ENDPOINT.laptop)!.resolver_id).not.toBe(before);
      expect(mock.screens.endpoints.find((e) => e.id === ENDPOINT.laptop)!.apple_profile_stale).toBe(true);
    });

    test.describe("a failed Rotate", () => {
      test.use({allowConsole: [/status of 5\d\d/]});

      test("S5-r2-9: the error stays in the Rotate dialog and its Retry rotates; the Edit form is not saved", async ({page, context, baseURL}) => {
        const mock = await openList(context, baseURL);
        const base = screenHandlers(mock.screens)["POST /endpoints/{id}:rotate-resolver"]!;
        let first = true;
        mock.on("POST /endpoints/{id}:rotate-resolver", (call, state) => {
          if (!first) return base(call, state);
          first = false;
          return {status: 503, body: errorBody("service_unavailable")};
        });
        await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
        const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
        // An unsaved change in the form: a Retry that saved the form would send it.
        await dialog.getByRole("textbox", {name: text("dialogs.fields.name")}).fill("Laptop two");
        await dialog.getByRole("button", {name: text("dialogs.edit.rotate.buttonAria", {name: "Laptop"})}).click();
        const confirm = dialogOf(page, text("dialogs.edit.rotate.confirmTitle", {name: "Laptop"}));
        await confirm.getByRole("button", {name: text("dialogs.edit.rotate.confirm")}).click();
        await expect(confirm).toBeVisible();
        await confirm.getByRole("button", {name: message(lang, "common", "retry")}).click();
        await expect(confirm).toBeHidden();
        expect(callsTo(mock.calls, "POST", /:rotate-resolver$/)).toHaveLength(2);
        expect(callsTo(mock.calls, "PATCH", /\/endpoints\//)).toHaveLength(0);
      });
    });

    test("a dialog keeps the page's language and direction, and Escape closes it and takes its parameters out of the address", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(`${endpointsPath(lang)}?deviceDialog=edit&deviceId=${ENDPOINT.laptop}`);
      const dialog = dialogOf(page, text("dialogs.edit.title", {name: "Laptop"}));
      await expect(dialog).toBeVisible();
      await expect(page.locator("html")).toHaveAttribute("dir", dir);
      await page.keyboard.press("Escape");
      await expect(dialog).toBeHidden();
      await expect(page).not.toHaveURL(/deviceDialog|deviceId/);
    });
  });
}
