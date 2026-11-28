import {nodeFixture, pairFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import {createNodeMock, type NodeMockState} from "@ctrlz/api-client/testing/nodeMock.ts";
import type {Locator, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {adm, allowAdminErrors, bodies, err, errText, gotoShell, LANGS, nodesText, openAdmin, typeCode, type Lang} from "./admin-support.ts";

// p4-nodes 10.1, package PD: the Pair page, in mock mode (spec 17.1). T-341 is the one Plan row: primary and fallback are chosen here, the node
// each pair advertises is shown, the page refuses with its reason what the table would refuse, and it says every case of SC 8a.9 "F0 reads no
// tracker" that concerns a pair change. The writes need the fresh TOTP window, as on the real routes (`freshRequired`).

test.beforeEach(({guard}) => allowAdminErrors(guard));

const CODE = "123456";
const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000).toISOString();

/**
 * Six nodes: two in the global pair, two active and free (one of them just heard from, one not for twenty minutes), one waiting for approval
 * and one revoked. `pairs` is the global pair only unless a case adds a second.
 */
function world(over: Partial<NodeMockState> = {}) {
  const a = nodeFixture({slot: 1, name: "tehran-1"});
  const b = nodeFixture({slot: 2, name: "tehran-2"});
  const c = nodeFixture({slot: 3, name: "shiraz-1"});
  const e = nodeFixture({slot: 4, name: "tabriz-1", last_heartbeat_at: minutesAgo(20)});
  const p = nodeFixture({slot: 5, name: "yazd-1", status: "pending"});
  const r = nodeFixture({slot: 6, name: "rasht-1", status: "revoked"});
  return {a, b, c, e, p, r, ...createNodeMock({nodes: [a, b, c, e, p, r], pairs: [pairFixture(a, b)], ...over})};
}

const rowOf = (grid: Locator, name: string) => grid.getByRole("row").filter({has: grid.page().getByText(name, {exact: true})});

for (const {lang, dir} of LANGS) {
  test.describe(`admin pair page, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);
    const N = (path: string, values?: Record<string, string | number>) => nodesText(lang, path, values);
    const goto = (page: Page, path = "/pair") => gotoShell(page, lang as Lang, path, N("pages.pair.title"));
    const grid = (page: Page) => page.getByRole("grid", {name: N("pair.grid.label")});
    const dialogOf = (page: Page, title: string) => page.getByRole("dialog", {name: title});
    const waitFresh = async (page: Page) => {
      await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
      await typeCode(page, "totp_code", CODE);
    };
    /** Chooses a node in the select whose label is `label`, by the name the option starts with. */
    const choose = async (dialog: Locator, label: string, name: string) => {
      await dialog.getByRole("button", {name: label}).click();
      await dialog.page().getByRole("option", {name: new RegExp(`^${name}`)}).click();
    };
    const openCreate = async (page: Page) => {
      await page.getByRole("button", {name: N("pair.create")}).click();
      const dialog = dialogOf(page, N("pair.form.createTitle"));
      await expect(dialog).toBeVisible();
      return dialog;
    };

    // ---- what is shown ----------------------------------------------------------------------------------------------------------

    test("T-341: the global pair, primary first, with the node that answers and a copy button that names what it copies", async ({page, context, baseURL}) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const card = page.getByTestId("pair-global");
      await expect(card.getByTestId("global-primary")).toContainText("tehran-1");
      await expect(card.getByTestId("global-primary").locator('bdi[dir="ltr"]')).toHaveText(w.a.dns_advertised_ip!);
      await expect(card.getByTestId("global-fallback")).toContainText("tehran-2");
      await expect(card.locator("[data-advertised]")).toHaveAttribute("data-advertised", "primary");
      await expect(card.locator("[data-advertised]")).toContainText(N("pair.advertised.primary", {name: "tehran-1"}));
      await card.getByRole("button", {name: N("pair.global.copy", {role: N("pair.global.primary")})}).click();
      await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(w.a.dns_advertised_ip);
    });

    test("T-341: with no pair the global card says the first pair becomes global, and the list is empty", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: createNodeMock({nodes: [nodeFixture({slot: 1, name: "tehran-1"})]}).handlers});
      await goto(page);
      await expect(page.getByTestId("pair-global-none")).toContainText(N("pair.global.none.title"));
      await expect(page.getByTestId("grid-empty")).toContainText(N("pair.grid.empty.title"));
    });

    test("T-341: each pair shows both nodes with their state as words, the node whose address is advertised, and whether it is the global pair", async ({page, context, baseURL}) => {
      const w = world();
      w.state.pairs.push(pairFixture(w.c, w.e, {is_global: false}));
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const g = grid(page);
      await expect(g.getByRole("row")).toHaveCount(3);
      const first = rowOf(g, "tehran-1");
      await expect(first).toContainText(N("health.serving"));
      await expect(first.getByTestId(`global-chip-${w.state.pairs[0]!.id}`)).toHaveText(N("pair.grid.global"));
      await expect(first).toContainText("tehran-2");
      const second = rowOf(g, "shiraz-1");
      await expect(second).toContainText(N("pair.grid.unused"));
      // The fallback is out of touch for twenty minutes, in words and not in colour.
      await expect(second).toContainText(N("health.out_of_touch"));
    });

    test("T-341: a withdrawn or held primary hands the advertised node to the fallback, and two withdrawn nodes advertise none", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[0] = {...w.a, dns_withdrawn: true};
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const id = w.state.pairs[0]!.id;
      await expect(page.getByTestId(`advertised-${id}`).locator("[data-advertised]")).toHaveAttribute("data-advertised", "fallback");
      await expect(page.getByTestId(`advertised-${id}`)).toContainText(N("pair.advertised.fallback", {name: "tehran-2"}));
      w.state.nodes[1] = {...w.b, dns_withdrawn: true, dns_hold: true};
      await page.reload();
      await expect(page.getByTestId(`advertised-${id}`).locator("[data-advertised]")).toHaveAttribute("data-advertised", "none");
      await expect(page.getByTestId(`advertised-${id}`)).toContainText(N("pair.advertised.none"));
    });

    test("T-341: the page says all three cases of SC 8a.9 at rest, and the order of a replacement when every slot is held", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const notes = page.getByTestId("pair-notes");
      for (const id of ["withdrawn", "both", "oneAtATime", "noPeer"]) {
        await expect(notes.locator(`[data-note="${id}"]`)).toContainText(N(`pair.notes.items.${id}.title`));
        await expect(notes.locator(`[data-note="${id}"]`)).toContainText(N(`pair.notes.items.${id}.text`));
      }
      await expect(page.getByTestId("pair-slots")).toContainText(N("pair.notes.slots.title"));
      await expect(notes.getByTestId("pair-runbook-link")).toHaveAttribute("href", new RegExp(`/${lang}/runbook$`));
    });

    test("T-341: the order of a replacement is not said while a slot is free", async ({page, context, baseURL}) => {
      const a = nodeFixture({slot: 1, name: "tehran-1"});
      const b = nodeFixture({slot: 2, name: "tehran-2"});
      await openAdmin(context, baseURL, {handlers: createNodeMock({nodes: [a, b], pairs: [pairFixture(a, b)]}).handlers});
      await goto(page);
      await expect(page.getByTestId("pair-notes")).toBeVisible();
      await expect(page.getByTestId("pair-slots")).toHaveCount(0);
    });

    // ---- a new pair -------------------------------------------------------------------------------------------------------------

    test("T-341: only an active node in no pair is offered, and the others are listed with the reason", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const dialog = await openCreate(page);
      await dialog.getByRole("button", {name: N("pair.form.primary")}).click();
      await expect(page.getByRole("option")).toHaveCount(6);
      const option = (name: string) => page.getByRole("option", {name: new RegExp(`^${name}`)});
      await expect(option("shiraz-1")).toBeEnabled();
      await expect(option("tehran-1")).toHaveAttribute("aria-disabled", "true");
      await expect(option("tehran-1")).toContainText(N("pair.form.notOffered.inPair", {peer: "tehran-2"}));
      await expect(option("yazd-1")).toContainText(N("pair.form.notOffered.pending"));
      await expect(option("yazd-1")).toHaveAttribute("aria-disabled", "true");
      await expect(option("rasht-1")).toContainText(N("pair.form.notOffered.revoked"));
      await expect(option("rasht-1")).toHaveAttribute("aria-disabled", "true");
    });

    test("T-341: the first pair is the global pair in the same change, the box cannot be cleared, and the write is repeated after the fresh code", async ({page, context, baseURL}) => {
      const a = nodeFixture({slot: 1, name: "tehran-1"});
      const b = nodeFixture({slot: 2, name: "tehran-2"});
      const w = createNodeMock({nodes: [a, b], freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const dialog = await openCreate(page);
      const global = dialog.getByRole("checkbox", {name: N("pair.form.makeGlobal")});
      await expect(global).toBeChecked();
      await expect(global).toBeDisabled();
      await expect(dialog).toContainText(N("pair.form.makeGlobalForced"));
      await choose(dialog, N("pair.form.primary"), "tehran-1");
      await choose(dialog, N("pair.form.fallback"), "tehran-2");
      await dialog.getByRole("button", {name: N("pair.form.submitCreate")}).click();
      await waitFresh(page);
      const want = {primary_node_id: a.id, fallback_node_id: b.id, make_global: true};
      await expect.poll(() => bodies(mock, "POST", "/pairs")).toEqual([want, want]);
      await expect(dialog).toHaveCount(0);
      await expect(page.getByTestId("pair-global-none")).toHaveCount(0);
      await expect(grid(page).getByRole("row")).toHaveCount(2);
      expect(page.url()).not.toContain("dialog=");
    });

    test("T-341: a second pair needs no global switch and is not made global unless asked", async ({page, context, baseURL}) => {
      const w = world();
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const dialog = await openCreate(page);
      const global = dialog.getByRole("checkbox", {name: N("pair.form.makeGlobal")});
      await expect(global).not.toBeChecked();
      await expect(global).toBeEnabled();
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await choose(dialog, N("pair.form.fallback"), "tabriz-1");
      await dialog.getByRole("button", {name: N("pair.form.submitCreate")}).click();
      await expect.poll(() => bodies(mock, "POST", "/pairs")).toEqual([{primary_node_id: w.c.id, fallback_node_id: w.e.id}]);
      await expect(grid(page).getByRole("row")).toHaveCount(3);
    });

    test("T-341: SC 8a.9 sentences that name this change appear while the nodes are chosen: two new nodes, a node that may be behind", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const dialog = await openCreate(page);
      await expect(dialog.getByTestId("pair-form-warnings")).toHaveCount(0);
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await choose(dialog, N("pair.form.fallback"), "tabriz-1");
      const warnings = dialog.getByTestId("pair-form-warnings");
      await expect(warnings.locator('[data-warning="twoNew"]')).toBeVisible();
      // tabriz-1 was last heard from twenty minutes ago.
      const behind = warnings.locator('[data-warning="behind"]');
      await expect(behind).toContainText("tabriz-1");
      await expect(behind).not.toContainText("shiraz-1");
    });

    test("T-341: a withdrawn primary, and a held fallback beside it, are said before the change is sent", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[2] = {...w.c, dns_withdrawn: true};
      w.state.nodes[3] = {...w.e, dns_withdrawn: true, dns_hold: true, last_heartbeat_at: minutesAgo(0)};
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const dialog = await openCreate(page);
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await choose(dialog, N("pair.form.fallback"), "tabriz-1");
      const warnings = dialog.getByTestId("pair-form-warnings");
      await expect(warnings.locator('[data-warning="primaryWithdrawn"]')).toContainText("shiraz-1");
      await expect(warnings.locator('[data-warning="fallbackHeld"]')).toContainText("tabriz-1");
    });

    test("T-341: two nodes that advertise one address are refused before any request, with the reason and the nodes", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[3] = {...w.e, dns_advertised_ip: w.c.dns_advertised_ip!};
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const dialog = await openCreate(page);
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await choose(dialog, N("pair.form.fallback"), "tabriz-1");
      const refusals = dialog.getByTestId("pair-refusals");
      await expect(refusals.locator('[data-refusal="duplicateAddress"]')).toContainText("shiraz-1");
      await expect(refusals.locator('[data-refusal="duplicateAddress"]')).toContainText("tabriz-1");
      await expect(dialog.getByRole("button", {name: N("pair.form.submitCreate")})).toBeDisabled();
      await page.keyboard.press("Enter");
      expect(mock.count("POST /pairs")).toBe(0);
    });

    test("T-341: two address families in one pair are refused before any request", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[3] = {...w.e, dns_advertised_ip: "2001:db8::4", proxy_advertised_ip: "2001:db8::5"};
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const dialog = await openCreate(page);
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await choose(dialog, N("pair.form.fallback"), "tabriz-1");
      await expect(dialog.locator('[data-refusal="mixedFamilies"]')).toBeVisible();
      await expect(dialog.getByRole("button", {name: N("pair.form.submitCreate")})).toBeDisabled();
      expect(mock.count("POST /pairs")).toBe(0);
    });

    test("T-341: a node cannot be both roles: the other select does not offer the one already chosen", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const dialog = await openCreate(page);
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await dialog.getByRole("button", {name: N("pair.form.fallback")}).click();
      await expect(page.getByRole("option", {name: /^shiraz-1/})).toHaveAttribute("aria-disabled", "true");
    });

    test("T-341: the refusals of the route show with the words of their code, and the dialog stays so the choice can be changed", async ({page, context, baseURL}) => {
      const w = world();
      let code = "table_invalid";
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "POST /pairs": () => err(409, code)}});
      await goto(page);
      const dialog = await openCreate(page);
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await choose(dialog, N("pair.form.fallback"), "tabriz-1");
      const submit = dialog.getByRole("button", {name: N("pair.form.submitCreate")});
      await submit.click();
      await expect(dialog.getByText(errText(lang, "table_invalid"))).toBeVisible();
      for (code of ["second_peer", "node_state", "global_pair_required"]) {
        await submit.click();
        await expect(dialog.getByText(errText(lang, code))).toBeVisible();
      }
      await expect(dialog).toBeVisible();
    });

    test("the dialog is a link: Back closes it, a direct link opens it, and Escape closes it", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const dialog = await openCreate(page);
      expect(page.url()).toContain("dialog=newPair");
      await page.goBack();
      await expect(dialog).toHaveCount(0);
      await goto(page, "/pair?dialog=newPair");
      await expect(dialogOf(page, N("pair.form.createTitle"))).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(dialogOf(page, N("pair.form.createTitle"))).toHaveCount(0);
      expect(page.url()).not.toContain("dialog=");
    });

    // ---- an edit ----------------------------------------------------------------------------------------------------------------

    test("T-341: the edit of a pair is a link with the pair in it, nothing to send until a choice differs, and a swap of the roles is said and sent", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const id = w.state.pairs[0]!.id;
      await page.getByTestId(`pair-edit-${id}`).click();
      const dialog = dialogOf(page, N("pair.form.editTitle"));
      await expect(dialog).toBeVisible();
      expect(page.url()).toContain(`pairId=${id}`);
      // As the pair stands there is nothing to say, and the refusal "no change" keeps Save off.
      await expect(dialog.getByTestId("pair-form-warnings")).toHaveCount(0);
      const save = dialog.getByRole("button", {name: N("pair.form.submitEdit")});
      await expect(save).toBeDisabled();
      await expect(dialog.locator('[data-refusal="same"]')).toContainText(N("pair.form.refusal.same"));
      await dialog.getByTestId("pair-swap").click();
      await expect(dialog.locator('[data-warning="swap"]')).toContainText("tehran-2");
      await save.click();
      await waitFresh(page);
      const want = {primary_node_id: w.b.id, fallback_node_id: w.a.id};
      await expect.poll(() => bodies(mock, "PUT", `/pairs/${id}`)).toEqual([want, want]);
      await expect(dialog).toHaveCount(0);
      expect(page.url()).not.toContain("pairId=");
    });

    test("T-341: a swap with a node that may be behind says so, by name", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[1] = {...w.b, applied_seq: 118, applied_seq_lag: 2};
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await page.getByTestId(`pair-edit-${w.state.pairs[0]!.id}`).click();
      const dialog = dialogOf(page, N("pair.form.editTitle"));
      await dialog.getByTestId("pair-swap").click();
      const behind = dialog.locator('[data-warning="behind"]');
      await expect(behind).toContainText("tehran-2");
      await expect(behind).not.toContainText("tehran-1");
    });

    test("T-341: a held fallback must be released or replaced before the primary changes, and replacing only the fallback is allowed", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[1] = {...w.b, dns_hold: true, dns_withdrawn: true};
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const id = w.state.pairs[0]!.id;
      await page.getByTestId(`pair-edit-${id}`).click();
      const dialog = dialogOf(page, N("pair.form.editTitle"));
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await expect(dialog.locator('[data-warning="heldFallbackFirst"]')).toContainText("tehran-2");
      // The primary stays and only the fallback is replaced: that sentence goes.
      await choose(dialog, N("pair.form.primary"), "tehran-1");
      await choose(dialog, N("pair.form.fallback"), "shiraz-1");
      await expect(dialog.locator('[data-warning="heldFallbackFirst"]')).toHaveCount(0);
      await dialog.getByRole("button", {name: N("pair.form.submitEdit")}).click();
      await expect.poll(() => bodies(mock, "PUT", `/pairs/${id}`)).toEqual([{primary_node_id: w.a.id, fallback_node_id: w.c.id}]);
      // The dialog closes with a step back in the history: the test ends after that, not in the middle of it (the guard closes the page next).
      await expect(dialog).toHaveCount(0);
      expect(page.url()).not.toContain("pairId=");
    });

    test("PG-r1-2: a node in no pair made the primary is withdrawn by the change, and the answer goes at once to the fallback that stays", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[1] = {...w.b, applied_seq: 118, applied_seq_lag: 2};
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await page.getByTestId(`pair-edit-${w.state.pairs[0]!.id}`).click();
      const dialog = dialogOf(page, N("pair.form.editTitle"));
      // The compromise runbook, step 2: (tehran-1, tehran-2) becomes (shiraz-1, tehran-2).
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      const warnings = dialog.getByTestId("pair-form-warnings");
      await expect(warnings.locator('[data-warning="primaryWithdrawn"]')).toContainText("shiraz-1");
      // The node that receives the answer may be behind, and it is named.
      await expect(warnings.locator('[data-warning="behind"]')).toContainText("tehran-2");
    });

    test("PG-r1-14: the pair is read again before the write that follows the fresh code, and a pair that moved meanwhile is not overwritten", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const id = w.state.pairs[0]!.id;
      await page.getByTestId(`pair-edit-${id}`).click();
      const dialog = dialogOf(page, N("pair.form.editTitle"));
      await dialog.getByTestId("pair-swap").click();
      await dialog.getByRole("button", {name: N("pair.form.submitEdit")}).click();
      await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
      // Another admin replaces the fallback while the code is being fetched.
      w.state.pairs[0] = {...w.state.pairs[0]!, fallback_node_id: w.c.id};
      await typeCode(page, "totp_code", CODE);
      await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
      // Only the first try, the one that met the fresh-code answer, reached the route.
      expect(bodies(mock, "PUT", `/pairs/${id}`)).toHaveLength(1);
      await expect(dialog).toBeVisible();
    });

    test("PG-r2-5: a forced make_global is not repeated when another admin made a pair global while the code was typed", async ({page, context, baseURL}) => {
      const a = nodeFixture({slot: 1, name: "tehran-1"});
      const b = nodeFixture({slot: 2, name: "tehran-2"});
      const c = nodeFixture({slot: 3, name: "shiraz-1"});
      const e = nodeFixture({slot: 4, name: "tabriz-1"});
      const w = createNodeMock({nodes: [a, b, c, e], freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const dialog = await openCreate(page);
      await expect(dialog.getByRole("checkbox", {name: N("pair.form.makeGlobal")})).toBeChecked();
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await choose(dialog, N("pair.form.fallback"), "tabriz-1");
      await dialog.getByRole("button", {name: N("pair.form.submitCreate")}).click();
      await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
      // Another admin makes (tehran-1, tehran-2) the global pair while the code is being fetched.
      w.state.pairs.push(pairFixture(a, b));
      await typeCode(page, "totp_code", CODE);
      await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
      expect(bodies(mock, "POST", "/pairs")).toHaveLength(1);
      await expect(dialog).toBeVisible();
    });

    test("PG-r2-8: a node the hub withdrew while the code was typed stops the repeated write, so the warnings are read again", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const dialog = await openCreate(page);
      await choose(dialog, N("pair.form.primary"), "shiraz-1");
      await choose(dialog, N("pair.form.fallback"), "tabriz-1");
      await dialog.getByRole("button", {name: N("pair.form.submitCreate")}).click();
      await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
      w.state.nodes[2] = {...w.c, dns_withdrawn: true};
      await typeCode(page, "totp_code", CODE);
      await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
      expect(bodies(mock, "POST", "/pairs")).toHaveLength(1);
      await expect(dialog).toBeVisible();
    });

    test("PG-r2-6: a revoked node that is still in its pair is marked as such, the page says to replace it, and its address cannot be copied", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[0] = {...w.a, status: "revoked"};
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const card = page.getByTestId("pair-global");
      await expect(card.locator("[data-advertised]")).toHaveAttribute("data-advertised", "revoked");
      await expect(card.locator("[data-advertised]")).toContainText(N("pair.advertised.revoked", {name: "tehran-1"}));
      await expect(card.getByTestId("pair-revoked-member")).toContainText(N("pair.advertised.revokedMember", {names: "tehran-1"}));
      await expect(card.getByTestId("pair-revoked-member").getByRole("link", {name: N("givenUp.runbook")})).toHaveAttribute("href", new RegExp("/runbook#compromise$"));
      await expect(card.getByRole("button", {name: N("pair.global.copy", {role: N("pair.global.primary")})})).toHaveCount(0);
      // Its peer is active, so that address is still offered.
      await expect(card.getByRole("button", {name: N("pair.global.copy", {role: N("pair.global.fallback")})})).toHaveCount(1);
    });

    test("a link to a pair that is not there opens nothing, and leaves a clean address", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page, "/pair?dialog=editPair&pairId=00000000-0000-4000-8000-0000000000ff");
      await expect.poll(() => page.url()).not.toContain("pairId=");
      await expect(page.getByRole("dialog")).toHaveCount(0);
    });

    test("PG-r3-2: a link to a pair is kept while the list of pairs fails, and is not called stale", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "GET /pairs": () => err(503, "internal")}});
      await goto(page, `/pair?dialog=editPair&pairId=${w.state.pairs[0]!.id}`);
      await page.waitForTimeout(500);
      expect(page.url()).toContain("pairId=");
      await expect(page.getByText(N("pair.stale"))).toHaveCount(0);
    });

    // ---- the global pair and removal ---------------------------------------------------------------------------------------------

    test("T-341: making another pair global names what it does (no peer changes) and is sent with the fresh code", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const second = pairFixture(w.c, w.e, {is_global: false});
      w.state.pairs.push(second);
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await page.getByTestId(`pair-global-${second.id}`).click();
      const dialog = page.getByRole("alertdialog");
      await expect(dialog).toBeVisible();
      await expect(dialog.getByTestId("pair-switch-warnings").locator('[data-warning="swap"]')).toBeVisible();
      // tabriz-1 was heard from twenty minutes ago.
      await expect(dialog.locator('[data-warning="behind"]')).toContainText("tabriz-1");
      await expect(dialog).toContainText(N("pair.switch.free"));
      await dialog.getByTestId("pair-switch-confirm").click();
      await waitFresh(page);
      await expect.poll(() => bodies(mock, "PUT", "/settings/global-pair")).toEqual([{pair_id: second.id}, {pair_id: second.id}]);
      await expect(page.getByTestId(`global-chip-${second.id}`)).toBeVisible();
      await expect(page.getByTestId("pair-global").getByTestId("global-primary")).toContainText("shiraz-1");
    });

    test("T-341: the global pair cannot be removed and its button says why; another pair is removed after a confirmation", async ({page, context, baseURL}) => {
      const w = world();
      const second = pairFixture(w.c, w.e, {is_global: false});
      w.state.pairs.push(second);
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const globalId = w.state.pairs[0]!.id;
      const blocked = page.getByTestId(`pair-remove-${globalId}`);
      await expect(blocked).toBeDisabled();
      await expect(blocked).toHaveAttribute("aria-label", N("pair.actions.removeGlobalRow", {primary: "tehran-1", fallback: "tehran-2"}));
      await page.getByTestId(`pair-remove-${second.id}`).click();
      const dialog = page.getByRole("alertdialog");
      await expect(dialog).toContainText(N("pair.remove.text"));
      await dialog.getByTestId("pair-remove-confirm").click();
      await expect.poll(() => mock.count("DELETE /pairs/{id}")).toBe(1);
      await expect(grid(page).getByRole("row")).toHaveCount(2);
    });

    test("T-341: a refusal of the removal shows in its dialog with the words of its code", async ({page, context, baseURL}) => {
      const w = world();
      const second = pairFixture(w.c, w.e, {is_global: false});
      w.state.pairs.push(second);
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "DELETE /pairs/{id}": err(409, "pair_in_use")}});
      await goto(page);
      await page.getByTestId(`pair-remove-${second.id}`).click();
      const dialog = page.getByRole("alertdialog");
      await dialog.getByTestId("pair-remove-confirm").click();
      await expect(dialog.getByTestId("action-error")).toHaveText(errText(lang, "pair_in_use"));
    });

    test("the nodes of the page open their own page", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await grid(page).getByRole("link", {name: N("nodes.openRow", {name: "tehran-1"})}).click();
      await expect(page).toHaveURL(new RegExp(`/nodes/${w.a.id}$`));
    });
  });
}
