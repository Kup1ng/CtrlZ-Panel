import {nodeFixture, pairFixture, freeCounterFixture, givenUpFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import {createNodeMock, type NodeMockState} from "@ctrlz/api-client/testing/nodeMock.ts";
import type {Locator, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {adm, allowAdminErrors, bodies, commonText, err, errText, gotoShell, LANGS, nodesText, openAdmin, typeCode, type Lang} from "./admin-support.ts";

// p4-nodes 10.1, package PF: the Overview and the Nodes page, in mock mode (spec 17.1). Each case names the Plan row it closes:
// T-339 (the overview), T-556 (the addresses of free DNS and its switch), T-546 (the addresses given up and their fixed note),
// T-561 (the runbook link). The writes need the fresh TOTP window, as on the real routes (`freshRequired`).

test.beforeEach(({guard}) => allowAdminErrors(guard));

const CODE = "123456";
const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000).toISOString();

/** Four nodes: one serving, one held and two behind, one out of touch and one waiting for approval; the first two are the global pair. */
function world(over: Partial<NodeMockState> = {}) {
  const a = nodeFixture({slot: 1, name: "tehran-1", qps: 200, cache_hit_permille: 900});
  const b = nodeFixture({slot: 2, name: "tehran-2", qps: 140, cache_hit_permille: 950, dns_hold: true, applied_seq: 118, applied_seq_lag: 2});
  const c = nodeFixture({slot: 3, name: "shiraz-1", last_heartbeat_at: minutesAgo(20)});
  const d = nodeFixture({slot: 4, name: "tabriz-1", status: "pending"});
  return {a, b, c, d, ...createNodeMock({nodes: [a, b, c, d], pairs: [pairFixture(a, b)], ...over})};
}

/** Digits as the page of a language shows them. */
/** The row of a grid whose first cell is this exact name: "tehran-1" must not find the row that says "with tehran-1". */
const rowOf = (grid: Locator, name: string) => grid.getByRole("row").filter({has: grid.page().getByText(name, {exact: true})});

const num = (lang: Lang, n: number, useGrouping = false) => new Intl.NumberFormat(lang === "fa" ? "fa-IR-u-nu-arabext" : "en-US", {useGrouping}).format(n);

for (const {lang, dir} of LANGS) {
  test.describe(`admin nodes, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);
    const N = (path: string, values?: Record<string, string | number>) => nodesText(lang, path, values);
    const goto = (page: Page, path: string, title: string) => gotoShell(page, lang as Lang, path, title);

    // ---- Overview (T-339) -------------------------------------------------------------------------------------------------------

    test.describe("overview", () => {
      test("T-339: the totals are node-wide, and a figure the system has not got says it is not reported yet", async ({page, context, baseURL}) => {
        const w = world();
        await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/overview", N("pages.overview.title"));
        const kpis = page.getByTestId("overview-kpis");
        await expect(kpis.getByTestId("kpi-serving")).toContainText(N("overview.kpi.servingValue", {serving: num(lang, 1), total: num(lang, 3)}));
        // 200 + 140 queries a second, from the nodes that reported one; the cache rate is weighted by those queries.
        await expect(kpis.getByTestId("kpi-qps")).toContainText(num(lang, 340));
        await expect(kpis.getByTestId("kpi-cache")).toContainText(lang === "fa" ? "٪" : "%");
        await expect(kpis.getByTestId("kpi-head")).toContainText(num(lang, 120));
        await expect(kpis.getByTestId("kpi-free")).toContainText(N("overview.free.limit", {qps: num(lang, 1000)}));
      });

      test("T-339: with no node reporting a QPS the tile says so instead of showing zero", async ({page, context, baseURL}) => {
        const a = nodeFixture({slot: 1});
        const mock = createNodeMock({nodes: [a]});
        await openAdmin(context, baseURL, {handlers: {...mock.handlers, "GET /overview": {body: {nodes: [a], config_head: 120, free_dns: {enabled: false, qps: 500, version: 2}}}}});
        await goto(page, "/overview", N("pages.overview.title"));
        await expect(page.getByTestId("kpi-qps")).toContainText(N("notReported"));
        await expect(page.getByTestId("kpi-cache")).toContainText(N("notReported"));
        await expect(page.getByTestId("kpi-free")).toContainText(N("overview.free.off"));
      });

      test("T-339: each node has its state as a word, its last contact, its versions and its lag, and the hub's view is 'not reported yet'", async ({page, context, baseURL}) => {
        const w = world();
        await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/overview", N("pages.overview.title"));
        const grid = page.getByRole("grid", {name: N("overview.nodes.gridLabel")});
        await expect(grid.getByRole("row")).toHaveCount(5);
        const row = (name: string) => rowOf(grid, name);
        await expect(row("tehran-1")).toContainText(N("health.serving"));
        await expect(row("tehran-1")).toContainText(N("overview.nodes.lag.upToDate"));
        await expect(row("tehran-1").locator('bdi[dir="ltr"]').first()).toHaveText("0.4.2");
        await expect(row("tehran-2")).toContainText(N("health.held"));
        // Two entries behind: the figures "applied of head" are there, in the page's own digits.
        await expect(row("tehran-2")).toContainText(N("overview.nodes.lag.applied", {applied: num(lang, 118), head: num(lang, 120)}));
        await expect(row("shiraz-1")).toContainText(N("health.out_of_touch"));
        await expect(row("tabriz-1")).toContainText(N("health.pending"));
        // The hub's own parts are not in the document yet: every row says so, in words.
        await expect(row("tehran-1")).toContainText(N("notReported"));
        // The state is a word with an icon, so colour is never the only sign: every chip holds text.
        for (const chip of await grid.locator("[data-health]").all()) await expect(chip).not.toHaveText("");
      });

      test("T-339: a hub verdict is shown beside the node's state when the document carries one", async ({page, context, baseURL}) => {
        const a = nodeFixture({slot: 1, name: "tehran-1"});
        const withHub = {...a, health: "degraded"};
        await openAdmin(context, baseURL, {handlers: {"GET /overview": {body: {nodes: [withHub], config_head: 120, free_dns: {enabled: true, qps: 1000, version: 1}}}}});
        await goto(page, "/overview", N("pages.overview.title"));
        await expect(page.locator('[data-hub-health="degraded"]')).toHaveText(N("hubHealth.degraded"));
      });

      test("T-339: the free DNS counters are by node, transport, outcome and rcode, and show no name and no address", async ({page, context, baseURL}) => {
        const a = nodeFixture({slot: 1, name: "tehran-1"});
        const b = nodeFixture({slot: 2, name: "tehran-2"});
        const hour = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000 - 3_600_000).toISOString();
        const counters = [
          freeCounterFixture(a, {bucket_start: hour, count: 1200}),
          freeCounterFixture(a, {bucket_start: hour, outcome: "rd0", rcode: 5, count: 30}),
          freeCounterFixture(b, {bucket_start: hour, transport: "tcp", outcome: "rate_limited", rcode: 2, count: 4}),
        ];
        const w = createNodeMock({nodes: [a, b], counters});
        const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/overview", N("pages.overview.title"));
        const grid = page.getByRole("grid", {name: N("overview.counters.gridLabel")});
        await expect(grid.getByRole("row")).toHaveCount(4);
        await expect(grid.getByRole("row").filter({hasText: N("outcome.answered")})).toContainText("UDP");
        await expect(grid.getByRole("row").filter({hasText: N("outcome.rd0")})).toContainText("REFUSED");
        await expect(grid.getByRole("row").filter({hasText: N("outcome.rate_limited")})).toContainText("SERVFAIL");
        await expect(page.getByTestId("counters-total")).toContainText(num(lang, 1234, true));
        await expect(page.getByTestId("free-counters")).toContainText(N("overview.counters.text"));
        // No address of a node, and no domain, is in the table: the counters name a node and nothing else.
        expect(await grid.innerText()).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
        // The window is a whole number of hours ending with this one, and a week asks again with a longer one.
        const first = mock.calls.find((c) => c.path === "/free-dns/counters")!;
        const hours = (Date.parse(first.query.get("to")!) - Date.parse(first.query.get("from")!)) / 3_600_000;
        expect(hours).toBe(24);
        await page.getByRole("radio", {name: N("overview.counters.window.week")}).click();
        await expect.poll(() => mock.calls.filter((c) => c.path === "/free-dns/counters").length).toBe(2);
        const second = mock.calls.filter((c) => c.path === "/free-dns/counters")[1]!;
        expect((Date.parse(second.query.get("to")!) - Date.parse(second.query.get("from")!)) / 3_600_000).toBe(168);
      });

      test("T-339: a period with nothing counted is an empty state, and a failed read has Retry that asks again", async ({page, context, baseURL}) => {
        const w = world();
        let failing = true;
        await openAdmin(context, baseURL, {handlers: {...w.handlers, "GET /free-dns/counters": () => (failing ? err(500, "internal") : {body: {items: []}})}});
        await goto(page, "/overview", N("pages.overview.title"));
        const section = page.getByTestId("free-counters");
        await expect(section.getByRole("alert")).toContainText(errText(lang, "internal"));
        // The nodes above it are still there: one failed section does not take the page down.
        await expect(page.getByRole("grid", {name: N("overview.nodes.gridLabel")})).toBeVisible();
        failing = false;
        await section.getByRole("button", {name: commonText(lang, "retry")}).click();
        await expect(section.getByTestId("counters-empty")).toContainText(N("overview.counters.empty.title"));
      });

      test("T-339: no node yet is an empty state, and a failed overview has Retry that asks again", async ({page, context, baseURL}) => {
        let failing = true;
        const mock = await openAdmin(context, baseURL, {
          handlers: {"GET /overview": () => (failing ? err(500, "internal") : {body: {nodes: [], config_head: 0, free_dns: {enabled: true, qps: 1000, version: 1}}})},
        });
        await page.goto(`/${lang}/overview`);
        await expect(page.getByRole("alert").filter({hasText: errText(lang, "internal")})).toBeVisible();
        failing = false;
        await page.getByRole("button", {name: commonText(lang, "retry")}).click();
        await expect(page.getByTestId("grid-empty")).toContainText(N("overview.nodes.empty.title"));
        expect(mock.count("GET /overview")).toBeGreaterThanOrEqual(2);
      });
    });

    // ---- Navigation -------------------------------------------------------------------------------------------------------------

    test.describe("navigation", () => {
      test("the root of the admin is Overview, and the sidebar lists Overview, Nodes, Pair and Domain before the P1 pages", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: world().handlers});
        await page.goto(`/${lang}`);
        await expect(page).toHaveURL(new RegExp(`/${lang}/overview$`));
        // Each entry is a link in the sidebar, in this order down the list: the four of P4, then the pages of P1.
        const names = [N("nav.overview"), N("nav.nodes"), N("nav.pair"), N("nav.domain"), A("nav.users")];
        const ys: number[] = [];
        for (const name of names) {
          const entry = page.locator("aside.sidebar").getByText(name, {exact: true});
          await expect(entry).toBeVisible();
          ys.push((await entry.boundingBox())!.y);
        }
        expect([...ys].sort((p, q) => p - q)).toEqual(ys);
        await expect(page.locator('aside.sidebar [data-current="true"]')).toContainText(N("nav.overview"));
      });

      test("Pair and Domain open their own page with its header and its content, never a 404 and no placeholder", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: world().handlers});
        await goto(page, "/pair", N("pages.pair.title"));
        await expect(page.getByTestId("pair-global")).toBeVisible();
        await goto(page, "/domain", N("pages.domain.title"));
        await expect(page.getByTestId("domain-form")).toBeVisible();
      });
    });

    // ---- Nodes ------------------------------------------------------------------------------------------------------------------

    test.describe("nodes", () => {
      test("the nodes are listed with their state, their advertised addresses as technical tokens and their pair", async ({page, context, baseURL}) => {
        const w = world();
        await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const grid = page.getByRole("grid", {name: N("nodes.gridLabel")});
        await expect(grid.getByRole("row")).toHaveCount(5);
        const row = (name: string) => rowOf(grid, name);
        await expect(row("tehran-1").locator('bdi[dir="ltr"]').first()).toHaveText(w.a.dns_advertised_ip!);
        await expect(row("tehran-1")).toContainText(N("nodes.pair.with", {name: "tehran-2"}));
        await expect(row("shiraz-1")).toContainText(N("nodes.pair.none"));
        await expect(row("tabriz-1")).toContainText(N("health.pending"));
      });

      test("an empty list says so", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: createNodeMock().handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        await expect(page.getByRole("region", {name: N("nodes.gridLabel")}).getByTestId("grid-empty")).toContainText(N("nodes.empty.title"));
        // With no global pair free DNS has no address to give, and says that.
        await expect(page.getByTestId("free-dns-no-address")).toHaveText(N("freeDns.addresses.none"));
      });
    });

    // ---- Free DNS (T-556) -------------------------------------------------------------------------------------------------------

    test.describe("free DNS", () => {
      test("T-556: the advertised DNS addresses of the global pair, primary first, each with a copy button that names what it copies", async ({page, context, baseURL}) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"]);
        const w = world();
        await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const list = page.getByTestId("free-dns-addresses").getByRole("listitem");
        await expect(list).toHaveCount(2);
        await expect(list.nth(0)).toContainText(N("freeDns.addresses.primary"));
        await expect(list.nth(0).locator('bdi[dir="ltr"]')).toHaveText(w.a.dns_advertised_ip!);
        await expect(list.nth(1)).toContainText(N("freeDns.addresses.fallback"));
        await expect(list.nth(1).locator('bdi[dir="ltr"]')).toHaveText(w.b.dns_advertised_ip!);
        const copy = list.nth(0).getByRole("button", {name: N("freeDns.addresses.copy", {role: N("freeDns.addresses.primary")})});
        await copy.click();
        await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(w.a.dns_advertised_ip);
        // The accessible name holds the visible word and its subject.
        await expect(list.nth(1).getByRole("button", {name: N("freeDns.addresses.copy", {role: N("freeDns.addresses.fallback")})})).toBeVisible();
      });

      test("T-556, PG-r3-3: a revoked node of the global pair is not given out, and is marked as still advertised with the runbook link", async ({page, context, baseURL}) => {
        const w = world();
        w.state.nodes[0] = {...w.state.nodes[0]!, status: "revoked"};
        await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const section = page.getByTestId("free-dns-addresses");
        await expect(section.getByTestId("free-address-fallback")).toContainText(N("freeDns.addresses.fallback"));
        await expect(section.getByTestId("free-address-primary")).toHaveCount(0);
        const revoked = section.getByTestId("free-address-revoked-primary");
        await expect(revoked).toContainText(N("pair.advertised.revokedMember"));
        await expect(revoked.getByRole("link", {name: N("givenUp.runbook")})).toHaveAttribute("href", new RegExp("/runbook#compromise$"));
        await expect(revoked.getByRole("button")).toHaveCount(0);
      });

      test("PG-r3-3: with both members revoked the card says the pair has no active node, not that there is no pair", async ({page, context, baseURL}) => {
        const w = world();
        w.state.nodes[0] = {...w.state.nodes[0]!, status: "revoked"};
        w.state.nodes[1] = {...w.state.nodes[1]!, status: "revoked"};
        await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        await expect(page.getByTestId("free-dns-no-address")).toHaveText(N("freeDns.addresses.noneActive"));
        await expect(page.getByTestId("free-dns-revoked").getByRole("listitem")).toHaveCount(2);
      });

      test("T-556: the warning that free DNS users get no notice is on the card", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: world().handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const warning = page.getByTestId("free-dns-warning");
        await expect(warning).toContainText(N("freeDns.warning.title"));
        await expect(warning).toContainText(N("freeDns.warning.text"));
      });

      test("T-556: the save needs a fresh code, opens its dialog, is repeated once, and sends the switch and the qps", async ({page, context, baseURL}) => {
        const w = world({freshRequired: true});
        const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const card = page.getByTestId("free-dns");
        const qps = card.locator('input[name="qps"]');
        await qps.fill(lang === "fa" ? "۴۵۰" : "450");
        await card.getByRole("switch", {name: N("freeDns.enabled")}).locator("xpath=ancestor::label").click();
        await card.getByRole("button", {name: N("freeDns.submit")}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        await typeCode(page, "totp_code", CODE);
        await expect.poll(() => bodies(mock, "PUT", "/settings/free-dns")).toEqual([{enabled: false, qps: 450}, {enabled: false, qps: 450}]);
        expect(w.state.freeDns).toMatchObject({enabled: false, qps: 450});
        // The form is clean again: nothing to save until another edit.
        await expect(card.getByRole("button", {name: N("freeDns.submit")})).toBeDisabled();
      });

      test("T-556: a qps outside the range is refused on the page before any request, and the server's refusal shows its text", async ({page, context, baseURL}) => {
        const w = world();
        const mock = await openAdmin(context, baseURL, {handlers: {...w.handlers, "PUT /settings/free-dns": err(422, "qps_out_of_range")}});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const card = page.getByTestId("free-dns");
        const qps = card.locator('input[name="qps"]');
        await qps.fill("0");
        await qps.blur();
        // 0 is held to the floor of 1 when the field is left, so the request is never a number the route would refuse.
        await expect(qps).toHaveValue(num(lang, 1));
        await card.getByRole("button", {name: N("freeDns.submit")}).click();
        // The ceiling the server holds may differ from the page's: its answer is shown with the text of its code.
        await expect(card.getByText(errText(lang, "qps_out_of_range"))).toBeVisible();
        expect(bodies(mock, "PUT", "/settings/free-dns")).toEqual([{enabled: true, qps: 1}]);
      });

      test("T-556, PG-r1-8: a qps above the ceiling of today is sent, because the ceiling is the route's, and its refusal shows its text", async ({page, context, baseURL}) => {
        const w = world();
        const mock = await openAdmin(context, baseURL, {handlers: {...w.handlers, "PUT /settings/free-dns": err(422, "qps_out_of_range")}});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const card = page.getByTestId("free-dns");
        await card.locator('input[name="qps"]').fill("3000");
        await card.getByRole("button", {name: N("freeDns.submit")}).click();
        await expect(card.getByText(errText(lang, "qps_out_of_range"))).toBeVisible();
        expect(bodies(mock, "PUT", "/settings/free-dns")).toEqual([{enabled: true, qps: 3000}]);
      });

      test("T-556: a value that another admin changed while this one was editing is a conflict, and Save waits for an answer", async ({page, context, baseURL}) => {
        await page.clock.install();
        const w = world();
        const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const card = page.getByTestId("free-dns");
        const qps = card.locator('input[name="qps"]');
        const save = card.getByRole("button", {name: N("freeDns.submit")});
        await qps.fill(lang === "fa" ? "۳۰۰" : "300");
        await card.getByRole("switch", {name: N("freeDns.enabled")}).locator("xpath=ancestor::label").click();
        await expect(save).toBeEnabled();
        // Another admin sets 700 while this one has 300 in the box.
        w.state.freeDns = {...w.state.freeDns, qps: 700, version: w.state.freeDns.version + 1};
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        const qpsNote = card.getByTestId("conflict-qps");
        await expect(qpsNote).toBeVisible();
        await expect(qpsNote.getByTestId("conflict-qps-value")).toHaveText(num(lang, 700));
        await expect(qps).toHaveValue(num(lang, 300));
        await expect(save).toBeDisabled();
        expect(mock.count("PUT /settings/free-dns")).toBe(0);
        await qpsNote.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(qpsNote).toHaveCount(0);
        await expect(save).toBeEnabled();
        await save.click();
        // The admin's values go out, since they chose to keep them, and the fresh window is not needed here.
        await expect.poll(() => bodies(mock, "PUT", "/settings/free-dns")).toEqual([{enabled: false, qps: 300}]);
      });
    });

    // ---- Addresses given up (T-546, T-561) --------------------------------------------------------------------------------------

    test.describe("addresses given up", () => {
      test("T-546: each address has its node, the time it was given up and the date from which giving it back is safe, with the fixed note", async ({page, context, baseURL}) => {
        const w = world({
          givenUp: [
            givenUpFixture({address: "203.0.113.50", kind: "dns", node_name: "tehran-old", given_up_at: minutesAgo(60 * 24 * 3), safe_from: new Date(Date.now() + 27 * 86_400_000).toISOString()}),
            givenUpFixture({address: "198.51.100.50", kind: "proxy", node_name: undefined, given_up_at: minutesAgo(60 * 24 * 3), safe_from: new Date(Date.now() + 27 * 86_400_000).toISOString()}),
          ],
        });
        await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const grid = page.getByRole("grid", {name: N("givenUp.gridLabel")});
        await expect(grid.getByRole("row")).toHaveCount(3);
        const dns = grid.getByRole("row").filter({hasText: "203.0.113.50"});
        await expect(dns.locator('bdi[dir="ltr"]')).toHaveText("203.0.113.50");
        await expect(dns).toContainText("tehran-old");
        await expect(dns).toContainText(N("givenUp.kind.dns"));
        await expect(dns.locator("time")).toHaveCount(2);
        await expect(grid.getByRole("row").filter({hasText: "198.51.100.50"})).toContainText(N("givenUp.removedNode"));
        // The date is not a countdown of the product: it is a date and a note of what is outside the panel.
        await expect(page.getByTestId("given-up")).toContainText(N("givenUp.wait"));
        await expect(page.getByTestId("given-up-note")).toContainText(N("givenUp.fixedNote"));
        // Free DNS users who typed an old address get no notice (T-556), said above the list as well.
        await expect(page.getByTestId("given-up-free-warning")).toHaveText(N("givenUp.freeWarning"));
      });

      test("T-546: an address whose date has come says it is safe now", async ({page, context, baseURL}) => {
        const w = world({givenUp: [givenUpFixture({safe_from: minutesAgo(5)})]});
        await openAdmin(context, baseURL, {handlers: w.handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        await expect(page.getByTestId("given-up")).toContainText(N("givenUp.safeNow"));
      });

      test("T-546: with nothing waiting the list says so, and the fixed note stays", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: world().handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        await expect(page.getByTestId("given-up").getByTestId("grid-empty")).toContainText(N("givenUp.empty.title"));
        await expect(page.getByTestId("given-up-note")).toBeVisible();
      });

      test("T-546: a failed list has Retry and the page around it stays", async ({page, context, baseURL}) => {
        let failing = true;
        const w = world();
        await openAdmin(context, baseURL, {handlers: {...w.handlers, "GET /nodes/addresses-given-up": () => (failing ? err(500, "internal") : {body: {items: []}})}});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const section = page.getByTestId("given-up");
        await expect(section.getByRole("alert")).toContainText(errText(lang, "internal"));
        await expect(page.getByTestId("free-dns")).toBeVisible();
        failing = false;
        await section.getByRole("button", {name: commonText(lang, "retry")}).click();
        await expect(section.getByTestId("grid-empty")).toBeVisible();
      });

      test("PG-r1-5: with every slot taken the Nodes page says the order that replaces a node", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: world().handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        const note = page.getByTestId("replacement-order");
        await expect(note).toContainText(N("replacement.title"));
        await expect(note.getByTestId("replacement-steps")).toContainText(N("replacement.steps.put"));
        await expect(note.getByTestId("replacement-steps")).toContainText(N("replacement.steps.approve"));
        await expect(note.getByTestId("replacement-address")).toHaveText(N("replacement.address"));
      });

      test("PG-r1-5: with a slot free the note is not shown", async ({page, context, baseURL}) => {
        const w = world();
        await openAdmin(context, baseURL, {handlers: {...w.handlers, "GET /nodes": {body: {items: w.state.nodes.slice(0, 3), next_cursor: undefined}}}});
        await goto(page, "/nodes", N("pages.nodes.title"));
        await expect(page.getByTestId("replacement-order")).toHaveCount(0);
      });

      test("T-561: the runbook link opens the runbook page inside the app, and its way back returns to Nodes", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: world().handlers});
        await goto(page, "/nodes", N("pages.nodes.title"));
        await page.getByRole("link", {name: N("givenUp.runbook")}).click();
        await expect(page).toHaveURL(new RegExp(`/${lang}/runbook$`));
        await expect(page.getByRole("heading", {level: 1, name: N("pages.runbook.title")})).toBeVisible();
        const steps = page.getByTestId("runbook");
        // The compromise runbook of SC 8a.9 is on the page, in order, with the steps outside the panel (PG-r1-4).
        await expect(steps.getByTestId("runbook-compromise").getByRole("listitem")).toHaveCount(8);
        await expect(steps.getByTestId("runbook-compromise")).toContainText(N("runbook.compromise.steps.keys"));
        await expect(steps.getByTestId("runbook-compromise")).toContainText(N("runbook.compromise.steps.registrar"));
        await expect(steps).toContainText(N("runbook.retire.steps.replace"));
        await expect(steps).toContainText(N("runbook.retire.steps.giveBack"));
        await expect(steps).toContainText(N("runbook.free.steps.listed"));
        await expect(steps).toContainText(N("runbook.outside.text"));
        await page.getByRole("link", {name: N("runbook.back")}).click();
        await expect(page).toHaveURL(new RegExp(`/${lang}/nodes$`));
      });
    });
  });
}

