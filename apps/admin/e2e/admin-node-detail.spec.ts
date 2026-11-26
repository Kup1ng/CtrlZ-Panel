import {claimFixture, nodeFixture, pairFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import {createNodeMock, type NodeMockState} from "@ctrlz/api-client/testing/nodeMock.ts";
import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {adm, allowAdminErrors, bodies, err, errText, gotoShell, LANGS, nodesText, openAdmin, typeCode, type Lang} from "./admin-support.ts";

// p4-nodes 10.1, package PN: the page of one node, in mock mode (spec 17.1). Each case names the Plan row it closes. T-542: the node's
// state, the conditions of F3 not yet met, "a hold does not isolate the node", the drain state, and Hold, Release and Force failback.
// T-546: leaving a pair and removing a node, with its conditions shown and its addresses given up afterwards. The writes need the fresh
// TOTP window, as on the real routes (`freshRequired`). NodeView carries the F3 conditions, the time F3 is due and the drain once the hub
// has written them (migration 0103); a case that needs them adds them to the answer by hand, and a node without them reads "not reported yet".
// The revocation still pending and the hub's verdict are not in the document: a case that needs them adds them by hand too.

test.beforeEach(({guard}) => allowAdminErrors(guard));

const CODE = "123456";
const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000).toISOString();

/** Four nodes: two in the global pair, one alone and serving, one waiting for approval. */
function world(over: Partial<NodeMockState> = {}) {
  const a = nodeFixture({slot: 1, name: "tehran-1"});
  const b = nodeFixture({slot: 2, name: "tehran-2"});
  const c = nodeFixture({slot: 3, name: "shiraz-1"});
  const d = nodeFixture({slot: 4, name: "tabriz-1", status: "pending", last_heartbeat_at: undefined});
  return {a, b, c, d, ...createNodeMock({nodes: [a, b, c, d], pairs: [pairFixture(a, b)], ...over})};
}

for (const {lang, dir} of LANGS) {
  test.describe(`admin node page, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);
    const N = (path: string, values?: Record<string, string | number>) => nodesText(lang, path, values);
    const goto = (page: Page, id: string, name: string) => gotoShell(page, lang as Lang, `/nodes/${id}`, name);
    const waitFresh = async (page: Page) => {
      await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
      await typeCode(page, "totp_code", CODE);
    };

    test("T-542: the page names the node, its state as a word, and says which of the hub's parts the hub has not reported yet", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.a.id, "tehran-1");
      const summary = page.getByTestId("node-summary");
      await expect(summary.getByTestId("fact-state")).toContainText(N("health.serving"));
      // The hub has written nothing for this node: the page says so and does not make one up.
      await expect(summary.getByTestId("fact-hub").getByTestId("not-reported")).toHaveText(N("notReported"));
      await expect(summary.getByTestId("fact-pair")).toContainText(N("nodes.pair.with", {name: "tehran-2"}));
      await expect(summary.getByTestId("fact-config")).toContainText(N("overview.nodes.lag.upToDate"));
      const failover = page.getByTestId("node-failover");
      await expect(failover.locator("[data-answer]")).toHaveAttribute("data-answer", "advertised");
      await expect(failover.getByTestId("fact-drain").getByTestId("not-reported")).toBeVisible();
      await expect(failover.getByTestId("fact-peer-views").getByTestId("not-reported")).toBeVisible();
      await expect(failover.getByTestId("f3-not-needed")).toHaveText(N("node.failover.unmet.notNeeded"));
      await expect(page.getByTestId("revocation-pending")).toHaveCount(0);
    });

    test("T-542: a node that is out of the answer lists the conditions of F3 not yet met, in words, and a name the page does not know by its own name", async ({page, context, baseURL}) => {
      const w = world();
      const withdrawn = {...w.b, dns_withdrawn: true, f3_unmet: ["peer_view", "stable_period", "a_new_condition"], drain_state: "done", drain_since: minutesAgo(30), health: "degraded"};
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "GET /nodes/{id}": {body: withdrawn}}});
      await goto(page, w.b.id, "tehran-2");
      const failover = page.getByTestId("node-failover");
      await expect(failover.locator("[data-answer]")).toHaveAttribute("data-answer", "withdrawn");
      const unmet = failover.getByTestId("f3-unmet");
      await expect(unmet.locator('[data-condition="peer_view"]')).toContainText(N("node.failover.unmet.names.peer_view"));
      await expect(unmet.locator('[data-condition="stable_period"]')).toContainText(N("node.failover.unmet.names.stable_period"));
      await expect(unmet.locator('[data-condition="a_new_condition"]')).toContainText("a_new_condition");
      await expect(failover.locator("[data-drain]")).toHaveText(N("node.failover.drain.states.done"));
      await expect(failover.getByTestId("drain-since")).not.toBeEmpty();
      // F3 has a due time only while no condition is unmet: the hub writes none here, so the page shows no row for it.
      await expect(failover.getByTestId("fact-f3-due")).toHaveCount(0);
      await expect(page.getByTestId("node-summary").locator('[data-hub-health="degraded"]')).toHaveText(N("hubHealth.degraded"));
    });

    test("T-542: when every condition is met the page shows the time F3 acts, and a drain in progress shows when it began", async ({page, context, baseURL}) => {
      const w = world();
      const soon = {...w.b, dns_withdrawn: true, f3_unmet: [], f3_due_at: new Date(Date.now() + 5 * 60_000).toISOString(), drain_state: "draining", drain_since: minutesAgo(5)};
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "GET /nodes/{id}": {body: soon}}});
      await goto(page, w.b.id, "tehran-2");
      const failover = page.getByTestId("node-failover");
      await expect(failover.getByTestId("f3-none")).toHaveText(N("node.failover.unmet.none"));
      await expect(failover.getByTestId("fact-f3-due")).toContainText(N("node.failover.unmet.dueTitle"));
      await expect(failover.getByTestId("f3-due-at")).not.toBeEmpty();
      await expect(failover.locator("[data-drain]")).toHaveText(N("node.failover.drain.states.draining"));
      await expect(failover.getByTestId("drain-since")).not.toBeEmpty();
      await expect(failover.getByTestId("not-reported")).toHaveCount(1); // only the peers' view, which no document carries
    });

    test("T-542: a node that is not draining shows no start of a drain, and a time the page cannot read is left out", async ({page, context, baseURL}) => {
      const w = world();
      const node = {...w.b, dns_withdrawn: true, f3_unmet: [], f3_due_at: "soon", drain_state: "none", drain_since: minutesAgo(90)};
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "GET /nodes/{id}": {body: node}}});
      await goto(page, w.b.id, "tehran-2");
      const failover = page.getByTestId("node-failover");
      await expect(failover.locator("[data-drain]")).toHaveText(N("node.failover.drain.states.none"));
      await expect(failover.getByTestId("drain-since")).toHaveCount(0);
      await expect(failover.getByTestId("fact-f3-due")).toHaveCount(0);
    });

    test("T-542: a withdrawn node whose hub parts are absent says they are not reported, and a revocation still pending is a warning", async ({page, context, baseURL}) => {
      const w = world();
      const node = {...w.b, dns_withdrawn: true, revocation_pending: true};
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "GET /nodes/{id}": {body: {...node, f3_unmet: undefined}}}});
      await goto(page, w.b.id, "tehran-2");
      await expect(page.getByTestId("node-failover").getByTestId("fact-unmet").getByTestId("not-reported")).toBeVisible();
      await expect(page.getByTestId("revocation-pending")).toContainText(N("node.revocationPending.title"));
    });

    test("T-542: the page says that a hold does not isolate the node, and that a compromised node is revoked, with the link to the runbook", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.a.id, "tehran-1");
      const note = page.getByTestId("hold-note");
      await expect(note).toContainText(N("node.failover.holdNote.title"));
      await expect(note).toContainText(N("node.failover.holdNote.text"));
      await expect(note.getByRole("link")).toHaveAttribute("href", new RegExp(`/${lang}/runbook#compromise$`));
      // Asking for a hold repeats it in the dialog, so it is read again at the moment of the decision.
      await page.getByTestId("request-hold").click();
      await expect(page.getByRole("alertdialog")).toContainText(N("node.failover.holdNote.text"));
    });

    test("T-542: Hold needs a fresh code, is repeated once, sends the kind of request, and says the hub decides", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.a.id, "tehran-1");
      await expect(page.getByTestId("request-release")).toBeDisabled();
      await expect(page.getByTestId("request-force_failback")).toBeDisabled();
      await page.getByRole("button", {name: N("node.failover.actions.hold.row", {name: "tehran-1"})}).click();
      await expect(page.getByRole("alertdialog", {name: N("node.failover.actions.hold.title", {name: "tehran-1"})})).toBeVisible();
      await page.getByTestId("confirm-hold").click();
      await waitFresh(page);
      await expect.poll(() => bodies(mock, "POST", `/nodes/${w.a.id}/dns-requests`)).toEqual([{kind: "hold"}, {kind: "hold"}]);
      await expect(page.getByText(N("node.failover.sent"))).toBeVisible();
      // The request is decided on the hub's next tick: the mock applies a hold at once, and the page reads the node again.
      await expect(page.getByTestId("request-release")).toBeEnabled();
      await expect(page.getByTestId("request-hold")).toBeDisabled();
      // The hub then names the hold as the condition that keeps the node out (the mock writes it at once, as it applies the hold).
      await expect(page.getByTestId("node-failover").locator('[data-condition="held"]')).toContainText(N("node.failover.unmet.names.held"));
    });

    test("T-542: Release and Force failback send their own kinds, and the buttons follow the state the database holds", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes.find((n) => n.id === w.b.id)!.dns_hold = true;
      w.state.nodes.find((n) => n.id === w.b.id)!.dns_withdrawn = true;
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.b.id, "tehran-2");
      await expect(page.getByTestId("node-failover").locator("[data-answer]")).toHaveAttribute("data-answer", "held");
      await expect(page.getByTestId("request-hold")).toBeDisabled();
      await page.getByTestId("request-force_failback").click();
      await expect(page.getByRole("alertdialog")).toContainText(N("node.failover.actions.force_failback.text"));
      await page.getByTestId("confirm-force_failback").click();
      await expect.poll(() => bodies(mock, "POST", `/nodes/${w.b.id}/dns-requests`)).toEqual([{kind: "force_failback"}]);
      await page.getByTestId("request-release").click();
      await page.getByTestId("confirm-release").click();
      await expect.poll(() => bodies(mock, "POST", `/nodes/${w.b.id}/dns-requests`)).toEqual([{kind: "force_failback"}, {kind: "release"}]);
    });

    test("T-542: a refusal of the route is shown in the dialog with the words of its code, and the dialog stays", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "POST /nodes/{id}/dns-requests": err(409, "node_state")}});
      await goto(page, w.a.id, "tehran-1");
      await page.getByTestId("request-hold").click();
      await page.getByTestId("confirm-hold").click();
      await expect(page.getByTestId("action-error")).toHaveText(errText(lang, "node_state"));
      await expect(page.getByRole("alertdialog")).toBeVisible();
    });

    test("T-542: a node with no pair says failover does not look at it, and a node that is not active takes no part", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.c.id, "shiraz-1");
      await expect(page.getByTestId("failover-no-pair")).toHaveText(N("node.failover.noPair"));
      await page.goto(`/${lang}/nodes/${w.d.id}`);
      await expect(page.getByTestId("failover-not-active")).toHaveText(N("node.failover.notActive"));
      await expect(page.getByTestId("request-hold")).toHaveCount(0);
    });

    test("PG-r2-6, PG-r2-7: a revoked node still in its pair is said to need replacing, and it can be held but not released or failed back", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[0] = {...w.a, status: "revoked"};
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.a.id, "tehran-1");
      const block = page.getByTestId("failover-revoked-in-pair");
      await expect(block).toContainText(N("node.failover.revokedInPair"));
      await expect(block).toContainText(N("node.failover.revokedHold"));
      await expect(block.getByRole("link", {name: N("givenUp.runbook")})).toHaveAttribute("href", new RegExp("/runbook#compromise$"));
      await expect(page.getByTestId("failover-not-active")).toHaveCount(0);
      await expect(page.getByTestId("request-hold")).toBeEnabled();
      await expect(page.getByTestId("request-release")).toHaveCount(0);
      await expect(page.getByTestId("request-force_failback")).toHaveCount(0);
      await page.getByTestId("request-hold").click();
      // PW-r1-5: the dialog of a revoked node does not promise that the hold lasts, and does not repeat the active node's text.
      await expect(page.getByRole("alertdialog")).toContainText(N("node.failover.revokedHoldDialog"));
      await page.getByTestId("confirm-hold").click();
      // The mock answers as the route does (a hold of a revoked node is accepted), so the request is recorded with the real body (PW-r1-1).
      await expect.poll(() => bodies(mock, "POST", `/nodes/${w.a.id}/dns-requests`)).toEqual([{kind: "hold"}]);
      await expect(page.getByTestId("action-error")).toHaveCount(0);
    });

    test("PG-r1-3: only the node the pair advertises is called advertised, and its healthy peer is on standby", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.a.id, "tehran-1");
      await expect(page.getByTestId("node-failover").locator("[data-answer]")).toHaveAttribute("data-answer", "advertised");
      await page.goto(`/${lang}/nodes/${w.b.id}`);
      const failover = page.getByTestId("node-failover");
      await expect(failover.locator("[data-answer]")).toHaveAttribute("data-answer", "standby");
      await expect(failover.locator("[data-answer]")).toContainText(N("node.failover.answerState.standby"));
      // A standby node is not withdrawn, so it needs no conditions to return; the page does not say it is advertised.
      await expect(failover.getByTestId("f3-not-needed")).toHaveText(N("node.failover.unmet.notNeeded"));
    });

    test("PG-r1-6: the address edit of a node of the global pair says that free DNS users get no notice, and a node outside it does not", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.a.id, "tehran-1");
      await expect(page.getByTestId("addresses-note")).toContainText(N("node.addresses.pairedNote"));
      await expect(page.getByTestId("addresses-free-note")).toHaveText(N("node.addresses.globalNote"));
      await page.goto(`/${lang}/nodes/${w.c.id}`);
      await expect(page.getByTestId("addresses-note")).toBeVisible();
      await expect(page.getByTestId("addresses-free-note")).toHaveCount(0);
    });

    test("PG-r1-5: a pending host whose DNS address another node holds cannot be approved, and the page says the order that frees it", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes[3] = {...w.d, dns_advertised_ip: w.a.dns_advertised_ip!};
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.d.id, "tabriz-1");
      await page.getByRole("button", {name: N("node.lifecycle.approve.row", {name: "tabriz-1"})}).click();
      const clash = page.getByTestId("approve-address-clash");
      await expect(clash).toContainText("tehran-1");
      await expect(clash.getByTestId("replacement-steps")).toContainText(N("replacement.steps.remove"));
      await expect(page.getByTestId("confirm-approve")).toBeDisabled();
      expect(mock.calls.filter((c) => c.path === `/nodes/${w.d.id}:approve`)).toHaveLength(0);
    });

    test("T-340: a node waiting for approval is approved with a fresh code, and the page shows it active", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.d.id, "tabriz-1");
      await expect(page.getByTestId("node-summary").getByTestId("fact-state")).toContainText(N("health.pending"));
      await expect(page.getByTestId("node-revoke")).toHaveCount(0);
      await page.getByRole("button", {name: N("node.lifecycle.approve.row", {name: "tabriz-1"})}).click();
      await page.getByTestId("confirm-approve").click();
      await waitFresh(page);
      await expect.poll(() => mock.calls.filter((c) => c.method === "POST" && c.path === `/nodes/${w.d.id}:approve`).length).toBe(2);
      expect(w.state.nodes.find((n) => n.id === w.d.id)!.status).toBe("active");
      await expect(page.getByTestId("node-approve")).toHaveCount(0);
    });

    test("T-542: revoking is a danger confirmation that says it cannot be undone, and the page then shows the node as revoked with its reports", async ({page, context, baseURL}) => {
      const w = world();
      w.state.reports.claims = [claimFixture(1, {consumed_at: minutesAgo(5)})];
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.c.id, "shiraz-1");
      await expect(page.getByTestId("node-reports")).toHaveCount(0);
      await page.getByTestId("node-revoke").click();
      await expect(page.getByRole("alertdialog")).toContainText(N("node.lifecycle.revoke.text"));
      await page.getByTestId("confirm-revoke").click();
      await expect.poll(() => mock.calls.filter((c) => c.method === "POST" && c.path === `/nodes/${w.c.id}:revoke`).length).toBe(1);
      await expect(page.getByTestId("node-summary").getByTestId("fact-state")).toContainText(N("health.revoked"));
      const reports = page.getByTestId("node-reports");
      await expect(reports.getByRole("grid", {name: N("node.reports.gridLabel")}).getByRole("row")).toHaveCount(2);
      // A revoked node's addresses are not edited, and nothing offers to approve or revoke it.
      await expect(page.getByTestId("node-addresses")).toContainText(N("node.addresses.revoked"));
      await expect(page.getByTestId("node-approve")).toHaveCount(0);
      await expect(page.getByTestId("node-revoke")).toHaveCount(0);
    });

    test("T-542: the claims of a revoked node come 200 at a time and the older ones on a button", async ({page, context, baseURL}) => {
      const w = world();
      const node = w.state.nodes.find((n) => n.id === w.c.id)!;
      node.status = "revoked";
      // 250 claims, a minute apart, newest first; the route repeats the instant of `to`, so the 200th claim comes again on the second page.
      w.state.reports.claims = Array.from({length: 250}, (_, i) => claimFixture(i + 1, {consumed_at: new Date(Math.floor(Date.now() / 60_000) * 60_000 - (i + 1) * 60_000).toISOString()}));
      w.state.reports.kept_rows = [{tenant_id: "0000000a-0000-4000-8000-000000000001", endpoint_id: "0000000b-0000-4000-8000-0000000000aa"}];
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.c.id, "shiraz-1");
      const reports = page.getByTestId("node-reports");
      await expect(reports.getByTestId("reports-truncated")).toContainText(N("node.reports.truncated"));
      await expect(reports.getByTestId("reports-kept")).toContainText("0000000b-0000-4000-8000-0000000000aa");
      await reports.getByRole("button", {name: N("node.reports.more")}).click();
      await expect(reports.getByTestId("reports-truncated")).toHaveCount(0);
      const calls = mock.calls.filter((c) => c.path === `/nodes/${w.c.id}/reports`);
      expect(calls).toHaveLength(2);
      // The second page walks back from the instant of the last claim of the first.
      expect(calls[1]!.query.get("to")).toBe(w.state.reports.claims[199]!.consumed_at);
    });

    test("T-542: the reports ask from the start of a day, the window the admin picks, and the default is thirty days", async ({page, context, baseURL}) => {
      const w = world();
      w.state.nodes.find((n) => n.id === w.c.id)!.status = "revoked";
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.c.id, "shiraz-1");
      await expect(page.getByTestId("node-reports").getByTestId("grid-empty")).toContainText(N("node.reports.empty.title"));
      const days = (iso: string) => Math.round((Date.now() - Date.parse(iso)) / 86_400_000);
      const first = mock.calls.find((c) => c.path === `/nodes/${w.c.id}/reports`)!;
      expect(days(first.query.get("from")!)).toBeGreaterThanOrEqual(30);
      expect(first.query.get("from")).toMatch(/T00:00:00\.000Z$/);
      await page.getByTestId("node-reports").getByRole("radio").first().click();
      await expect.poll(() => mock.calls.filter((c) => c.path === `/nodes/${w.c.id}/reports`).length).toBe(2);
      expect(days(mock.calls.filter((c) => c.path === `/nodes/${w.c.id}/reports`)[1]!.query.get("from")!)).toBeGreaterThanOrEqual(7);
    });

    test("T-546: a node in a pair cannot be removed, and the page says why before it is asked", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.a.id, "tehran-1");
      const conditions = page.getByTestId("remove-conditions");
      await expect(conditions).toContainText(N("node.lifecycle.remove.blocked", {peer: "tehran-2"}));
      await expect(conditions).toContainText(N("node.lifecycle.remove.conditions.notInTable"));
      await expect(page.getByTestId("node-remove")).toBeDisabled();
    });

    test("T-546: removing a node outside every pair sends the delete, goes back to the list, and its addresses are there with their date", async ({page, context, baseURL, guard}) => {
      // The page asks for the node again as the delete settles, and the node is gone.
      guard.allowConsole(/status of 404/);
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.c.id, "shiraz-1");
      await expect(page.getByTestId("remove-conditions").locator('[data-met="true"]')).toContainText(N("node.lifecycle.remove.conditions.notPaired"));
      await page.getByRole("button", {name: N("node.lifecycle.remove.row", {name: "shiraz-1"})}).click();
      await expect(page.getByRole("alertdialog")).toContainText(N("node.lifecycle.remove.text"));
      await page.getByTestId("confirm-remove").click();
      await waitFresh(page);
      await expect(page.getByRole("heading", {level: 1, name: N("pages.nodes.title")})).toBeVisible();
      expect(mock.calls.filter((c) => c.method === "DELETE" && c.path === `/nodes/${w.c.id}`)).toHaveLength(2);
      const given = page.getByRole("grid", {name: N("givenUp.gridLabel")});
      await expect(given.getByRole("row")).toHaveCount(3);
      await expect(given).toContainText("203.0.113.13");
      await expect(page.getByTestId("given-up-note")).toContainText(N("givenUp.fixedNote"));
    });

    test("T-546: a route that refuses the removal for the table shows its words in the dialog", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "DELETE /nodes/{id}": err(409, "node_in_table")}});
      await goto(page, w.c.id, "shiraz-1");
      await page.getByTestId("node-remove").click();
      await page.getByTestId("confirm-remove").click();
      await expect(page.getByTestId("action-error")).toHaveText(errText(lang, "node_in_table"));
    });

    test("T-340: the advertised addresses are checked on the page, then saved with the fresh code, and the old one is said to go to the given-up list", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.c.id, "shiraz-1");
      const card = page.getByTestId("node-addresses");
      await expect(card.getByTestId("addresses-note")).toContainText(N("node.addresses.freeNote"));
      await expect(card.getByTestId("fact-bind-dns")).toContainText("203.0.113.13");
      const dns = card.locator('input[name="dns_advertised_ip"]');
      await dns.fill("not-an-address");
      await card.getByRole("button", {name: N("node.addresses.submit")}).click();
      await expect(card.getByText(N("node.addresses.invalid"))).toBeVisible();
      expect(bodies(mock, "PUT", `/nodes/${w.c.id}/addresses`)).toEqual([]);
      await dns.fill("203.0.113.77");
      await card.getByRole("button", {name: N("node.addresses.submit")}).click();
      await waitFresh(page);
      await expect.poll(() => bodies(mock, "PUT", `/nodes/${w.c.id}/addresses`)).toEqual([
        {dns_advertised_ip: "203.0.113.77", proxy_advertised_ip: "198.51.100.13"},
        {dns_advertised_ip: "203.0.113.77", proxy_advertised_ip: "198.51.100.13"},
      ]);
      expect(w.state.givenUp.map((g) => g.address)).toEqual(["203.0.113.13"]);
    });

    test("T-340: a node in a pair is told that an address change queues a pair change, and the route's refusal shows its words", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "PUT /nodes/{id}/addresses": err(422, "upstream_loop")}});
      await goto(page, w.a.id, "tehran-1");
      const card = page.getByTestId("node-addresses");
      await expect(card.getByTestId("addresses-note")).toContainText(N("node.addresses.pairedNote"));
      await card.locator('input[name="proxy_advertised_ip"]').fill("198.51.100.99");
      await card.getByRole("button", {name: N("node.addresses.submit")}).click();
      await expect(card.getByText(errText(lang, "upstream_loop"))).toBeVisible();
    });

    test("T-340: an address another admin changed while this one was editing is a conflict, and Save waits for an answer", async ({page, context, baseURL}) => {
      await page.clock.install();
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.c.id, "shiraz-1");
      const card = page.getByTestId("node-addresses");
      const dns = card.locator('input[name="dns_advertised_ip"]');
      const save = card.getByRole("button", {name: N("node.addresses.submit")});
      await dns.fill("203.0.113.70");
      await expect(save).toBeEnabled();
      w.state.nodes.find((n) => n.id === w.c.id)!.dns_advertised_ip = "203.0.113.71";
      await page.clock.fastForward(31_000);
      await page.evaluate(() => {
        window.dispatchEvent(new Event("offline"));
        window.dispatchEvent(new Event("online"));
      });
      const note = card.getByTestId("conflict-dns_advertised_ip");
      await expect(note).toBeVisible();
      await expect(note.getByTestId("conflict-dns_advertised_ip-value")).toHaveText("203.0.113.71");
      await expect(dns).toHaveValue("203.0.113.70");
      await expect(save).toBeDisabled();
    });

    test("T-340: the name and the proxy block are saved together, and a name changed meanwhile is a conflict", async ({page, context, baseURL}) => {
      await page.clock.install();
      const w = world();
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page, w.c.id, "shiraz-1");
      const card = page.getByTestId("node-settings");
      const name = card.locator('input[name="name"]');
      const save = card.getByRole("button", {name: N("node.settings.submit")});
      await expect(save).toBeDisabled();
      await name.fill("shiraz-2");
      await card.getByRole("switch", {name: N("node.settings.proxyBlocked")}).locator("xpath=ancestor::label").click();
      await save.click();
      await expect.poll(() => bodies(mock, "PATCH", `/nodes/${w.c.id}`)).toEqual([{name: "shiraz-2", proxy_blocked: true}]);
      await expect(page.getByRole("heading", {level: 1, name: "shiraz-2"})).toBeVisible();
      // Now the conflict: this admin types a name while another admin renames the node.
      await name.fill("shiraz-3");
      w.state.nodes.find((n) => n.id === w.c.id)!.name = "shiraz-9";
      await page.clock.fastForward(31_000);
      await page.evaluate(() => {
        window.dispatchEvent(new Event("offline"));
        window.dispatchEvent(new Event("online"));
      });
      const note = card.getByTestId("conflict-name");
      await expect(note).toBeVisible();
      await expect(note.getByTestId("conflict-name-value")).toHaveText("shiraz-9");
      await expect(save).toBeDisabled();
    });

    test("T-542: a node that is not there says so, with the way back to the list", async ({page, context, baseURL, guard}) => {
      guard.allowConsole(/status of 404/);
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await page.goto(`/${lang}/nodes/00000000-0000-4000-8000-0000000fffff`);
      await expect(page.getByText(N("node.notFound.title"))).toBeVisible();
      await page.getByTestId("back-to-nodes").click();
      await expect(page.getByRole("heading", {level: 1, name: N("pages.nodes.title")})).toBeVisible();
    });

    test("T-542: the list names each node as a link to its page, and the plus opens the enrolment", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await gotoShell(page, lang as Lang, "/nodes", N("pages.nodes.title"));
      await page.getByRole("link", {name: N("nodes.openRow", {name: "tehran-2"})}).click();
      await expect(page.getByRole("heading", {level: 1, name: "tehran-2"})).toBeVisible();
      await expect(page).toHaveURL(new RegExp(`/nodes/${w.b.id}$`));
      await page.goBack();
      await page.getByRole("button", {name: N("pages.enrol.title")}).click();
      await expect(page.getByRole("heading", {level: 1, name: N("pages.enrol.title")})).toBeVisible();
      await expect(page).toHaveURL(new RegExp(`/nodes/enrol$`));
    });
  });
}
