import {enrollmentFixture, nodeFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import {createNodeMock, MOCK_INSTALL_COMMAND, type NodeMockState} from "@ctrlz/api-client/testing/nodeMock.ts";
import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {adm, allowAdminErrors, bodies, commonText, err, errText, gotoShell, LANGS, nodesText, openAdmin, typeCode, type Lang} from "./admin-support.ts";

// p4-nodes 4.2 and 10.1, package PN: the enrolment of a node, in mock mode (spec 17.1). T-340 is the row these cases close: the install
// command is made with a fresh code and shown once, a host that has called in is compared by its fingerprint typed by the admin, and
// only an equal fingerprint, the four addresses ticked and a name let a node row be made. The command is the one secret of the page: it
// reaches no URL, no storage and no query, and it is gone with its dialog.

test.beforeEach(({guard}) => allowAdminErrors(guard));

const CODE = "123456";
// The hex SHA-256 of a key as the host prints it.
const FP = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";
const FP_OTHER = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab13";
const spaced = (fp: string) => fp.toUpperCase().match(/.{2}/g)!.join(":");

function world(over: Partial<NodeMockState> = {}) {
  const waiting = enrollmentFixture({
    state: "pending_approval",
    key_fingerprint: FP,
    hostname: "host-1",
    os_release: "Ubuntu 24.04.2 LTS",
    enrolled_at: new Date(Date.now() - 120_000).toISOString(),
    enrolled_from: "192.0.2.9",
    expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
  });
  const issued = enrollmentFixture({state: "issued", key_fingerprint: undefined, hostname: undefined, os_release: undefined, node_version: undefined, expires_at: new Date(Date.now() + 5 * 60_000).toISOString()});
  return {waiting, issued, ...createNodeMock({nodes: [nodeFixture({slot: 1, name: "tehran-1"})], enrollments: [waiting, issued], ...over})};
}

for (const {lang, dir} of LANGS) {
  test.describe(`admin enrolment, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);
    const N = (path: string, values?: Record<string, string | number>) => nodesText(lang, path, values);
    const goto = (page: Page, path = "/nodes/enrol") => gotoShell(page, lang as Lang, path, N("pages.enrol.title"));
    const waitFresh = async (page: Page) => {
      await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
      await typeCode(page, "totp_code", CODE);
    };
    const fill = async (page: Page, name: string, value: string) => page.locator(`input[name="${name}"]`).fill(value);

    test("T-340: the form refuses an address that is not one before any request, and asks for every address", async ({page, context, baseURL}) => {
      const w = world();
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const form = page.getByTestId("enrol-form");
      await form.getByTestId("enrol-submit").click();
      await expect(form.getByText(N("enrol.form.required"))).toHaveCount(1);
      await fill(page, "dns_bind_ip", "203.0.113.31");
      await fill(page, "proxy_bind_ip", "198.51.100.300");
      await fill(page, "bound_ip", "somewhere");
      await form.getByTestId("enrol-submit").click();
      await expect(form.getByText(N("enrol.form.invalid"))).toHaveCount(1);
      expect(bodies(mock, "POST", "/node-enrollments")).toEqual([]);
    });

    test("T-340: the command is made with a fresh code, shown once in a dialog, and reaches no URL, no storage and nothing after it is closed", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await fill(page, "dns_bind_ip", "203.0.113.31");
      await fill(page, "proxy_bind_ip", "198.51.100.31");
      await fill(page, "bound_ip", "192.0.2.50");
      await page.getByTestId("enrol-submit").click();
      await waitFresh(page);
      // Advertised follows bind until the admin says the host is behind NAT; the call is made twice, once for the fresh code.
      const body = {dns_bind_ip: "203.0.113.31", dns_advertised_ip: "203.0.113.31", proxy_bind_ip: "198.51.100.31", proxy_advertised_ip: "198.51.100.31", bound_ip: "192.0.2.50"};
      await expect.poll(() => bodies(mock, "POST", "/node-enrollments")).toEqual([body, body]);
      const result = page.getByTestId("one-time-result");
      await expect(result).toBeVisible();
      const command = page.getByTestId("one-time-command");
      // The command starts with a space on purpose, and the dialog says to copy it whole.
      expect((await command.textContent())!.startsWith(" curl")).toBe(true);
      await expect(result).toContainText(N("enrol.result.spaceNote"));
      // What a click selects and a copy by hand takes is the rendered text, so the space must survive there too (PG-r1-12).
      await command.click();
      const selected = await page.evaluate(() => window.getSelection()?.toString() ?? "");
      expect(selected.startsWith(" curl")).toBe(true);
      expect(MOCK_INSTALL_COMMAND.startsWith(" ")).toBe(true);
      // The token is in the page's state and nowhere else.
      expect(page.url()).not.toContain("FIXTURETOKEN");
      const stored = await page.evaluate(() => JSON.stringify([{...localStorage}, {...sessionStorage}]));
      expect(stored).not.toContain("FIXTURETOKEN");
      // Closing without having copied it asks first; ticking "I have saved it" lets it close.
      await page.getByRole("button", {name: commonText(lang, "done")}).click();
      await expect(page.getByRole("alertdialog")).toContainText(A("result.confirmText"));
      await page.getByRole("button", {name: A("result.keep")}).click();
      await page.getByRole("checkbox", {name: A("result.saved")}).locator("xpath=ancestor::label").click();
      await page.getByRole("button", {name: commonText(lang, "done")}).click();
      await expect(result).toHaveCount(0);
      await expect(page.getByText("FIXTURETOKEN")).toHaveCount(0);
      // The form is empty again, so the next command starts from nothing.
      await expect(page.locator('input[name="dns_bind_ip"]')).toHaveValue("");
    });

    test("T-340: a host behind NAT is told apart: the advertised addresses are typed when the switch is off", async ({page, context, baseURL}) => {
      const w = world();
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await expect(page.locator('input[name="dns_advertised_ip"]')).toHaveCount(0);
      await page.getByRole("switch", {name: N("enrol.form.same")}).locator("xpath=ancestor::label").click();
      await fill(page, "dns_bind_ip", "10.0.0.5");
      await fill(page, "dns_advertised_ip", "203.0.113.31");
      await fill(page, "proxy_bind_ip", "10.0.0.6");
      await fill(page, "proxy_advertised_ip", "198.51.100.31");
      await page.getByTestId("enrol-submit").click();
      await expect(page.getByTestId("one-time-result")).toBeVisible();
      expect(bodies(mock, "POST", "/node-enrollments")).toEqual([{dns_bind_ip: "10.0.0.5", dns_advertised_ip: "203.0.113.31", proxy_bind_ip: "10.0.0.6", proxy_advertised_ip: "198.51.100.31"}]);
    });

    test("T-340: a refused address and a missing pin file are said with their own words, and nothing is shown as made", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "POST /node-enrollments": err(422, "address_refused")}});
      await goto(page);
      await fill(page, "dns_bind_ip", "203.0.113.31");
      await fill(page, "proxy_bind_ip", "198.51.100.31");
      await page.getByTestId("enrol-submit").click();
      await expect(page.getByTestId("enrol-form").getByText(errText(lang, "address_refused"))).toBeVisible();
      await expect(page.getByTestId("one-time-result")).toHaveCount(0);
    });

    test("T-340: an answer that did not arrive says the command may exist, and does not offer a plain retry", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "POST /node-enrollments": err(500, "internal")}});
      await goto(page);
      await fill(page, "dns_bind_ip", "203.0.113.31");
      await fill(page, "proxy_bind_ip", "198.51.100.31");
      await page.getByTestId("enrol-submit").click();
      await expect(page.getByTestId("enrol-lost")).toContainText(N("enrol.form.lost"));
    });

    test("T-340: with four slots taken the page says so before the host is confirmed", async ({page, context, baseURL}) => {
      const nodes = [1, 2, 3, 4].map((slot) => nodeFixture({slot, name: `node-${slot}`}));
      const w = createNodeMock({nodes});
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await expect(page.getByTestId("enrol-full")).toContainText(N("enrol.form.full.title"));
      // "Remove one" is a dead end when the slots are paired nodes, so the alert gives the order that works (PG-r1-5).
      await expect(page.getByTestId("enrol-full").getByTestId("replacement-steps")).toContainText(N("replacement.steps.put"));
    });

    test("T-340: the list shows each enrolment by its state in words, and only a host that has called in can be compared", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const grid = page.getByRole("grid", {name: N("enrol.list.gridLabel")});
      await expect(grid.getByRole("row")).toHaveCount(3);
      const waitingRow = grid.getByRole("row").filter({hasText: "host-1"});
      await expect(waitingRow.locator("[data-enrol-state]")).toHaveText(N("enrol.list.state.pending_approval"));
      await expect(waitingRow).toContainText("192.0.2.9");
      await expect(waitingRow.getByRole("button", {name: N("enrol.list.compareRow", {host: "host-1"})})).toBeVisible();
      const issuedRow = grid.getByRole("row").filter({hasText: N("enrol.list.noHost")});
      await expect(issuedRow.locator("[data-enrol-state]")).toHaveText(N("enrol.list.state.issued"));
      await expect(issuedRow.getByRole("button", {name: N("enrol.list.rejectRow", {host: N("enrol.list.unnamed")})})).toBeVisible();
      await expect(issuedRow.getByRole("button", {name: N("enrol.list.compareRow", {host: N("enrol.list.unnamed")})})).toHaveCount(0);
    });

    test("T-340: the Nodes page points to a host that waits for its fingerprint to be compared", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await gotoShell(page, lang as Lang, "/nodes", N("pages.nodes.title"));
      const banner = page.getByTestId("pending-enrolments");
      await expect(banner).toBeVisible();
      await banner.getByRole("link", {name: N("enrol.pendingBanner.open")}).click();
      await expect(page.getByRole("heading", {level: 1, name: N("pages.enrol.title")})).toBeVisible();
      // Nothing waits once the list has none: no banner, and no empty box.
      w.waiting.state = "rejected";
      await page.goBack();
      await page.reload();
      await expect(page.getByRole("heading", {level: 1, name: N("pages.nodes.title")})).toBeVisible();
      await expect(page.getByTestId("pending-enrolments")).toHaveCount(0);
    });

    test("T-340: the confirmation is in the address, shows the record, and stays shut until the typed fingerprint, the addresses and a name are right", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await page.getByRole("button", {name: N("enrol.list.compareRow", {host: "host-1"})}).click();
      await expect(page).toHaveURL(new RegExp(`dialog=confirmNode&enrollmentId=${w.waiting.id}`));
      const dialog = page.getByRole("dialog", {name: N("enrol.confirm.title")});
      await expect(dialog).toBeVisible();
      // The record: the fingerprint in eight groups, left to right, the four addresses, the host and where it called in from.
      const record = dialog.getByTestId("confirm-record");
      await expect(record.getByTestId("record-fingerprint")).toHaveAttribute("dir", "ltr");
      await expect(record.getByTestId("record-fingerprint")).toHaveText(FP.match(/.{8}/g)!.join(""));
      await expect(record.getByTestId("fact-dns-advertised")).toContainText("203.0.113.20");
      await expect(record.getByTestId("fact-source")).toContainText("192.0.2.9");
      await expect(record.getByTestId("fact-host")).toContainText("host-1");
      const submit = dialog.getByTestId("confirm-node-submit");
      const check = dialog.getByTestId("fingerprint-check");
      const typed = dialog.locator('input[name="typed_fingerprint"]');
      await expect(submit).toBeDisabled();
      await expect(check).toHaveAttribute("data-check", "empty");
      await typed.fill(FP.slice(0, 20));
      await expect(check).toHaveAttribute("data-check", "partial");
      await expect(check).toContainText(N("enrol.confirm.check.partial"));
      await typed.fill(spaced(FP_OTHER));
      await expect(check).toHaveAttribute("data-check", "mismatch");
      await expect(check).toContainText(N("enrol.confirm.check.mismatch"));
      await expect(submit).toBeDisabled();
      // The right fingerprint, with colons and in capitals, is the same fingerprint; the addresses must still be ticked.
      await typed.fill(spaced(FP));
      await expect(check).toHaveAttribute("data-check", "match");
      await expect(submit).toBeDisabled();
      await dialog.getByRole("checkbox", {name: N("enrol.confirm.addresses")}).locator("xpath=ancestor::label").click();
      await expect(dialog.locator('input[name="node_name"]')).toHaveValue("host-1");
      await dialog.locator('input[name="node_name"]').fill("");
      await expect(submit).toBeDisabled();
      await dialog.locator('input[name="node_name"]').fill("tehran-9");
      await expect(submit).toBeEnabled();
      await submit.click();
      await waitFresh(page);
      const sent = {fingerprint: FP, name: "tehran-9"};
      await expect.poll(() => bodies(mock, "POST", `/node-enrollments/${w.waiting.id}:confirm`)).toEqual([sent, sent]);
      await expect(page.getByText(N("enrol.confirm.done"))).toBeVisible();
      await expect(dialog).toHaveCount(0);
      await expect(page).not.toHaveURL(/dialog=|enrollmentId=/);
      // The row says confirmed and links to the node, which waits for approval on its own page.
      const row = page.getByRole("grid", {name: N("enrol.list.gridLabel")}).getByRole("row").filter({hasText: "host-1"});
      await expect(row.locator("[data-enrol-state]")).toHaveText(N("enrol.list.state.approved"));
      await row.getByRole("link", {name: N("enrol.list.openRow", {host: "host-1"})}).click();
      await expect(page.getByRole("heading", {level: 1, name: "tehran-9"})).toBeVisible();
      await expect(page.getByTestId("node-summary").getByTestId("fact-state")).toContainText(N("health.pending"));
    });

    test("T-340: a route that finds another fingerprint answers with its own words, and the dialog stays open", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "POST /node-enrollments/{id}:confirm": err(422, "fingerprint_mismatch")}});
      await goto(page);
      await page.getByRole("button", {name: N("enrol.list.compareRow", {host: "host-1"})}).click();
      const dialog = page.getByRole("dialog", {name: N("enrol.confirm.title")});
      await dialog.locator('input[name="typed_fingerprint"]').fill(FP);
      await dialog.getByRole("checkbox", {name: N("enrol.confirm.addresses")}).locator("xpath=ancestor::label").click();
      await dialog.getByTestId("confirm-node-submit").click();
      await expect(dialog.getByText(errText(lang, "fingerprint_mismatch"))).toBeVisible();
    });

    test("T-340: Back closes the confirmation, and a link that arrives on it opens it and closes it to the list", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await page.getByRole("button", {name: N("enrol.list.compareRow", {host: "host-1"})}).click();
      await expect(page.getByRole("dialog", {name: N("enrol.confirm.title")})).toBeVisible();
      await page.goBack();
      await expect(page.getByRole("dialog", {name: N("enrol.confirm.title")})).toHaveCount(0);
      await expect(page).not.toHaveURL(/enrollmentId=/);
      // A direct link opens the same dialog; Cancel takes both parameters out of the address and stays on the page.
      await page.goto(`/${lang}/nodes/enrol?dialog=confirmNode&enrollmentId=${w.waiting.id}`);
      const dialog = page.getByRole("dialog", {name: N("enrol.confirm.title")});
      await expect(dialog).toBeVisible();
      await dialog.getByRole("button", {name: commonText(lang, "cancel")}).click();
      await expect(dialog).toHaveCount(0);
      await expect(page).toHaveURL(new RegExp(`/${lang}/nodes/enrol$`));
    });

    test("T-340: an enrolment that is not in the list, or is no longer waiting, is said in the dialog and cannot be confirmed", async ({page, context, baseURL}) => {
      const w = world();
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await page.goto(`/${lang}/nodes/enrol?dialog=confirmNode&enrollmentId=00000000-0000-4000-8000-0000000fffff`);
      await expect(page.getByTestId("confirm-missing")).toContainText(N("enrol.confirm.missingTitle"));
      await page.goto(`/${lang}/nodes/enrol?dialog=confirmNode&enrollmentId=${w.issued.id}`);
      await expect(page.getByTestId("confirm-closed")).toContainText(N("enrol.confirm.closed", {state: N("enrol.list.state.issued")}));
      await expect(page.getByTestId("confirm-node-submit")).toHaveCount(0);
    });

    test("T-340: rejecting an enrolment spends its token, needs a fresh code, and the row reads rejected", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await page.getByRole("button", {name: N("enrol.list.rejectRow", {host: "host-1"})}).click();
      await expect(page.getByRole("alertdialog")).toContainText(N("enrol.reject.text"));
      await page.getByTestId("confirm-reject").click();
      await waitFresh(page);
      await expect.poll(() => mock.calls.filter((c) => c.method === "POST" && c.path === `/node-enrollments/${w.waiting.id}:reject`).length).toBe(2);
      const row = page.getByRole("grid", {name: N("enrol.list.gridLabel")}).getByRole("row").filter({hasText: "host-1"});
      await expect(row.locator("[data-enrol-state]")).toHaveText(N("enrol.list.state.rejected"));
      await expect(row.getByRole("button")).toHaveCount(0);
    });
  });
}
