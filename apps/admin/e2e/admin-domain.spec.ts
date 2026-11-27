import {certificateFixture, domainFixture} from "@ctrlz/api-client/testing/adminFixtures.ts";
import {createNodeMock, type NodeMockState} from "@ctrlz/api-client/testing/nodeMock.ts";
import type {Locator, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {adm, allowAdminErrors, bodies, commonText, err, errText, gotoShell, LANGS, nodesText, openAdmin, typeCode, type Lang} from "./admin-support.ts";

// p4-nodes 10.1 and 10.4, package PD: the Domain page, in mock mode (spec 17.1). T-344 is the Plan row: the three values with a placeholder, the
// transition and what it touches, the "apply on the server" state with its command, and the certificates (upload and retire). The writes need
// the fresh TOTP window, as on the real routes (`freshRequired`). The private key of an upload is held to the rules of FE 9 and 10: no URL, no
// storage, no copy while it is hidden, and nothing of it left when the dialog goes.

test.beforeEach(({guard}) => allowAdminErrors(guard));

const CODE = "123456";
const DAY = 86_400_000;
const pem = (label: string, body: string) => `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
const CHAIN = pem("CERTIFICATE", "A".repeat(80));
const KEY = pem("PRIVATE KEY", "B".repeat(80));

function world(over: Partial<NodeMockState> = {}) {
  return createNodeMock({domain: domainFixture(), ...over});
}

for (const {lang, dir} of LANGS) {
  test.describe(`admin domain page, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);
    const N = (path: string, values?: Record<string, string | number>) => nodesText(lang, path, values);
    const goto = (page: Page) => gotoShell(page, lang as Lang, "/domain", N("pages.domain.title"));
    const form = (page: Page) => page.getByTestId("domain-form");
    const field = (page: Page, name: string) => form(page).locator(`input[name="${name}"]`);
    const save = (page: Page) => form(page).getByRole("button", {name: N("domain.form.submit")});
    const waitFresh = async (page: Page) => {
      await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
      await typeCode(page, "totp_code", CODE);
    };

    // ---- what is shown ----------------------------------------------------------------------------------------------------------

    test("T-344: the zone and both hosts are shown as technical tokens, and what serves now when it is not what is asked for", async ({page, context, baseURL}) => {
      const w = world({domain: domainFixture({panel_host: "panel2.example.ir", applied_panel_host: "panel.example.ir", applied_admin_host: "admin.example.ir"})});
      await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const status = page.getByTestId("domain-status");
      await expect(status.getByTestId("fact-zone").locator('bdi[dir="ltr"]')).toHaveText("dns.example.ir");
      await expect(status.getByTestId("fact-panel")).toContainText("panel2.example.ir");
      await expect(status.getByTestId("fact-panel")).toContainText("panel.example.ir");
      await expect(status.getByTestId("fact-admin").locator('bdi[dir="ltr"]').first()).toHaveText("admin.example.ir");
    });

    test("T-344: with nothing set the three values say so, and the form's fields hold their placeholders", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world({domain: {apply_pending: false}}).handlers});
      await goto(page);
      await expect(page.getByTestId("fact-zone").getByTestId("not-reported")).toHaveText(N("domain.status.notSet"));
      for (const name of ["dns_zone", "panel_host", "admin_host"] as const) {
        await expect(field(page, name)).toHaveAttribute("placeholder", {dns_zone: "dns.example.ir", panel_host: "panel.example.ir", admin_host: "admin.example.ir"}[name]);
        await expect(field(page, name)).toHaveValue("");
        await expect(field(page, name)).toHaveAttribute("dir", "ltr");
      }
    });

    test("T-344: while an apply is pending the page says so, and shows the command to run on the server with a copy button that names it", async ({page, context, baseURL}) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      await openAdmin(context, baseURL, {handlers: world({domain: domainFixture({apply_pending: true})}).handlers});
      await goto(page);
      const pending = page.getByTestId("domain-apply-pending");
      await expect(pending).toContainText(N("domain.apply.pending.title"));
      await expect(page.getByTestId("domain-apply-done")).toHaveCount(0);
      const command = page.getByTestId("domain-apply-command");
      await expect(command.locator('bdi[dir="ltr"]')).toHaveText("scripts/domain-apply.sh");
      await expect(command).toContainText(N("domain.apply.command.again"));
      await command.getByRole("button", {name: N("domain.apply.command.copy")}).click();
      await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe("scripts/domain-apply.sh");
    });

    test("T-344: when nothing is pending it says what the panel asks for is what serves, and the passkey RP ID points to Settings", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      await expect(page.getByTestId("domain-apply-done")).toContainText(N("domain.apply.done"));
      await expect(page.getByTestId("domain-apply-pending")).toHaveCount(0);
      await expect(page.getByTestId("domain-passkey-link")).toHaveAttribute("href", new RegExp(`/${lang}/settings$`));
    });

    // ---- the three values -------------------------------------------------------------------------------------------------------

    test("T-344: a first zone starts no transition: no length is asked, no impact is read, and the write carries the default", async ({page, context, baseURL}) => {
      const w = world({domain: {apply_pending: false}, freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await field(page, "dns_zone").fill("dns.example.ir");
      await field(page, "panel_host").fill("Panel.Example.ir");
      await field(page, "admin_host").fill("admin.example.ir");
      await expect(form(page).locator('input[name="transition_days"]')).toHaveCount(0);
      await expect(page.getByTestId("domain-impact")).toHaveCount(0);
      expect(mock.count("GET /settings/domain/impact")).toBe(0);
      await save(page).click();
      await waitFresh(page);
      const want = {dns_zone: "dns.example.ir", panel_host: "panel.example.ir", admin_host: "admin.example.ir", transition_days: 30};
      await expect.poll(() => bodies(mock, "PUT", "/settings/domain")).toEqual([want, want]);
      // The panel now asks for hosts the web tier does not serve yet: the apply step is pending, and the form is clean.
      await expect(page.getByTestId("domain-apply-pending")).toBeVisible();
      await expect(save(page)).toBeDisabled();
    });

    test("PG-r2-3: a zone typed with a length and put back leaves nothing to save", async ({page, context, baseURL}) => {
      const w = world();
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await field(page, "dns_zone").fill("dns.example.com");
      const days = form(page).locator('input[name="transition_days"]');
      await days.fill("60");
      await days.blur();
      await field(page, "dns_zone").fill("dns.example.ir");
      await expect(days).toHaveCount(0);
      await expect(save(page)).toBeDisabled();
      expect(bodies(mock, "PUT", "/settings/domain")).toHaveLength(0);
    });

    test("T-344: a change of host alone starts no transition either", async ({page, context, baseURL}) => {
      const w = world();
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await field(page, "panel_host").fill("panel-new.example.ir");
      await expect(form(page).locator('input[name="transition_days"]')).toHaveCount(0);
      await expect(page.getByTestId("domain-impact")).toHaveCount(0);
      await save(page).click();
      await expect.poll(() => bodies(mock, "PUT", "/settings/domain")).toEqual([{dns_zone: "dns.example.ir", panel_host: "panel-new.example.ir", admin_host: "admin.example.ir", transition_days: 30}]);
      expect(w.state.domain.prev_dns_zone).toBeUndefined();
    });

    test("T-344: a change from one zone to another asks for the length, shows what it touches before it is saved, and starts the transition", async ({page, context, baseURL}) => {
      const w = world();
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      // Nothing is read until the zone differs from the one now.
      expect(mock.count("GET /settings/domain/impact")).toBe(0);
      await field(page, "dns_zone").fill("dns.example.com");
      const days = form(page).locator('input[name="transition_days"]');
      await expect(days).toBeVisible();
      await expect(days).toHaveValue(new Intl.NumberFormat(lang === "fa" ? "fa-IR-u-nu-arabext" : "en-US", {useGrouping: false}).format(30));
      const impact = page.getByTestId("domain-impact");
      // The mock counts 12 Endpoints and 3 Apple profiles.
      await expect(impact).toContainText(N("domain.impact.counts", {endpoints: lang === "fa" ? "۱۲" : "12", profiles: lang === "fa" ? "۳" : "3"}));
      await days.fill("14");
      await days.blur();
      await expect(impact).toContainText(N("domain.impact.text", {days: lang === "fa" ? "۱۴" : "14"}));
      await save(page).click();
      await expect.poll(() => bodies(mock, "PUT", "/settings/domain")).toEqual([{dns_zone: "dns.example.com", panel_host: "panel.example.ir", admin_host: "admin.example.ir", transition_days: 14}]);
      // Both zones are served until the end, and the zone cannot be changed again until then.
      const transition = page.getByTestId("domain-transition");
      await expect(transition).toContainText("dns.example.ir");
      await expect(transition).toContainText("dns.example.com");
      await expect(page.getByTestId("domain-transition-running")).toBeVisible();
      await expect(field(page, "dns_zone")).toBeDisabled();
      expect(Date.parse(w.state.domain.transition_until!) - Date.now()).toBeGreaterThan(13 * DAY);
    });

    test("T-344: a length outside 1 to 90 is refused on the page before any request", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      await field(page, "dns_zone").fill("dns.example.com");
      const days = form(page).locator('input[name="transition_days"]');
      await days.fill("0");
      await days.blur();
      // 0 is held to the floor of 1 when the field is left, so the request is never a number the route would refuse.
      await expect(days).toHaveValue(new Intl.NumberFormat(lang === "fa" ? "fa-IR-u-nu-arabext" : "en-US").format(1));
      await days.fill("abc");
      await save(page).click();
      expect(mock.count("PUT /settings/domain")).toBe(0);
    });

    test("T-344: names the rules can read are refused in the field with their reason, and nothing is sent", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const zone = field(page, "dns_zone");
      await zone.fill("example.ir");
      await expect(form(page)).toContainText(N("domain.form.problem.zonePrefix", {prefix: "⁦dns.⁩", example: "⁦dns.example.ir⁩"}));
      await zone.fill("dns.ir");
      await expect(form(page)).toContainText(N("domain.form.problem.zoneShort", {prefix: "⁦dns.⁩", example: "⁦dns.example.ir⁩"}));
      await zone.fill("dns.example.ir");
      await field(page, "panel_host").fill("panel.dns.example.ir");
      await expect(form(page)).toContainText(N("domain.form.problem.underZone", {field: N("domain.form.panel_host"), zone: "⁦dns.example.ir⁩"}));
      await field(page, "panel_host").fill("https://panel.example.ir");
      await expect(form(page)).toContainText(N("domain.form.problem.grammar", {field: N("domain.form.panel_host")}));
      await field(page, "panel_host").fill("same.example.ir");
      await field(page, "admin_host").fill("same.example.ir");
      await expect(form(page)).toContainText(N("domain.form.problem.same"));
      await save(page).click();
      expect(mock.count("PUT /settings/domain")).toBe(0);
    });

    test("T-344: the refusals of the route show with the words of their code", async ({page, context, baseURL}) => {
      const w = world();
      let code = "domain_invalid";
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "PUT /settings/domain": () => err(code === "transition_active" ? 409 : 422, code)}});
      await goto(page);
      await field(page, "panel_host").fill("panel-new.example.ir");
      await save(page).click();
      await expect(form(page).getByText(errText(lang, "domain_invalid"))).toBeVisible();
      code = "transition_active";
      await save(page).click();
      await expect(form(page).getByText(errText(lang, "transition_active"))).toBeVisible();
    });

    test("T-344: a zone that another admin changed while this one was typing is a conflict, and Save waits for an answer", async ({page, context, baseURL}) => {
      await page.clock.install();
      const w = world();
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await field(page, "dns_zone").fill("dns.mine.ir");
      await expect(save(page)).toBeEnabled();
      w.state.domain = {...w.state.domain, dns_zone: "dns.theirs.ir"};
      await page.clock.fastForward(31_000);
      await page.evaluate(() => {
        window.dispatchEvent(new Event("offline"));
        window.dispatchEvent(new Event("online"));
      });
      const note = form(page).getByTestId("conflict-dns_zone");
      await expect(note).toBeVisible();
      await expect(note.getByTestId("conflict-dns_zone-value")).toHaveText("dns.theirs.ir");
      await expect(field(page, "dns_zone")).toHaveValue("dns.mine.ir");
      await expect(save(page)).toBeDisabled();
      expect(mock.count("PUT /settings/domain")).toBe(0);
      await note.getByRole("button", {name: A("conflict.useServer")}).click();
      await expect(note).toHaveCount(0);
      await expect(field(page, "dns_zone")).toHaveValue("dns.theirs.ir");
    });

    // ---- certificates -----------------------------------------------------------------------------------------------------------

    const certs = (now = Date.now()) => [
      certificateFixture({kind: "wildcard", names: ["*.dns.example.ir", "dns.example.ir"], not_after: new Date(now + 200 * DAY).toISOString()}),
      certificateFixture({kind: "panel", names: ["panel.example.ir"], not_after: new Date(now + 10 * DAY).toISOString()}),
      certificateFixture({kind: "admin", names: ["admin.example.ir"], state: "retired"}),
      certificateFixture({kind: "node_ca", source: "issued", names: ["ctrlz-node-ca"], not_after: new Date(now + 900 * DAY).toISOString()}),
    ];
    const certGrid = (page: Page) => page.getByRole("grid", {name: N("domain.certs.gridLabel")});

    test("T-344: the certificates are listed with their kind, names, state as a word and end date, and one that ends soon is flagged", async ({page, context, baseURL}) => {
      const rows = certs();
      await openAdmin(context, baseURL, {handlers: world({certificates: rows}).handlers});
      await goto(page);
      const g = certGrid(page);
      await expect(g.getByRole("row")).toHaveCount(5);
      const wildcard = g.getByRole("row").filter({hasText: N("domain.certs.kinds.wildcard")});
      await expect(wildcard).toContainText("*.dns.example.ir");
      await expect(wildcard).toContainText(N("domain.certs.state.active"));
      await expect(g.getByRole("row").filter({hasText: N("domain.certs.state.retired")})).toContainText(N("domain.certs.kinds.admin"));
      await expect(page.getByTestId(`cert-expiring-${rows[1]!.id}`)).toBeVisible();
      await expect(page.getByTestId(`cert-expiring-${rows[0]!.id}`)).toHaveCount(0);
      // Only an uploaded certificate that is active can be retired: not a retired one, and not a private CA's own.
      await expect(page.getByTestId(`cert-retire-${rows[0]!.id}`)).toBeVisible();
      await expect(page.getByTestId(`cert-retire-${rows[2]!.id}`)).toHaveCount(0);
      await expect(page.getByTestId(`cert-retire-${rows[3]!.id}`)).toHaveCount(0);
      await expect(page.getByTestId(`cert-retire-${rows[0]!.id}`)).toHaveAttribute("aria-label", N("domain.certs.retireRow", {kind: N("domain.certs.kinds.wildcard"), names: "*.dns.example.ir, dns.example.ir"}));
    });

    test("T-344: retiring a certificate is confirmed, says what it does, and is sent with the fresh code", async ({page, context, baseURL}) => {
      const rows = certs();
      const w = world({certificates: rows, freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      await page.getByTestId(`cert-retire-${rows[1]!.id}`).click();
      const dialog = page.getByRole("alertdialog");
      await expect(dialog).toContainText(N("domain.certs.retireText"));
      await dialog.getByTestId("cert-retire-confirm").click();
      await waitFresh(page);
      await expect.poll(() => mock.count("POST /certificates/{id}:retire")).toBe(2);
      await expect(certGrid(page).getByRole("row").filter({hasText: N("domain.certs.kinds.panel")})).toContainText(N("domain.certs.state.retired"));
    });

    test("T-344: a refusal of the retire shows in its dialog", async ({page, context, baseURL, guard}) => {
      // The route answers 404 for a row that is no longer an active uploaded one.
      guard.allowConsole(/status of 404/);
      const rows = certs();
      const w = world({certificates: rows});
      await openAdmin(context, baseURL, {handlers: {...w.handlers, "POST /certificates/{id}:retire": err(404, "not_found")}});
      await goto(page);
      await page.getByTestId(`cert-retire-${rows[0]!.id}`).click();
      const dialog = page.getByRole("alertdialog");
      await dialog.getByTestId("cert-retire-confirm").click();
      await expect(dialog.getByTestId("action-error")).toHaveText(errText(lang, "not_found"));
    });

    test("T-344: an empty list says that the hosts run on the private CA", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world({certificates: []}).handlers});
      await goto(page);
      await expect(page.getByTestId("certificates").getByTestId("grid-empty")).toContainText(N("domain.certs.empty.title"));
    });

    // ---- an upload and its private key --------------------------------------------------------------------------------------------

    const openUpload = async (page: Page) => {
      await page.getByTestId("cert-upload-open").click();
      const dialog = page.getByRole("dialog", {name: N("domain.certs.upload.title")});
      await expect(dialog).toBeVisible();
      return dialog;
    };
    const pickKind = async (dialog: Locator, kind: "wildcard" | "panel" | "admin") => {
      await dialog.getByRole("button", {name: N("domain.certs.upload.kind")}).click();
      await dialog.page().getByRole("option", {name: N(`domain.certs.kinds.${kind}`)}).click();
    };

    test("T-344: an upload sends the kind, the chain and the key once (after the fresh code), shows the new row, and leaves no key behind", async ({page, context, baseURL}) => {
      const w = world({freshRequired: true});
      const mock = await openAdmin(context, baseURL, {handlers: w.handlers});
      await goto(page);
      const dialog = await openUpload(page);
      await pickKind(dialog, "wildcard");
      await dialog.getByTestId("cert-chain").fill(CHAIN);
      await dialog.getByTestId("cert-key").fill(KEY);
      await dialog.getByRole("button", {name: N("domain.certs.upload.submit"), exact: true}).click();
      await waitFresh(page);
      const want = {kind: "wildcard", chain_pem: CHAIN, key_pem: KEY};
      await expect.poll(() => bodies(mock, "POST", "/certificates")).toEqual([want, want]);
      await expect(dialog).toHaveCount(0);
      await expect(certGrid(page).getByRole("row")).toHaveCount(3);
      // The private key is in no address, no storage and no part of the page: the dialog and its fields are gone.
      expect(page.url()).not.toContain("BBBB");
      const leaks = await page.evaluate(async () => {
        const hold = [JSON.stringify({...localStorage}), JSON.stringify({...sessionStorage}), document.body.innerHTML, document.cookie];
        const databases = (await indexedDB.databases?.()) ?? [];
        return {text: hold.some((text) => text.includes("BBBBBBBB")), databases: databases.length};
      });
      expect(leaks).toEqual({text: false, databases: 0});
    });

    test("T-344: the key box is not a password field, is masked, and cannot be copied or cut while it is hidden; Show makes it plain", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const dialog = await openUpload(page);
      const key = dialog.getByTestId("cert-key");
      await key.fill(KEY);
      await expect(key).not.toHaveAttribute("type", "password");
      await expect(key).toHaveAttribute("autocomplete", "off");
      await expect(key).toHaveAttribute("spellcheck", "false");
      // The opt-out of the password managers and of the writing assistants, which would send the text of the key away (PG-r1-13).
      await expect(key).toHaveAttribute("data-1p-ignore", "true");
      await expect(key).toHaveAttribute("data-lpignore", "true");
      await expect(key).toHaveAttribute("data-bwignore", "true");
      await expect(key).toHaveAttribute("data-gramm", "false");
      await expect(key).toHaveAttribute("data-gramm_editor", "false");
      await expect(key).toHaveAttribute("data-enable-grammarly", "false");
      await expect(key).toHaveAttribute("data-lt-active", "false");
      await expect(key).not.toHaveAttribute("name", /user|pass/i);
      await expect(key).toHaveCSS("-webkit-text-security", "disc");
      const copyPrevented = (locator: Locator, type: "copy" | "cut") =>
        locator.evaluate((el, kind) => {
          const event = new ClipboardEvent(kind, {bubbles: true, cancelable: true});
          el.dispatchEvent(event);
          return event.defaultPrevented;
        }, type);
      expect(await copyPrevented(key, "copy")).toBe(true);
      expect(await copyPrevented(key, "cut")).toBe(true);
      await dialog.getByRole("button", {name: N("domain.certs.upload.show", {field: N("domain.certs.upload.key")})}).click();
      await expect(key).not.toHaveCSS("-webkit-text-security", "disc");
      expect(await copyPrevented(key, "copy")).toBe(false);
      // The chain is not a secret and has no mask.
      await expect(dialog.getByTestId("cert-chain")).not.toHaveCSS("-webkit-text-security", "disc");
    });

    test("PG-r3-4: the chain box has the same opt-outs, and a private key put there is removed at once with the reason", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const dialog = await openUpload(page);
      const chain = dialog.getByTestId("cert-chain");
      for (const attribute of ["data-1p-ignore", "data-lpignore", "data-bwignore", "data-gramm", "data-gramm_editor", "data-enable-grammarly", "data-lt-active"]) {
        await expect(chain).toHaveAttribute(attribute, /true|false|other/);
      }
      await chain.fill(CHAIN + "\n" + KEY);
      await expect(chain).toHaveValue(CHAIN);
      await expect(dialog).toContainText(N("domain.certs.upload.problem.keyInChain"));
      // The same by a file: the combined file leaves no key in the box.
      await dialog.getByTestId("cert-chain-file").setInputFiles({name: "both.pem", mimeType: "text/plain", buffer: Buffer.from(KEY + "\n" + CHAIN)});
      await expect(chain).toHaveValue(CHAIN);
      expect(await chain.inputValue()).not.toContain("PRIVATE KEY");
    });

    test("T-344: a file picked for the chain or the key is read into its box, and nothing of the file's name stays in the input", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const dialog = await openUpload(page);
      await dialog.getByTestId("cert-chain-file").setInputFiles({name: "fullchain.pem", mimeType: "text/plain", buffer: Buffer.from(CHAIN)});
      await expect(dialog.getByTestId("cert-chain")).toHaveValue(CHAIN);
      await dialog.getByTestId("cert-key-file").setInputFiles({name: "privkey.pem", mimeType: "text/plain", buffer: Buffer.from(KEY)});
      await expect(dialog.getByTestId("cert-key")).toHaveValue(KEY);
      expect(await dialog.getByTestId("cert-key-file").evaluate((input: HTMLInputElement) => input.value)).toBe("");
      // A file over the limit is not read.
      await dialog.getByTestId("cert-key-file").setInputFiles({name: "huge.pem", mimeType: "text/plain", buffer: Buffer.alloc(9000, "A")});
      await expect(dialog).toContainText(N("domain.certs.upload.problem.tooLong"));
      await expect(dialog.getByTestId("cert-key")).toHaveValue(KEY);
    });

    test("T-344: what the page can see is wrong with the text is said in the box, and nothing is sent", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const dialog = await openUpload(page);
      const submit = dialog.getByRole("button", {name: N("domain.certs.upload.submit"), exact: true});
      await submit.click();
      await expect(dialog).toContainText(N("domain.certs.upload.problem.kind"));
      await pickKind(dialog, "panel");
      await submit.click();
      await expect(dialog).toContainText(N("domain.certs.upload.problem.empty"));
      // A key in the chain box, and a certificate in the key box, are named for what they are.
      // The key put in the chain box is taken out of it at once (PG-r3-4), so the box is empty and the reason is said without a submit.
      await dialog.getByTestId("cert-chain").fill(KEY);
      await expect(dialog.getByTestId("cert-chain")).toHaveValue("");
      await expect(dialog).toContainText(N("domain.certs.upload.problem.keyInChain"));
      await dialog.getByTestId("cert-chain").fill(CHAIN);
      await dialog.getByTestId("cert-key").fill(CHAIN);
      await submit.click();
      await expect(dialog).toContainText(N("domain.certs.upload.problem.isCertificate"));
      await dialog.getByTestId("cert-key").fill("not a pem, but long enough to pass the length floor of sixty-four characters.");
      await submit.click();
      await expect(dialog).toContainText(N("domain.certs.upload.problem.shape"));
      expect(mock.count("POST /certificates")).toBe(0);
    });

    test("T-344: the refusals of the server show in the dialog with the words of their code, and what was typed stays for the fix", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      const dialog = await openUpload(page);
      await pickKind(dialog, "admin");
      const submit = dialog.getByRole("button", {name: N("domain.certs.upload.submit"), exact: true});
      const chain = dialog.getByTestId("cert-chain");
      const key = dialog.getByTestId("cert-key");
      await chain.fill(CHAIN);
      await key.fill(pem("PRIVATE KEY", `MISMATCH${"B".repeat(80)}`));
      await submit.click();
      await expect(dialog.getByText(errText(lang, "cert_key_mismatch"))).toBeVisible();
      await chain.fill(pem("CERTIFICATE", `PRIVATECA${"A".repeat(80)}`));
      await key.fill(KEY);
      await submit.click();
      await expect(dialog.getByText(errText(lang, "cert_not_public"))).toBeVisible();
      await chain.fill(pem("CERTIFICATE", `EXPIRING${"A".repeat(80)}`));
      await submit.click();
      await expect(dialog.getByText(errText(lang, "cert_expiring"))).toBeVisible();
      // The text is still there and the dialog is still open: the admin fixes it and sends it again.
      await expect(key).toHaveValue(KEY);
      await expect(dialog).toBeVisible();
      expect(mock.count("POST /certificates")).toBe(3);
    });

    test("T-344: Cancel leaves nothing of what was typed, and the next upload starts empty", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: world().handlers});
      await goto(page);
      let dialog = await openUpload(page);
      await dialog.getByTestId("cert-key").fill(KEY);
      await dialog.getByRole("button", {name: commonText(lang, "cancel"), exact: true}).click();
      await expect(dialog).toHaveCount(0);
      dialog = await openUpload(page);
      await expect(dialog.getByTestId("cert-key")).toHaveValue("");
      await expect(dialog.getByTestId("cert-chain")).toHaveValue("");
    });
  });
}
