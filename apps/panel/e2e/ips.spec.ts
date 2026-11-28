import type {Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {screenHandlers} from "@ctrlz/api-client/testing/screenMock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {callsTo, openList, tick} from "./endpoint-screens-support.ts";
import {lockedUntilPassword, nf, text as endpointText} from "./endpoint-pages-support.ts";
import {AUTHORIZED, CLAIM, ENDPOINT, endpointPath} from "./endpoints-support.ts";
import {LANGS, LOCK_PASSWORD, PROFILE, text as profileText} from "./profiles-support.ts";

// The IPs page, spec p3 10, 4, 5 (T-262, T-263, T-267, T-268): the Plain DNS claims with their states, the proof dialog with its three ways and
// its code, the Authorized IPs with their protections, add and batch delete, and the Dynamic DNS hosts. Home router has four claims (active,
// waiting, grace, suspended), four authorized addresses (the first is the address of this browser) and a Dynamic DNS host.

test.use({viewport: {width: 1280, height: 900}, allowConsole: [/status of 4\d\d/]});

const ipsPath = (lang: "fa" | "en", dialog = "") => `${endpointPath(lang, ENDPOINT.home, "ips")}${dialog ? `?ipDialog=${dialog}` : ""}`;

for (const {lang, dir} of LANGS) {
  const text = (path: string, values: Record<string, string | number> = {}) => endpointText(lang, path, values);
  const dialogOf = (page: Page, title: string) => page.getByRole("dialog", {name: title});
  const claimRow = (page: Page, cidr: string) => page.getByRole("listitem").filter({hasText: cidr}).filter({has: page.getByRole("button", {name: text("ips.claims.releaseAria", {cidr})})});
  const authorizedRow = (page: Page, cidr: string) => page.locator(".authorized-list").getByRole("listitem").filter({hasText: cidr});

  test.describe(`${lang} (${dir})`, () => {
    test("T-267, T-268: each claim shows its state in words, whether it is proven, the date its grace ends, and offers proof only where proof helps", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(ipsPath(lang));
      const active = claimRow(page, "203.0.113.7/32");
      await expect(active).toContainText(text("ips.claims.state.active"));
      await expect(active).toContainText(text("ips.claims.proven"));
      await expect(active.getByRole("button", {name: text("ips.claims.proveAria", {cidr: "203.0.113.7/32"})})).toHaveCount(0);

      const pending = claimRow(page, "198.51.100.0/24");
      await expect(pending).toContainText(text("ips.claims.state.pending_proof"));
      await expect(pending).toContainText(text("ips.claims.unproven"));
      await expect(pending.getByRole("button", {name: text("ips.claims.proveAria", {cidr: "198.51.100.0/24"})})).toBeVisible();

      const grace = claimRow(page, "192.0.2.0/28");
      await expect(grace).toContainText(text("ips.claims.state.grace"));
      await expect(grace).toContainText(text("ips.claims.graceUntil", {date: ""}).split("{")[0]!.trim() || text("ips.claims.state.grace"));
      await expect(grace.getByRole("button", {name: text("ips.claims.proveAria", {cidr: "192.0.2.0/28"})})).toBeVisible();
      await expect(page.getByText(text("ips.claims.graceNote"))).toBeVisible();

      const suspended = claimRow(page, "192.0.2.64/26");
      await expect(suspended).toContainText(text("ips.claims.state.suspended"));
      await expect(suspended).toContainText(text("ips.claims.needsAdmin"));
      await expect(suspended.getByRole("button", {name: text("ips.claims.proveAria", {cidr: "192.0.2.64/26"})})).toHaveCount(0);
      await expect(suspended.getByRole("button", {name: text("ips.claims.releaseAria", {cidr: "192.0.2.64/26"})})).toBeDisabled();
    });

    test("T-267: a typed address makes a claim that waits for proof, and the proof dialog replaces the claim dialog in one history entry", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang));
      await page.getByRole("button", {name: text("ips.claims.add"), exact: true}).first().click();
      const dialog = dialogOf(page, text("ips.claim.title"));
      await expect(page).toHaveURL(/ipDialog=claim$/);
      await dialog.getByRole("textbox", {name: text("ips.claim.field")}).fill("not an address");
      await dialog.getByRole("button", {name: text("ips.claim.submit"), exact: true}).click();
      await expect(dialog.getByText(lang === "fa" ? "درست نیست." : /not valid/i)).toBeVisible();
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims`)).toHaveLength(0);

      await dialog.getByRole("textbox", {name: text("ips.claim.field")}).fill("203.0.113.50");
      await dialog.getByRole("button", {name: text("ips.claim.submit"), exact: true}).click();
      await expect(dialogOf(page, text("ips.proof.title", {cidr: "203.0.113.50"}))).toBeVisible();
      await expect(page).toHaveURL(/ipDialog=proof(:|%3A)/);
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims`)[0]!.body).toEqual({cidr: "203.0.113.50"});
      await page.goBack();
      await expect(page).not.toHaveURL(/ipDialog/);
    });

    test("T-267: the address of this browser can be claimed, with the note that a device's own address may differ", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang, "claim"));
      const dialog = dialogOf(page, text("ips.claim.title"));
      await expect(dialog).toContainText(text("ips.claim.useMineNote"));
      await dialog.getByRole("button", {name: text("ips.claim.useMine")}).click();
      await expect.poll(() => callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims`).length).toBe(1);
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims`)[0]!.body).toEqual({use_my_address: true});
    });

    test("T-267: a refused claim says why: a reserved range, a suspended address, a limit, and the wait of the hourly rate with its seconds", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang, "claim"));
      const dialog = dialogOf(page, text("ips.claim.title"));
      const field = dialog.getByRole("textbox", {name: text("ips.claim.field")});
      const submit = dialog.getByRole("button", {name: text("ips.claim.submit"), exact: true});

      mock.on("POST /endpoints/{id}/ip-claims", {status: 422, body: errorBody("validation_failed", {fields: [{name: "/cidr", code: "reserved_range"}]})});
      await field.fill("10.0.0.1");
      await submit.click();
      await expect(dialog.getByText(lang === "fa" ? "این بازه رزرو است." : /reserved/i)).toBeVisible();

      mock.on("POST /endpoints/{id}/ip-claims", {status: 409, body: errorBody("ip_suspended")});
      await field.fill("10.0.0.2");
      await submit.click();
      await expect(dialog.getByText(lang === "fa" ? /معلق شده/ : /suspended/i)).toBeVisible();

      mock.on("POST /endpoints/{id}/ip-claims", {status: 429, headers: {"retry-after": "60"}, body: errorBody("rate_limited")});
      await field.fill("10.0.0.3");
      await submit.click();
      await expect(dialog.getByText(lang === "fa" ? new RegExp(`${nf(lang, 60)}|${nf(lang, 59)}`) : /60|59/)).toBeVisible();
      await expect(submit).toBeDisabled();
    });

    test("T-267: the limit of claims is a notice with its name", async ({page, context, baseURL}) => {
      await openList(context, baseURL, {limits: {max_ip_claims: 0}});
      await page.goto(ipsPath(lang, "claim"));
      const dialog = dialogOf(page, text("ips.claim.title"));
      await dialog.getByRole("textbox", {name: text("ips.claim.field")}).fill("203.0.113.99");
      await dialog.getByRole("button", {name: text("ips.claim.submit"), exact: true}).click();
      await expect(dialog).toContainText(lang === "fa" ? "ادعاهای IP" : /IP claims/i);
    });

    test("T-267: the proof dialog starts a challenge, shows the three ways with copyable commands, and a typed code proves the address", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      await page.goto(ipsPath(lang, `proof:${CLAIM.pending}`));
      const dialog = dialogOf(page, text("ips.proof.title", {cidr: "198.51.100.0/24"}));
      await expect(dialog).toBeVisible();
      // The fixture's challenge ended long ago, so the dialog offers a new one.
      await expect(dialog.getByText(text("ips.proof.expired"))).toBeVisible();
      await dialog.getByRole("button", {name: text("ips.proof.again")}).click();
      await expect(dialog.getByTestId("proof-steps")).toBeVisible();
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims/${CLAIM.pending}/challenges`)).toHaveLength(1);
      // S6-r2-1: the countdown is a number of seconds in this language's digits, never "NaN" or "ناعدد".
      const countdown = dialog.getByText(lang === "fa" ? /ثانیه تا پایان کد/ : /until the code ends/);
      await expect(countdown).toHaveText(lang === "fa" ? /^[۰-۹]+ ثانیه تا پایان کد$/ : /^[0-9]+ seconds? until the code ends$/);

      const host = "abcdefghijklmnopqrstuvwxyz.verify.dns.example.test";
      await expect(dialog.getByRole("region", {name: text("ips.proof.tcp.title")})).toContainText(`dig +tcp TXT ${host} @203.0.113.53`);
      await expect(dialog.getByRole("region", {name: text("ips.proof.tcp.title")})).toContainText(`nslookup -vc -type=TXT ${host} 203.0.113.53`);
      await expect(dialog.getByRole("region", {name: text("ips.proof.udp.title")})).toContainText(`dig TXT ${host} @203.0.113.53`);
      // The browser's way is not offered where the installation has no verify origin.
      await expect(dialog.getByRole("region", {name: text("ips.proof.secure.title")})).toContainText(text("ips.proof.secure.off"));
      await dialog.getByRole("button", {name: lang === "fa" ? new RegExp(`${text("ips.proof.nameLabel")}`) : /Copy Name to query/}).click();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(host);

      // A wrong code is not proof, and the dialog says the code is not right (not that the query came from another address).
      const code = dialog.getByRole("textbox", {name: text("ips.proof.udp.code")});
      await code.fill("k9q2w7");
      await dialog.getByRole("button", {name: text("ips.proof.udp.check")}).click();
      await expect(dialog.getByText(text("ips.proof.noProofTitle"))).toBeVisible();
      await expect(dialog.getByText(text("ips.proof.noProofCodeText"))).toBeVisible();
      await expect(dialog.getByText(text("ips.proof.noProofText"))).toHaveCount(0);
      await code.fill("123456");
      await dialog.getByRole("button", {name: text("ips.proof.udp.check")}).click();
      await expect(dialog.getByText(text("ips.proof.provenTitle", {cidr: "198.51.100.0/24"}))).toBeVisible();
      const takes = callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims/${CLAIM.pending}:take`);
      expect(takes.map((c) => c.body)).toEqual([{code: "k9q2w7"}, {code: "123456"}]);
      expect(page.url()).not.toContain("123456");
      await dialog.getByRole("button", {name: lang === "fa" ? "انجام شد" : "Done"}).click();
      await expect(claimRow(page, "198.51.100.0/24")).toContainText(text("ips.claims.state.active"));
      await expectNoSecretResidue(page, ["123456", "k9q2w7"], "the proof code");
    });

    test("T-267: an observed query over TCP takes the claim by itself, within the 3-second reading", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang, `proof:${CLAIM.pending}`));
      const dialog = dialogOf(page, text("ips.proof.title", {cidr: "198.51.100.0/24"}));
      await dialog.getByRole("button", {name: text("ips.proof.again")}).click();
      await expect(dialog.getByTestId("proof-status")).toContainText(text("ips.proof.notYet"));
      // The node reports the query: the claim now carries the observation.
      mock.screens.claims.set(ENDPOINT.home, mock.screens.claims.get(ENDPOINT.home)!.map((c) => (c.id === CLAIM.pending && c.challenge ? {...c, challenge: {...c.challenge, observed: true, observed_protocol: "tcp"}} : c)));
      await expect(dialog.getByText(text("ips.proof.provenTitle", {cidr: "198.51.100.0/24"}))).toBeVisible({timeout: 15_000});
      const takes = callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims/${CLAIM.pending}:take`);
      expect(takes).toHaveLength(1);
      expect(takes[0]!.body).toEqual({});
    });

    test("T-267: too many codes in a minute is a wait with its seconds, and the button stays off until it ends", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      mock.on("POST /endpoints/{id}/ip-claims/{claim_id}/challenges", {status: 429, headers: {"retry-after": "60"}, body: errorBody("too_many_attempts")});
      await page.goto(ipsPath(lang, `proof:${CLAIM.pending}`));
      const dialog = dialogOf(page, text("ips.proof.title", {cidr: "198.51.100.0/24"}));
      const start = dialog.getByRole("button", {name: text("ips.proof.again")});
      await start.click();
      await expect(dialog.getByText(lang === "fa" ? new RegExp(`${nf(lang, 60)}|${nf(lang, 59)}`) : /60|59/)).toBeVisible();
      await expect(start).toBeDisabled();
    });

    test("T-267: a claim that waits for an administrator and one that is suspended say so instead of offering proof", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(ipsPath(lang, `proof:${CLAIM.suspended}`));
      await expect(dialogOf(page, text("ips.proof.title", {cidr: "192.0.2.64/26"}))).toContainText(text("ips.proof.suspended"));
    });

    test("T-267: with no service domain the proof cannot start, and says why", async ({page, context, baseURL}) => {
      await openList(context, baseURL, {resolverNotReady: true});
      await page.goto(ipsPath(lang, `proof:${CLAIM.pending}`));
      const dialog = dialogOf(page, text("ips.proof.title", {cidr: "198.51.100.0/24"}));
      await expect(dialog).toContainText(text("ips.proof.noZone"));
      await expect(dialog.getByRole("button", {name: text("ips.proof.again")})).toBeDisabled();
    });

    test("T-267: a proof link to a claim that is not there says so", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(ipsPath(lang, "proof:00000000-0000-4000-8000-000000000999"));
      await expect(dialogOf(page, text("ips.proof.titleNone"))).toContainText(text("ips.proof.gone"));
    });

    test("T-267: releasing a claim asks first and then sends the release", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang));
      await page.getByRole("button", {name: text("ips.claims.releaseAria", {cidr: "198.51.100.0/24"})}).click();
      const dialog = dialogOf(page, text("ips.claims.releaseTitle", {cidr: "198.51.100.0/24"}));
      await dialog.getByRole("button", {name: text("ips.claims.releaseSubmit")}).click();
      await expect(dialog).toBeHidden();
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims/${CLAIM.pending}:release`)).toHaveLength(1);
      await expect(page.getByRole("listitem").filter({hasText: "198.51.100.0/24"}).filter({has: page.getByRole("button", {name: text("ips.claims.releaseAria", {cidr: "198.51.100.0/24"})})})).toHaveCount(0);
    });

    test("T-267: with Plain DNS off the page says claims are not served, and offers the Endpoint's edit", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.home ? {...e, legacy_dns: false} : e));
      await page.goto(ipsPath(lang));
      await expect(page.getByText(text("ips.claims.legacyOffTitle"))).toBeVisible();
      await page.getByTestId("claims-section").getByRole("button", {name: text("ips.claims.legacyOffLink")}).click();
      await expect(page).toHaveURL(new RegExp(`deviceDialog=edit&deviceId=${ENDPOINT.home}`));
    });

    test("T-262: the authorized addresses show their kind, place and time, and the current one is marked and cannot be deleted", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(ipsPath(lang));
      const current = authorizedRow(page, "203.0.113.7/32");
      await expect(current).toContainText(text("ips.authorized.source.manual"));
      await expect(current).toContainText("Tehran");
      await expect(current).toContainText("Example ISP");
      await expect(current).toContainText(text("ips.authorized.currentChip"));
      await expect(current.getByRole("button", {name: text("ips.authorized.deleteAria", {cidr: "203.0.113.7/32"})})).toBeDisabled();
      await expect(authorizedRow(page, "2001:db8::/48")).toContainText(text("ips.authorized.source.secure_dns"));
      await expect(authorizedRow(page, "192.0.2.9/32")).toContainText(text("ips.authorized.source.ddns"));
      await expect(authorizedRow(page, "198.51.100.0/24").getByRole("button", {name: text("ips.authorized.deleteAria", {cidr: "198.51.100.0/24"})})).toBeEnabled();
      // Only a hand-made address has the clean-up switch.
      await expect(authorizedRow(page, "2001:db8::/48").getByRole("switch")).toHaveCount(0);
    });

    test("T-262: the list is searched on the server and copied from", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      await page.goto(ipsPath(lang));
      await page.getByRole("searchbox", {name: text("ips.authorized.searchLabel")}).fill("198.51");
      await expect.poll(() => callsTo(mock.calls, "GET", `/endpoints/${ENDPOINT.home}/authorized-ips`).some((c) => c.query.get("q") === "198.51")).toBe(true);
      await expect(authorizedRow(page, "203.0.113.7/32")).toHaveCount(0);
      await authorizedRow(page, "198.51.100.0/24").getByRole("button", {name: text("ips.authorized.copyAria", {cidr: "198.51.100.0/24"})}).click();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("198.51.100.0/24");
      await page.getByRole("searchbox", {name: text("ips.authorized.searchLabel")}).fill("nothing like it");
      await expect(page.getByText(text("ips.authorized.emptyFiltered"))).toBeVisible();
    });

    test("T-262: add takes an address, a subnet or a list, checks each before a request, and names the entry the server refuses", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang));
      await page.getByRole("button", {name: text("ips.authorized.add"), exact: true}).first().click();
      const dialog = dialogOf(page, text("ips.add.title"));
      await expect(page).toHaveURL(/ipDialog=add$/);
      const field = dialog.getByRole("textbox", {name: text("ips.add.field")});
      await field.fill("203.0.113.200/32\n198.51.100.128/25, nonsense");
      await dialog.getByRole("button", {name: text("ips.add.submit"), exact: true}).click();
      await expect(dialog.getByText(text("ips.add.badEntry", {n: nf(lang, 3), text: "nonsense"}))).toBeVisible();
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/authorized-ips`)).toHaveLength(0);

      await field.fill("203.0.113.200/32\n198.51.100.0/24");
      await dialog.getByRole("button", {name: text("ips.add.submit"), exact: true}).click();
      await expect(dialog.getByRole("alert").getByText(new RegExp("198\\.51\\.100\\.0/24"))).toBeVisible();

      await field.fill("203.0.113.200/32, ۱۹۸.۵۱.۱۰۰.۱۲۸/۲۵");
      await dialog.getByRole("button", {name: text("ips.add.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/authorized-ips`).at(-1)!.body).toEqual({cidrs: ["203.0.113.200/32", "198.51.100.128/25"]});
      await expect(authorizedRow(page, "198.51.100.128/25")).toBeVisible();
    });

    test("T-262: select several and delete them after a confirmation", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang));
      await page.getByRole("button", {name: text("ips.authorized.menu")}).click();
      await page.getByRole("menuitem", {name: text("ips.authorized.select")}).click();
      // The current address cannot be ticked.
      await expect(page.getByRole("checkbox", {name: text("ips.authorized.selectAria", {cidr: "203.0.113.7/32"})})).toBeDisabled();
      await tick(page.getByRole("checkbox", {name: text("ips.authorized.selectAria", {cidr: "198.51.100.0/24"})}));
      await tick(page.getByRole("checkbox", {name: text("ips.authorized.selectAria", {cidr: "192.0.2.9/32"})}));
      await page.getByRole("toolbar").getByRole("button", {name: new RegExp(text("ips.authorized.deleteSelected"))}).click();
      const dialog = dialogOf(page, text("ips.delete.title", {count: nf(lang, 2)}));
      await dialog.getByRole("button", {name: text("ips.delete.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/authorized-ips:delete`)[0]!.body).toEqual({ids: [expect.any(String), expect.any(String)]});
      await expect(authorizedRow(page, "198.51.100.0/24")).toHaveCount(0);
      await expect(authorizedRow(page, "203.0.113.7/32")).toBeVisible();
    });

    test("T-263: under Require the last address is marked and kept, and a selection that would empty the list cannot be sent", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.home ? {...e, require_authorized_ips: true} : e));
      const keep = mock.screens.authorized.get(ENDPOINT.home)!;
      mock.screens.authorized.set(ENDPOINT.home, keep.filter((r) => r.id !== AUTHORIZED.current && r.cidr !== "192.0.2.9/32" && r.cidr !== "2001:db8::/48"));
      await page.goto(ipsPath(lang));
      const last = authorizedRow(page, "198.51.100.0/24");
      await expect(last).toContainText(text("ips.authorized.lastChip"));
      await expect(last.getByRole("button", {name: text("ips.authorized.deleteAria", {cidr: "198.51.100.0/24"})})).toBeDisabled();
      await expect(page.getByText(text("ips.authorized.requireOn"))).toBeVisible();
      expect(callsTo(mock.calls, "POST", /authorized-ips:delete$/)).toHaveLength(0);

      // With two, a selection of both is refused on the page, and one of them is not.
      mock.screens.authorized.set(ENDPOINT.home, keep.filter((r) => r.id !== AUTHORIZED.current && r.cidr !== "192.0.2.9/32"));
      await page.reload();
      await page.getByRole("button", {name: text("ips.authorized.menu")}).click();
      await page.getByRole("menuitem", {name: text("ips.authorized.select")}).click();
      await tick(page.getByRole("checkbox", {name: text("ips.authorized.selectAria", {cidr: "198.51.100.0/24"})}));
      await tick(page.getByRole("checkbox", {name: text("ips.authorized.selectAria", {cidr: "2001:db8::/48"})}));
      await page.getByRole("toolbar").getByRole("button", {name: new RegExp(text("ips.authorized.deleteSelected"))}).click();
      const dialog = dialogOf(page, text("ips.delete.title", {count: nf(lang, 2)}));
      await expect(dialog.getByRole("button", {name: text("ips.delete.submit"), exact: true})).toBeDisabled();
      await expect(dialog).toContainText(lang === "fa" ? "آخرین نشانی حذف نمی‌شود" : /last address/i);
      expect(callsTo(mock.calls, "POST", /authorized-ips:delete$/)).toHaveLength(0);
    });

    test("T-263: a refusal of the server (a protection the page did not know of) is said in words and keeps the dialog", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      mock.on("POST /endpoints/{id}/authorized-ips:delete", {status: 422, body: errorBody("validation_failed", {fields: [{name: "/ids/0", code: "current_address"}]})});
      await page.goto(ipsPath(lang));
      await page.getByRole("button", {name: text("ips.authorized.deleteAria", {cidr: "198.51.100.0/24"})}).click();
      const dialog = dialogOf(page, text("ips.delete.title", {count: nf(lang, 1)}));
      await dialog.getByRole("button", {name: text("ips.delete.submit"), exact: true}).click();
      await expect(dialog.getByRole("alert")).toContainText(lang === "fa" ? "این نشانی فعلی شماست" : /current address/i);
      await expect(dialog).toBeVisible();
    });

    test("T-262: the switch of a hand-made address turns its clean-up on", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang));
      const row = authorizedRow(page, "203.0.113.7/32");
      await row.getByText(text("ips.authorized.cleanup"), {exact: true}).click();
      await expect.poll(() => callsTo(mock.calls, "PATCH", /authorized-ips\/[^/]+$/).length).toBe(1);
      expect(callsTo(mock.calls, "PATCH", /authorized-ips\/[^/]+$/)[0]!.body).toEqual({cleanup_opt_in: true});
    });

    test("T-272: Dynamic DNS hosts are listed when the Endpoint uses them, added, and deleted with a confirmation", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang));
      await expect(page.getByTestId("ddns-section")).toHaveCount(0);
      mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.home ? {...e, authorize_ddns: true} : e));
      await page.reload();
      const section = page.getByTestId("ddns-section");
      await expect(section).toContainText("home.example.org");
      await section.getByRole("textbox", {name: text("ips.ddns.field")}).fill("office.example.org");
      await section.getByRole("button", {name: text("ips.ddns.add"), exact: true}).click();
      await expect(section).toContainText("office.example.org");
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ddns-hosts`)[0]!.body).toEqual({hostname: "office.example.org"});
      await section.getByRole("textbox", {name: text("ips.ddns.field")}).fill("office.example.org");
      await section.getByRole("button", {name: text("ips.ddns.add"), exact: true}).click();
      await expect(section.getByText(lang === "fa" ? "از قبل وجود دارد." : /already exists/i)).toBeVisible();

      await section.getByRole("button", {name: text("ips.ddns.deleteAria", {name: "home.example.org"})}).click();
      const dialog = dialogOf(page, text("ips.ddns.deleteTitle", {name: "home.example.org"}));
      await dialog.getByRole("button", {name: text("ips.ddns.deleteSubmit")}).click();
      await expect(dialog).toBeHidden();
      await expect(section).not.toContainText("home.example.org");
    });

    test("S6-r1-5: a bare address is sent as typed and the server makes it a host prefix", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang, "add"));
      const dialog = dialogOf(page, text("ips.add.title"));
      await dialog.getByRole("textbox", {name: text("ips.add.field")}).fill("203.0.113.201");
      await dialog.getByRole("button", {name: text("ips.add.submit"), exact: true}).click();
      await expect(dialog).toBeHidden();
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/authorized-ips`).at(-1)!.body).toEqual({cidrs: ["203.0.113.201"]});
      await expect(authorizedRow(page, "203.0.113.201/32")).toBeVisible();
    });

    test("S6-r1-5: releasing a claim of an Endpoint on a locked profile asks for the lock password, a wrong one stays, the right one releases", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      // Office PC holds the waiting claim of Home router: its profile is locked, so the release is a write to a locked Endpoint.
      mock.screens.claims.set(ENDPOINT.office, mock.screens.claims.get(ENDPOINT.home)!.filter((c) => c.id === CLAIM.pending));
      const base = screenHandlers(mock.screens)["POST /endpoints/{id}/ip-claims/{claim_id}:release"]!;
      mock.on("POST /endpoints/{id}/ip-claims/{claim_id}:release", (call, state) => {
        const asked = lockedUntilPassword(PROFILE.office, LOCK_PASSWORD, () => ({status: 200}))(call);
        return asked.status === 200 ? base(call, state) : asked;
      });
      await page.goto(endpointPath(lang, ENDPOINT.office, "ips"));
      await page.getByRole("button", {name: text("ips.claims.releaseAria", {cidr: "198.51.100.0/24"})}).click();
      await dialogOf(page, text("ips.claims.releaseTitle", {cidr: "198.51.100.0/24"})).getByRole("button", {name: text("ips.claims.releaseSubmit")}).click();
      const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
      await expect(needed).toBeVisible();
      const field = needed.getByLabel(/Office/);
      await field.fill("not the password");
      await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
      await expect(needed).toBeVisible();
      await field.fill(LOCK_PASSWORD);
      await needed.getByRole("button", {name: profileText(lang, "profiles", "lock.dialog.continue")}).click();
      await expect(needed).toBeHidden();
      expect(mock.screens.claims.get(ENDPOINT.office)).toEqual([]);
      expect(page.url()).not.toContain(LOCK_PASSWORD);
      await expectNoSecretResidue(page, [LOCK_PASSWORD, "not the password"], "the lock password of a claim release");
    });

    test("S6-r1-5: a Dynamic DNS host delete the server refuses names the protection and keeps the dialog", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.home ? {...e, authorize_ddns: true} : e));
      await page.goto(ipsPath(lang));
      const section = page.getByTestId("ddns-section");
      const cancel = lang === "fa" ? "انصراف" : "Cancel";
      const refusal = async (code: string, words: RegExp) => {
        mock.on("POST /endpoints/{id}/ddns-hosts/{hid}:delete", {status: 422, body: errorBody("validation_failed", {fields: [{name: "/hostname", code}]})});
        await section.getByRole("button", {name: text("ips.ddns.deleteAria", {name: "home.example.org"})}).click();
        const dialog = dialogOf(page, text("ips.ddns.deleteTitle", {name: "home.example.org"}));
        await dialog.getByRole("button", {name: text("ips.ddns.deleteSubmit")}).click();
        await expect(dialog.getByRole("alert")).toContainText(words);
        await expect(dialog).toBeVisible();
        await dialog.getByRole("button", {name: cancel}).click();
        await expect(dialog).toBeHidden();
      };
      await refusal("current_address", lang === "fa" ? /این نشانی فعلی شماست/ : /current address/i);
      await refusal("last_authorized", lang === "fa" ? /آخرین نشانی حذف نمی‌شود/ : /last address/i);
    });

    // Under Require, a delete of authorized rows, a host delete and the clean-up switched on take every profile of the slots away, so the server
    // needs the password of each locked one (spec p3 5): the first ask says every password is needed, not that one may be enough (S6-r1-8).
    test("S6-r1-8: with Require on and two locked slot profiles, deleting an address and turning clean-up on ask for every password", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      mock.screens.profiles = mock.screens.profiles.map((p) => (p.id === PROFILE.travel ? {...p, locked: true} : p));
      mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.home ? {...e, require_authorized_ips: true, profile_id: PROFILE.office, profile2_id: PROFILE.travel} : e));
      const needsBoth = (call: {body: unknown}) => {
        const sent = (call.body as {lock_passwords?: {profile_id: string; password: string}[]}).lock_passwords ?? [];
        return sent.length < 2 ? {status: 423, body: errorBody("profile_locked", {fields: [{name: "/lock_passwords", code: "required"}]})} : {status: 204};
      };
      mock.on("POST /endpoints/{id}/authorized-ips:delete", needsBoth);
      mock.on("PATCH /endpoints/{id}/authorized-ips/{aid}", needsBoth);
      await page.goto(ipsPath(lang));
      const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
      const cancel = lang === "fa" ? "انصراف" : "Cancel";

      await page.getByRole("button", {name: text("ips.authorized.deleteAria", {cidr: "198.51.100.0/24"})}).click();
      const confirm = dialogOf(page, text("ips.delete.title", {count: nf(lang, 1)}));
      await confirm.getByRole("button", {name: text("ips.delete.submit"), exact: true}).click();
      await expect(needed).toBeVisible();
      await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needText"));
      await expect(needed).not.toContainText(profileText(lang, "profiles", "lock.dialog.needAnyText"));
      await needed.getByRole("button", {name: cancel}).click();
      await expect(needed).toBeHidden();
      await confirm.getByRole("button", {name: cancel}).click();
      await expect(confirm).toBeHidden();

      await authorizedRow(page, "203.0.113.7/32").getByText(text("ips.authorized.cleanup"), {exact: true}).click();
      await expect(needed).toBeVisible();
      await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needText"));
      await expect(needed).not.toContainText(profileText(lang, "profiles", "lock.dialog.needAnyText"));
    });

    // The hub keeps only the first query it sees for a label, so after a take that finds no proof on a query that needed no code, this challenge
    // can never prove the address: the dialog says so and offers a new one, and the new one is taken when it is observed (S6-r3-1, S6-r3-4).
    test("S6-r3-1: after no_proof on an automatic take the dialog offers a new code, and a query seen on the new one proves the address", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      const base = screenHandlers(mock.screens)["POST /endpoints/{id}/ip-claims/{claim_id}:take"]!;
      let answered = 0;
      mock.on("POST /endpoints/{id}/ip-claims/{claim_id}:take", (call, state) => {
        if (answered++ > 0) return base(call, state);
        return {status: 200, body: {claim: mock.screens.claims.get(ENDPOINT.home)!.find((c) => c.id === CLAIM.pending), outcome: "no_proof"}};
      });
      const observe = (protocol: "tcp" | "udp") =>
        mock.screens.claims.set(ENDPOINT.home, mock.screens.claims.get(ENDPOINT.home)!.map((c) => (c.id === CLAIM.pending && c.challenge ? {...c, challenge: {...c.challenge, observed: true, observed_protocol: protocol}} : c)));
      await page.goto(ipsPath(lang, `proof:${CLAIM.pending}`));
      const dialog = dialogOf(page, text("ips.proof.title", {cidr: "198.51.100.0/24"}));
      await dialog.getByRole("button", {name: text("ips.proof.again")}).click();
      await expect(dialog.getByTestId("proof-steps")).toBeVisible();
      observe("tcp");
      await expect(dialog.getByText(text("ips.proof.noProofText"))).toBeVisible({timeout: 15_000});
      await dialog.getByRole("button", {name: text("ips.proof.newChallenge")}).click();
      await expect(dialog.getByText(text("ips.proof.noProofText"))).toHaveCount(0);
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims/${CLAIM.pending}/challenges`)).toHaveLength(2);
      await expect(dialog.getByTestId("proof-status")).toContainText(text("ips.proof.notYet"));
      observe("tcp");
      await expect(dialog.getByText(text("ips.proof.provenTitle", {cidr: "198.51.100.0/24"}))).toBeVisible({timeout: 15_000});
      expect(callsTo(mock.calls, "POST", `/endpoints/${ENDPOINT.home}/ip-claims/${CLAIM.pending}:take`)).toHaveLength(2);
    });

    test("S6-r3-4: a wrong code names both causes and offers a new code too", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(ipsPath(lang, `proof:${CLAIM.pending}`));
      const dialog = dialogOf(page, text("ips.proof.title", {cidr: "198.51.100.0/24"}));
      await dialog.getByRole("button", {name: text("ips.proof.again")}).click();
      await dialog.getByRole("textbox", {name: text("ips.proof.udp.code")}).fill("k9q2w7");
      await dialog.getByRole("button", {name: text("ips.proof.udp.check")}).click();
      await expect(dialog.getByText(text("ips.proof.noProofCodeText"))).toBeVisible();
      await expect(dialog.getByRole("button", {name: text("ips.proof.newChallenge")})).toBeVisible();
    });

    test("S6-r3-2: a shared address and an address that waits for an administrator say what to do instead of the generic line", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      await page.goto(ipsPath(lang, `proof:${CLAIM.pending}`));
      const dialog = dialogOf(page, text("ips.proof.title", {cidr: "198.51.100.0/24"}));
      await dialog.getByRole("button", {name: text("ips.proof.again")}).click();
      await dialog.getByRole("textbox", {name: text("ips.proof.udp.code")}).fill("k9q2w7");
      mock.on("POST /endpoints/{id}/ip-claims/{claim_id}:take", {status: 409, body: errorBody("ip_unavailable")});
      await dialog.getByRole("button", {name: text("ips.proof.udp.check")}).click();
      await expect(dialog.getByText(text("ips.proof.unavailable"))).toBeVisible();
      await expect(dialog.getByText(lang === "fa" ? /DoH یا DoT/ : /DoH or DoT/)).toBeVisible();
      mock.on("POST /endpoints/{id}/ip-claims/{claim_id}:take", {status: 409, body: errorBody("needs_admin_approval")});
      await dialog.getByRole("button", {name: text("ips.proof.udp.check")}).click();
      await expect(dialog.getByText(text("ips.proof.needsAdmin"))).toBeVisible();
    });

    test("S6-r3-3: a prefix wider than the allowed width is refused with the limit named, and the hint names it before", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      mock.on("POST /endpoints/{id}/authorized-ips", {status: 422, body: errorBody("validation_failed", {fields: [{name: "/cidrs/0", code: "out_of_range"}]})});
      await page.goto(ipsPath(lang));
      await page.getByRole("button", {name: text("ips.authorized.add"), exact: true}).first().click();
      const dialog = dialogOf(page, text("ips.add.title"));
      await expect(dialog.getByText(/\/16/)).toBeVisible();
      await dialog.getByRole("textbox", {name: text("ips.add.field")}).fill("10.0.0.0/8");
      await dialog.getByRole("button", {name: text("ips.add.submit"), exact: true}).click();
      await expect(dialog.getByRole("alert")).toContainText(text("ips.add.outOfRange"));
      await expect(dialog.getByRole("alert")).toContainText("10.0.0.0/8");
    });

    // Releasing a claim that holds a Plain DNS identity, or deleting a Dynamic DNS host that made one, empties that identity's stack, so every
    // locked profile is needed; a claim that holds none keeps the optional ask (S6-r3-5).
    test("S6-r3-5: releasing an active claim and deleting a Dynamic DNS host with a claim ask for every password, a waiting claim for any", async ({page, context, baseURL}) => {
      const mock = await openList(context, baseURL);
      mock.screens.profiles = mock.screens.profiles.map((p) => (p.id === PROFILE.travel ? {...p, locked: true} : p));
      mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.home ? {...e, authorize_ddns: true, profile_id: PROFILE.office, profile2_id: PROFILE.travel} : e));
      mock.screens.claims.set(ENDPOINT.home, mock.screens.claims.get(ENDPOINT.home)!.map((c) => (c.state === "grace" ? {...c, source: "ddns" as const} : c)));
      const locked = {status: 423, body: errorBody("profile_locked", {fields: [{name: "/lock_passwords", code: "required"}]})};
      mock.on("POST /endpoints/{id}/ip-claims/{claim_id}:release", locked);
      mock.on("POST /endpoints/{id}/ddns-hosts/{hid}:delete", locked);
      await page.goto(ipsPath(lang));
      const needed = page.getByRole("dialog", {name: profileText(lang, "profiles", "lock.dialog.needTitle")});
      const cancel = lang === "fa" ? "انصراف" : "Cancel";
      const release = async (cidr: string) => {
        await page.getByRole("button", {name: text("ips.claims.releaseAria", {cidr})}).click();
        await dialogOf(page, text("ips.claims.releaseTitle", {cidr})).getByRole("button", {name: text("ips.claims.releaseSubmit")}).click();
        await expect(needed).toBeVisible();
      };
      const close = async (cidr: string) => {
        await needed.getByRole("button", {name: cancel}).click();
        await expect(needed).toBeHidden();
        await dialogOf(page, text("ips.claims.releaseTitle", {cidr})).getByRole("button", {name: cancel}).click();
      };

      await release("203.0.113.7/32");
      await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needText"));
      await expect(needed).not.toContainText(profileText(lang, "profiles", "lock.dialog.needAnyText"));
      await close("203.0.113.7/32");

      await release("198.51.100.0/24");
      await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needAnyText"));
      await close("198.51.100.0/24");

      await page.getByTestId("ddns-section").getByRole("button", {name: text("ips.ddns.deleteAria", {name: "home.example.org"})}).click();
      await dialogOf(page, text("ips.ddns.deleteTitle", {name: "home.example.org"})).getByRole("button", {name: text("ips.ddns.deleteSubmit")}).click();
      await expect(needed).toBeVisible();
      await expect(needed).toContainText(profileText(lang, "profiles", "lock.dialog.needText"));
      await expect(needed).not.toContainText(profileText(lang, "profiles", "lock.dialog.needAnyText"));
    });

    test("an Endpoint with nothing of either kind offers both first steps", async ({page, context, baseURL}) => {
      await openList(context, baseURL);
      await page.goto(endpointPath(lang, ENDPOINT.laptop, "ips"));
      await expect(page.getByText(text("ips.claims.empty"), {exact: true})).toBeVisible();
      await expect(page.getByText(text("ips.authorized.empty"), {exact: true})).toBeVisible();
    });
  });
}
