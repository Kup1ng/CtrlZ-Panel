import type {Page} from "@playwright/test";
import {notificationFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {flip} from "./endpoint-screens-support.ts";
import {ENDPOINT, deviceDialogPath, endpointPath, endpointsText} from "./endpoints-support.ts";
import {openWith, openBell, shell, type Handlers as NoticeHandlers} from "./notices-support.ts";
import {LANGS, openProfiles, type Handlers} from "./profiles-support.ts";

// Plan T-557 (D55): what the pages say about free DNS, by the switch the browser reads from GET /public/free-dns. The Endpoint page has the
// add-address reminder (closed until the address changes) and the IPv6 pair warning; the delete dialog, the Legacy DNS texts and the notice of a
// suspended address say what an unidentified device gets. When the route cannot be read, no text that depends on the switch is drawn. The
// incomplete state of the verify wizard is in verify.spec.ts, which has the server with a verify origin.
//
// Home router (the Endpoint of the fixture) holds four claims: 203.0.113.7/32 active, 198.51.100.0/24 waiting for proof, 192.0.2.0/28 in grace
// (unproven) and 192.0.2.64/26 suspended. The default browser of the mock is on IPv6, so a case about the reminder gives it an IPv4 address.

test.use({viewport: {width: 1280, height: 900}});

const PAIR = {primary_dns_ip: "203.0.113.53", fallback_dns_ip: "203.0.113.54"};
const session = (ip: string) => ({
  id: "00000000-0000-4000-8000-0000000000e1",
  current: true,
  created_at: "2026-11-10T09:00:00Z",
  last_seen_at: "2026-11-25T09:00:00Z",
  auth_method: "password",
  ip,
  user_agent: "test",
});
const around = (ip: string, free: unknown = {enabled: true, ...PAIR}): Handlers => ({
  "GET /account/sessions": {body: {sessions: [session(ip)]}},
  "GET /public/free-dns": {body: free},
});

/** One mock for a whole case: the address and the switch are read at each request, so a case changes them between visits without removing the routes (the guard's own are on the context). */
function changing(initial: {ip: string; free: unknown}) {
  const now = {...initial};
  const handlers: Handlers = {
    "GET /account/sessions": () => ({body: {sessions: [session(now.ip)]}}),
    "GET /public/free-dns": () => ({body: now.free}),
  };
  return {now, handlers};
}

for (const {lang, dir} of LANGS) {
  const text = (path: string, values: Record<string, string | number> = {}) => endpointsText(lang, path, values);
  const remind = (page: Page) => page.getByTestId("free-dns-remind");
  const home = endpointPath(lang, ENDPOINT.home, "clients");
  const framed = (page: Page, name: string) => page.getByRole("navigation", {name: text("frame.tabsLabel", {name})});

  test.describe(`${lang} (${dir})`, () => {
    test("T-557: an unclaimed IPv4 address gets the reminder with its address and an Add button that opens the claim dialog", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {handlers: around("203.0.113.200")});
      await page.goto(home);
      await expect(remind(page)).toBeVisible();
      await expect(remind(page)).toContainText(text("freeDns.remind.title"));
      await expect(remind(page).locator("bdi")).toHaveText("203.0.113.200");
      // V1-r1-2: the address is the one of the session's sign-in, which nothing refreshes, so the text says so and does not claim to see the browser now.
      await expect(remind(page)).toContainText(lang === "en" ? "last signed in" : "آخرین بار");
      await remind(page).getByRole("button", {name: text("freeDns.remind.add")}).click();
      await expect(page).toHaveURL(/\/ips\?ipDialog=claim$/);
      await expect(page.getByRole("dialog", {name: text("ips.claim.title")})).toBeVisible();
    });

    test("T-557: an address that an active or a grace claim holds gets no reminder, and one that only a waiting or a suspended claim holds does", async ({page, context, baseURL}) => {
      const seen = changing({ip: "", free: {enabled: true, ...PAIR}});
      await openProfiles(context, baseURL, {handlers: seen.handlers});
      for (const [ip, shown] of [["203.0.113.7", false], ["192.0.2.5", false], ["198.51.100.9", true], ["192.0.2.100", true]] as const) {
        seen.now.ip = ip;
        await page.goto(home);
        await expect(framed(page, "Home router")).toBeVisible();
        if (shown) await expect(remind(page), ip).toBeVisible();
        else await expect(remind(page), ip).toHaveCount(0);
      }
    });

    test("T-557: closing the reminder keeps it closed for that address, also after a reload, and it returns when the address changes", async ({page, context, baseURL}) => {
      let ip = "203.0.113.200";
      await openProfiles(context, baseURL, {handlers: {...around(ip), "GET /account/sessions": () => ({body: {sessions: [session(ip)]}})}});
      await page.goto(home);
      await remind(page).getByRole("button", {name: lang === "fa" ? "بستن" : "Close"}).click();
      await expect(remind(page)).toHaveCount(0);
      await page.reload();
      await expect(framed(page, "Home router")).toBeVisible();
      await expect(remind(page)).toHaveCount(0);
      ip = "203.0.113.201";
      await page.reload();
      await expect(remind(page)).toBeVisible();
      await expect(remind(page).locator("bdi")).toHaveText("203.0.113.201");
    });

    test("T-557: no reminder with the switch off, for an IPv6 browser, or for an Endpoint with Plain DNS off", async ({page, context, baseURL}) => {
      const seen = changing({ip: "203.0.113.200", free: {enabled: false, ...PAIR}});
      const mock = await openProfiles(context, baseURL, {handlers: seen.handlers});
      await page.goto(home);
      await expect(framed(page, "Home router")).toBeVisible();
      await expect(remind(page)).toHaveCount(0);

      seen.now.free = {enabled: true, ...PAIR};
      seen.now.ip = "2001:db8::77";
      await page.goto(home);
      await expect(framed(page, "Home router")).toBeVisible();
      await expect(remind(page)).toHaveCount(0);

      seen.now.ip = "203.0.113.200";
      mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.laptop ? {...e, legacy_dns: false} : e));
      await page.goto(endpointPath(lang, ENDPOINT.laptop, "clients"));
      await expect(framed(page, "Laptop")).toBeVisible();
      await expect(remind(page)).toHaveCount(0);
    });

    test("T-557: an IPv6 pair warns that Plain DNS is not matched to the Endpoint, by the switch, and an IPv4 pair does not", async ({page, context, baseURL}) => {
      const v6 = {primary_dns_ip: "2001:db8::53", fallback_dns_ip: "2001:db8::54"};
      const seen = changing({ip: "2001:db8::77", free: {enabled: true, ...v6}});
      await openProfiles(context, baseURL, {handlers: seen.handlers});
      await page.goto(home);
      const warning = page.getByTestId("free-dns-ipv6");
      await expect(warning).toContainText(text("freeDns.ipv6.on"));
      await expect(warning).not.toContainText(text("freeDns.ipv6.off"));

      seen.now.free = {enabled: false, ...v6};
      await page.goto(home);
      await expect(page.getByTestId("free-dns-ipv6")).toContainText(text("freeDns.ipv6.off"));

      seen.now.free = {enabled: true, ...PAIR};
      await page.goto(home);
      await expect(framed(page, "Home router")).toBeVisible();
      await expect(page.getByTestId("free-dns-ipv6")).toHaveCount(0);
    });

    test.describe("the route cannot be read", () => {
      test.use({allowConsole: [/status of (429|5\d\d)/]});

      test("T-557: with no good answer (429, then 503) no text that depends on the switch is drawn, and the Add and Prove buttons stay", async ({page, context, baseURL}) => {
        let status = 429;
        await openProfiles(context, baseURL, {
          handlers: {...around("203.0.113.200"), "GET /public/free-dns": () => ({status, body: {code: status === 429 ? "rate_limited" : "service_unavailable"}})},
        });
        for (status of [429, 503]) {
          await page.goto(endpointPath(lang, ENDPOINT.home, "ips"));
          await expect(page.getByTestId("claims-section")).toBeVisible();
          await expect(page.getByTestId("free-dns-remind")).toHaveCount(0);
          await expect(page.getByTestId("free-dns-ipv6")).toHaveCount(0);
          // The buttons of the page do not wait for the switch.
          await expect(page.getByRole("button", {name: text("ips.claims.add"), exact: true}).first()).toBeVisible();
          await expect(page.getByRole("button", {name: text("ips.claims.proveAria", {cidr: "198.51.100.0/24"})})).toBeVisible();
          // The delete dialog draws no sentence about it.
          await page.goto(deviceDialogPath(lang, "delete", ENDPOINT.home));
          await expect(page.getByRole("dialog")).toContainText(text("dialogs.delete.text", {name: "Home router"}));
          await expect(page.getByTestId("delete-free-dns")).toHaveCount(0);
        }
      });

      // V1-r1-4: the page-level counterpart of the unit test of readFreeDns. The route answers once, then fails at the next poll (the page re-reads every
      // minute), and the notices of the Endpoint page keep what the good answer said.
      test("T-557: with a good answer from before, a 503 at the next poll keeps the reminder and the IPv6 warning", async ({page, context, baseURL}) => {
        let asked = 0;
        let down = false;
        const v6 = {primary_dns_ip: "2001:db8::53", fallback_dns_ip: "2001:db8::54"};
        await page.clock.install();
        await openProfiles(context, baseURL, {
          handlers: {
            ...around("203.0.113.200"),
            "GET /public/free-dns": () => {
              asked++;
              return down ? {status: 503, body: {code: "service_unavailable"}} : {body: {enabled: true, ...v6}};
            },
          },
        });
        await page.goto(home);
        await expect(remind(page)).toBeVisible();
        await expect(page.getByTestId("free-dns-ipv6")).toContainText(text("freeDns.ipv6.on"));
        down = true;
        const before = asked;
        await page.clock.fastForward(70_000);
        await expect.poll(() => asked).toBeGreaterThan(before);
        await expect(remind(page)).toBeVisible();
        await expect(page.getByTestId("free-dns-ipv6")).toContainText(text("freeDns.ipv6.on"));
      });

      test("T-557: with a good answer from before, a 429 keeps the text of that answer", async ({page, context, baseURL}) => {
        let limited = false;
        await page.clock.install();
        await openProfiles(context, baseURL, {
          handlers: {...around("2001:db8::77"), "GET /public/free-dns": () => (limited ? {status: 429, body: {code: "rate_limited"}} : {body: {enabled: true, ...PAIR}})},
        });
        await page.goto(deviceDialogPath(lang, "edit", ENDPOINT.laptop));
        const dialog = page.getByRole("dialog", {name: text("dialogs.edit.title", {name: "Laptop"})});
        await dialog.getByRole("button", {name: text("dialogs.fields.advanced")}).click();
        await flip(dialog, text("dialogs.fields.legacy"), false);
        await expect(dialog.getByTestId("legacy-off-free-dns")).toContainText(text("freeDns.legacyOff.on"));
        // The answer is stale after 30 seconds, so a note that mounts then asks again, is refused, and says what the earlier answer said.
        limited = true;
        await page.clock.fastForward(40_000);
        await flip(dialog, text("dialogs.fields.legacy"), true);
        await flip(dialog, text("dialogs.fields.legacy"), false);
        await expect(dialog.getByTestId("legacy-off-free-dns")).toContainText(text("freeDns.legacyOff.on"));
      });
    });

    test("T-233, T-557: the delete dialog says what a Plain DNS device gets, by the switch, and nothing for an Endpoint with Plain DNS off", async ({page, context, baseURL}) => {
      const seen = changing({ip: "2001:db8::77", free: {enabled: true}});
      const mock = await openProfiles(context, baseURL, {handlers: seen.handlers});
      await page.goto(deviceDialogPath(lang, "delete", ENDPOINT.home));
      await expect(page.getByTestId("delete-free-dns")).toHaveText(text("dialogs.delete.freeDnsOn"));

      seen.now.free = {enabled: false};
      await page.goto(deviceDialogPath(lang, "delete", ENDPOINT.home));
      await expect(page.getByTestId("delete-free-dns")).toHaveText(text("dialogs.delete.freeDnsOff"));

      seen.now.free = {enabled: true};
      mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.laptop ? {...e, legacy_dns: false} : e));
      await page.goto(deviceDialogPath(lang, "delete", ENDPOINT.laptop));
      await expect(page.getByRole("dialog")).toContainText(text("dialogs.delete.text", {name: "Laptop"}));
      await expect(page.getByTestId("delete-free-dns")).toHaveCount(0);
    });

    test("T-223, T-557: turning Plain DNS off in the edit dialog, and the Addresses page of an Endpoint that has it off, say what its devices get", async ({page, context, baseURL}) => {
      const seen = changing({ip: "2001:db8::77", free: {enabled: true}});
      const off = await openProfiles(context, baseURL, {handlers: seen.handlers});
      await page.goto(deviceDialogPath(lang, "edit", ENDPOINT.laptop));
      const dialog = page.getByRole("dialog", {name: text("dialogs.edit.title", {name: "Laptop"})});
      await dialog.getByRole("button", {name: text("dialogs.fields.advanced")}).click();
      await expect(dialog.getByTestId("legacy-off-free-dns")).toHaveCount(0);
      await flip(dialog, text("dialogs.fields.legacy"), false);
      await expect(dialog.getByTestId("legacy-off-free-dns")).toHaveText(text("freeDns.legacyOff.on"));

      seen.now.free = {enabled: false};
      off.screens.endpoints = off.screens.endpoints.map((e) => (e.id === ENDPOINT.home ? {...e, legacy_dns: false} : e));
      await page.goto(endpointPath(lang, ENDPOINT.home, "ips"));
      await expect(page.getByTestId("claims-section").getByTestId("legacy-off-free-dns")).toHaveText(text("freeDns.legacyOff.off"));
    });

    test("T-557: the notice of a suspended address says what its queries get now, by the switch", async ({page, context, baseURL}) => {
      let free: unknown = {enabled: true};
      const handlers: NoticeHandlers = {"GET /public/free-dns": () => ({body: free})};
      await openWith(context, baseURL, {notifications: [notificationFixture({kind: "ip_suspended", severity: "warning"})], handlers});
      const open = async () => {
        await page.goto(`/${lang}/preferences/account`);
        await openBell(page);
        await page.getByRole("dialog").getByRole("button", {name: new RegExp(shell(lang, "bell.kinds.ip_suspended.title"))}).click();
      };
      await open();
      await expect(page.getByRole("dialog")).toContainText(shell(lang, "bell.kinds.ip_suspended.text"));
      await expect(page.getByTestId("suspended-free-dns")).toHaveText(shell(lang, "bell.freeDns.suspendedOn"));

      free = {enabled: false};
      await open();
      await expect(page.getByTestId("suspended-free-dns")).toHaveText(shell(lang, "bell.freeDns.suspendedOff"));
    });
  });
}
