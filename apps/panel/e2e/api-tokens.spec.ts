import type {Page} from "@playwright/test";
import type {ScreenState} from "@ctrlz/api-client/testing/screenMock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {err, fieldText} from "./account-support.ts";
import {LANGS, openProfiles} from "./profiles-support.ts";
import {REAUTH_PASSWORD, apiText, retryLabel, tokenRow, tokensPath} from "./s8-support.ts";

// The API tokens page (spec p3 6.4, 10; wireframe note "Preferences"; Plan T-315, T-320): the list with name, type, Allowed IPs, creation and last
// use, Create and Edit behind a live reauth, the value shown ONCE in a state-only dialog, Delete behind a confirmation, and the link to the API
// documentation. Mock mode: the routes of /api-tokens are answered by the stateful mock of the screens.

test.beforeEach(({guard}) => guard.allowConsole(/status of (401|403|422|429|500|503)/));

const VALUE = `ctz_${"Qx7".repeat(21)}Q`;
const reauthed = {"POST /auth/reauth": {status: 204}} as const;

for (const {lang, dir} of LANGS) {
  test.describe(`API tokens, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 900}});
    const A = (path: string, values?: Record<string, string | number>) => apiText(lang, path, values);
    const dialog = (page: Page) => page.getByRole("dialog");

    test("T-315: the list shows each token with its type, Allowed IPs, last use and a state in words", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(tokensPath(lang));
      await expect(page.getByRole("heading", {level: 1, name: A("title")})).toBeVisible();
      await expect(tokenRow(page, "CI")).toBeVisible();
      await expect(page.locator("li[data-token]")).toHaveCount(4);
      const ci = tokenRow(page, "CI");
      await expect(ci.getByTestId("token-kind")).toContainText(A("kind.read"));
      await expect(ci.getByTestId("token-allowed")).toContainText("203.0.113.0/24");
      await expect(ci.getByTestId("token-state")).toContainText(A("state.live"));
      await expect(ci.getByTestId("token-last-use")).not.toContainText(A("row.never"));
      // The day a token stops working is in the row (S8-r3-2): the fixture's 2027-11-01 is year 2027, and 1406 in the Persian calendar.
      await expect(ci.getByTestId("token-expires")).toContainText(A("row.expires"));
      await expect(ci.getByTestId("token-expires")).toContainText(lang === "fa" ? "۱۴۰۶" : "2027");
      const automation = tokenRow(page, "Automation");
      await expect(automation.getByTestId("token-kind")).toContainText(A("kind.write"));
      await expect(automation.getByTestId("token-allowed")).toContainText(A("row.anyAddress"));
      await expect(automation.getByTestId("token-last-use")).toContainText(A("row.never"));
      // A token past its year and one that a credential change ended are marked with a word, not only a colour.
      await expect(tokenRow(page, "Old").getByTestId("token-state")).toContainText(A("state.expired"));
      await expect(tokenRow(page, "Ended by a password change").getByTestId("token-state")).toContainText(A("state.ended"));
      // The list holds the prefix of a token and never a value.
      await expect(page.locator("body")).not.toContainText("ctz_AAAA");
      await expect(ci).toContainText("aB3dE9");
      await expect(page.getByTestId("token-count")).toBeVisible();
    });

    test("T-315: every control names its token, and the page links to the API documentation", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL);
      await page.goto(tokensPath(lang));
      for (const key of ["copy", "edit", "delete"]) await expect(page.getByRole("button", {name: A(`row.${key}`, {name: "CI"})})).toBeVisible();
      await expect(page.getByRole("button", {name: A("create.open")})).toBeVisible();
      const link = page.getByRole("link", {name: A("docs")});
      await expect(link).toHaveAttribute("href", new RegExp(`/${lang}/docs/api$`));
      await link.click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/docs/api$`));
    });

    test("T-315: the first token needs an empty list to offer Create in the middle of the page", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      mock.screens.tokens = [];
      await page.goto(tokensPath(lang));
      await expect(page.getByText(A("tokens.emptyTitle"))).toBeVisible();
      await expect(page.getByText(A("tokens.empty"))).toBeVisible();
      await page.locator("button", {hasText: A("create.open")}).click();
      await expect(dialog(page).getByRole("heading", {name: A("create.title")})).toBeVisible();
    });

    test("T-315: Create sends name, type and Allowed IPs after the reauth, and shows the value once", async ({page, context, baseURL}) => {
      let first = true;
      const holder: {screens?: ScreenState} = {};
      const mock = await openProfiles(context, baseURL, {
        handlers: {
          ...reauthed,
          "POST /api-tokens": (call, state) => {
            if (first) {
              first = false;
              return err(403, "reauth_required");
            }
            void state;
            const body = call.body as {name: string; kind: "read" | "write"; allowed_ips?: string[]};
            const token = {id: "tk-new", name: body.name, kind: body.kind, token_prefix: "Qx7Qx7", allowed_ips: (body.allowed_ips ?? []).map((a) => (a.includes("/") ? a : `${a}/32`)), created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 365 * 86_400_000).toISOString(), ended: false};
            holder.screens!.tokens.unshift(token);
            return {status: 201, body: {token, value: VALUE}};
          },
        },
      });
      holder.screens = mock.screens;
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      const create = dialog(page);
      await create.getByRole("textbox", {name: A("dialog.name")}).fill("  Backup script ");
      await create.getByText(A("kind.write"), {exact: true}).click();
      await expect(create.getByRole("radio", {name: new RegExp(A("kind.write"))})).toBeChecked();
      await create.getByRole("textbox", {name: A("allowed.label")}).fill("198.51.100.0/24");
      await create.getByRole("button", {name: A("allowed.addAria")}).click();
      await create.getByRole("textbox", {name: A("allowed.label")}).fill("203.0.113.9");
      await page.keyboard.press("Enter");
      await expect(create.getByTestId("allowed-ips-field").getByRole("row")).toHaveCount(2);
      await create.getByRole("button", {name: A("create.submit")}).click();

      // The first answer is `reauth_required`: the reauth dialog opens, and the same create is repeated once after it.
      const reauth = page.getByRole("dialog").last();
      await reauth.locator('input[name="password"]').fill(REAUTH_PASSWORD);
      await reauth.locator("button[type=submit]").click();

      const value = page.getByTestId("token-value");
      await expect(value).toBeVisible();
      await expect(value).toContainText(VALUE);
      await expect(page.getByRole("heading", {name: A("value.title", {name: "Backup script"})})).toBeVisible();
      const creates = mock.calls.filter((c) => c.method === "POST" && c.path === "/api-tokens");
      expect(creates).toHaveLength(2);
      expect(creates[1]!.body).toEqual({name: "Backup script", kind: "write", allowed_ips: ["198.51.100.0/24", "203.0.113.9"]});

      // The value is in no address, and Escape and a click outside do not lose it: only the button ends the step.
      expect(page.url()).not.toContain("ctz_");
      await page.keyboard.press("Escape");
      await expect(value).toBeVisible();
      await page.getByTestId("token-value-done").click();
      await expect(value).toHaveCount(0);
      // The list has the new token by its prefix; the value is nowhere on the page, in the address, storage or history.
      await expect(page.locator("li[data-token]").first()).toContainText("Backup script");
      await expect(page.locator("body")).not.toContainText(VALUE);
      await expectNoSecretResidue(page, [VALUE, REAUTH_PASSWORD], "making an API token");
    });

    test("T-315: the type of a token is chosen once and the value step has no way to dismiss it but the button", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      const create = dialog(page);
      await expect(create.getByRole("radio", {name: new RegExp(A("kind.read"))})).toBeChecked();
      await expect(create.getByText(A("create.kindFixed"))).toBeVisible();
      await create.getByRole("textbox", {name: A("dialog.name")}).fill("One");
      await create.getByRole("button", {name: A("create.submit")}).click();
      await expect(page.getByTestId("token-value")).toBeVisible();
      await expect(dialog(page).getByRole("button", {name: lang === "fa" ? "بستن" : "Close"})).toHaveCount(1);
    });

    test("T-315: a missing name and a bad address are refused before any request, and the reasons are on the fields", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      const create = dialog(page);
      await create.getByRole("button", {name: A("create.submit")}).click();
      await expect(create.getByText(fieldText(lang, "required")).first()).toBeVisible();
      const field = create.getByRole("textbox", {name: A("allowed.label")});
      for (const [typed, problem] of [
        ["not an address", "invalid"],
        ["203.0.113.7/24", "hostBits"],
        ["2001:db8::1/32", "hostBits"],
      ] as const) {
        await field.fill(typed);
        await create.getByRole("button", {name: A("allowed.addAria")}).click();
        await expect(create.getByText(A(`allowed.problems.${problem}`, {max: 32}))).toBeVisible();
      }
      await field.fill("203.0.113.0/24");
      await create.getByRole("button", {name: A("allowed.addAria")}).click();
      await field.fill("203.0.113.0/24");
      await create.getByRole("button", {name: A("allowed.addAria")}).click();
      await expect(create.getByText(A("allowed.problems.duplicate"))).toBeVisible();
      expect(mock.count("POST /api-tokens")).toBe(0);
    });

    test("T-315: an entry that the server refuses is named by what the person typed", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {
        handlers: {...reauthed, "POST /api-tokens": err(422, "validation_failed", {fields: [{name: "/allowed_ips/1", code: "invalid"}]})},
      });
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      const create = dialog(page);
      await create.getByRole("textbox", {name: A("dialog.name")}).fill("Two entries");
      const field = create.getByRole("textbox", {name: A("allowed.label")});
      for (const entry of ["198.51.100.0/24", "203.0.113.0/24"]) {
        await field.fill(entry);
        await create.getByRole("button", {name: A("allowed.addAria")}).click();
      }
      await create.getByRole("button", {name: A("create.submit")}).click();
      await expect(create.getByText(A("allowed.problems.serverInvalid", {entry: "203.0.113.0/24"}))).toBeVisible();
      // Still the form, with what was typed.
      await expect(create.getByRole("textbox", {name: A("dialog.name")})).toHaveValue("Two entries");
    });

    test("T-315: the cap of tokens is a notice in the form, and nothing was made", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {limits: {max_api_tokens: 4}, handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      const create = dialog(page);
      await create.getByRole("textbox", {name: A("dialog.name")}).fill("Fifth");
      await create.getByRole("button", {name: A("create.submit")}).click();
      await expect(create.getByRole("alert").or(create.locator(".alert")).first()).toBeVisible();
      expect(mock.screens.tokens).toHaveLength(4);
      await expect(page.getByTestId("token-value")).toHaveCount(0);
    });

    // S8-r2-4: token-create is a daily budget (20 a day), so its Retry-After is tens of thousands of seconds, and the button says hours, not "71,234 s".
    test("T-315: a daily-limit 429 on Create says the wait in hours on the button, and makes no token", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {handlers: {...reauthed, "POST /api-tokens": err(429, "too_many_attempts", {retry_after_s: 71_234})}});
      const before = mock.screens.tokens.length;
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      const create = dialog(page);
      await create.getByRole("textbox", {name: A("dialog.name")}).fill("Twenty-first");
      await create.getByRole("button", {name: A("create.submit")}).click();
      const waiting = create.getByRole("button", {name: lang === "fa" ? /ساعت دیگر/ : /20 h/}).first();
      await expect(waiting).toBeDisabled();
      await expect(waiting).not.toContainText(/71|۷۱/);
      expect(mock.screens.tokens).toHaveLength(before);
    });

    test("T-315: giving up on the reauth leaves the form, and no token is made", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {handlers: {"POST /api-tokens": err(403, "reauth_required")}});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      await dialog(page).getByRole("textbox", {name: A("dialog.name")}).fill("Nope");
      await dialog(page).getByRole("button", {name: A("create.submit")}).click();
      await page.getByRole("dialog").last().getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
      await expect(page.getByRole("dialog").getByRole("textbox", {name: A("dialog.name")})).toHaveValue("Nope");
      expect(mock.count("POST /api-tokens")).toBe(1);
      expect(mock.screens.tokens).toHaveLength(4);
    });

    test("T-315: Edit changes the name and the addresses, sends only what changed, and shows the type as fixed", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("row.edit", {name: "Automation"})}).click();
      const edit = dialog(page);
      await expect(edit.getByRole("heading", {name: A("edit.title", {name: "Automation"})})).toBeVisible();
      await expect(edit.getByText(A("kind.write"))).toBeVisible();
      await expect(edit.getByRole("radio")).toHaveCount(0);
      await edit.getByRole("textbox", {name: A("dialog.name")}).fill("Automation 2");
      await edit.getByRole("button", {name: lang === "fa" ? "ذخیره" : "Save"}).click();
      await expect(tokenRow(page, "Automation 2")).toBeVisible();
      const patches = mock.calls.filter((c) => c.method === "PATCH" && c.path.startsWith("/api-tokens/"));
      expect(patches).toHaveLength(1);
      expect(patches[0]!.body).toEqual({name: "Automation 2"});
    });

    test("T-315: an edit that changes nothing sends nothing, and removing every address means any address", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("row.edit", {name: "CI"})}).click();
      await dialog(page).getByRole("button", {name: lang === "fa" ? "ذخیره" : "Save"}).click();
      await expect(dialog(page)).toHaveCount(0);
      expect(mock.count("PATCH /api-tokens/{tid}")).toBe(0);

      await page.getByRole("button", {name: A("row.edit", {name: "CI"})}).click();
      await dialog(page).locator('[slot="remove"]').first().click();
      await expect(dialog(page).getByText(A("allowed.anyAddress"))).toBeVisible();
      await dialog(page).getByRole("button", {name: lang === "fa" ? "ذخیره" : "Save"}).click();
      await expect(tokenRow(page, "CI").getByTestId("token-allowed")).toContainText(A("row.anyAddress"));
      expect(mock.calls.find((c) => c.method === "PATCH")?.body).toEqual({allowed_ips: []});
    });

    // S8-r1-2: an address that is typed and not added is part of the list when the form is sent, or it is refused on the field; it is never dropped.
    test("T-315: Create adds an address that was typed and not added, so the token is not left open to any address", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      const create = dialog(page);
      await create.getByRole("textbox", {name: A("dialog.name")}).fill("Typed only");
      await create.getByRole("textbox", {name: A("allowed.label")}).fill("203.0.113.0/24");
      await create.getByRole("button", {name: A("create.submit")}).click();
      await expect(page.getByTestId("token-value")).toBeVisible();
      const creates = mock.calls.filter((c) => c.method === "POST" && c.path === "/api-tokens");
      expect(creates).toHaveLength(1);
      expect(creates[0]!.body).toEqual({name: "Typed only", kind: "read", allowed_ips: ["203.0.113.0/24"]});
    });

    test("T-315: Create stops on an address that was typed and cannot be added, and sends nothing", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      const create = dialog(page);
      await create.getByRole("textbox", {name: A("dialog.name")}).fill("Bad entry");
      await create.getByRole("textbox", {name: A("allowed.label")}).fill("::1");
      await create.getByRole("button", {name: A("create.submit")}).click();
      await expect(create.getByText(A("allowed.problems.invalid"))).toBeVisible();
      await expect(page.getByTestId("token-value")).toHaveCount(0);
      expect(mock.count("POST /api-tokens")).toBe(0);
    });

    test("T-315: Edit sends an address that was typed and not added, and does not close as 'nothing changed'", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("row.edit", {name: "Automation"})}).click();
      const edit = dialog(page);
      await edit.getByRole("textbox", {name: A("allowed.label")}).fill("198.51.100.0/24");
      await edit.getByRole("button", {name: lang === "fa" ? "ذخیره" : "Save"}).click();
      await expect(tokenRow(page, "Automation").getByTestId("token-allowed")).toContainText("198.51.100.0/24");
      const patches = mock.calls.filter((c) => c.method === "PATCH" && c.path.startsWith("/api-tokens/"));
      expect(patches).toHaveLength(1);
      expect(patches[0]!.body).toEqual({allowed_ips: ["198.51.100.0/24"]});
    });

    // S8-r1-6: Cancel discards. The dialogs stay mounted for their exit animation, so a draft that survived would be shown again and compared with a refetched list.
    test("T-315: Edit shows the stored name and addresses again after Cancel", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL, {handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("row.edit", {name: "CI"})}).click();
      let edit = dialog(page);
      await edit.getByRole("textbox", {name: A("dialog.name")}).fill("Draft name");
      await edit.locator('[slot="remove"]').first().click();
      await edit.getByRole("textbox", {name: A("allowed.label")}).fill("198.51.100.0/24");
      await edit.getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
      await expect(dialog(page)).toHaveCount(0);

      await page.getByRole("button", {name: A("row.edit", {name: "CI"})}).click();
      edit = dialog(page);
      await expect(edit.getByRole("textbox", {name: A("dialog.name")})).toHaveValue("CI");
      await expect(edit.getByRole("textbox", {name: A("allowed.label")})).toHaveValue("");
      await expect(edit.getByTestId("allowed-ips-field")).toContainText("203.0.113.0/24");
      // Saving with no change sends nothing: the stored list is what the dialog holds.
      await edit.getByRole("button", {name: lang === "fa" ? "ذخیره" : "Save"}).click();
      await expect(dialog(page)).toHaveCount(0);
      expect(mock.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
    });

    test("T-315: Create starts empty again after Cancel", async ({page, context, baseURL}) => {
      await openProfiles(context, baseURL, {handlers: reauthed});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      let create = dialog(page);
      await create.getByRole("textbox", {name: A("dialog.name")}).fill("Draft");
      await create.getByText(A("kind.write"), {exact: true}).click();
      await create.getByRole("textbox", {name: A("allowed.label")}).fill("198.51.100.0/24");
      await create.getByRole("button", {name: A("allowed.addAria")}).click();
      await create.getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
      await expect(dialog(page)).toHaveCount(0);

      await page.getByRole("button", {name: A("create.open")}).first().click();
      create = dialog(page);
      await expect(create.getByRole("textbox", {name: A("dialog.name")})).toHaveValue("");
      await expect(create.getByRole("radio", {name: new RegExp(A("kind.read"))})).toBeChecked();
      await expect(create.getByText(A("allowed.anyAddress"))).toBeVisible();
    });

    test("T-315: Delete asks first, names what stops working, and removes only after the confirmation", async ({page, context, baseURL}) => {
      const mock = await openProfiles(context, baseURL);
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("row.delete", {name: "Old"})}).click();
      const confirm = page.getByRole("alertdialog");
      await expect(confirm.getByRole("heading", {name: A("delete.title", {name: "Old"})})).toBeVisible();
      await expect(confirm.getByText(A("delete.text", {name: "Old"}))).toBeVisible();
      await confirm.getByRole("button", {name: lang === "fa" ? "انصراف" : "Cancel"}).click();
      await expect(tokenRow(page, "Old")).toBeVisible();
      expect(mock.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);

      await page.getByRole("button", {name: A("row.delete", {name: "Old"})}).click();
      await page.getByRole("alertdialog").getByRole("button", {name: A("delete.confirm")}).click();
      await expect(tokenRow(page, "Old")).toHaveCount(0);
      expect(mock.calls.filter((c) => c.method === "DELETE").map((c) => c.path)).toEqual([expect.stringMatching(/^\/api-tokens\//)]);
      // Delete is a session action: no reauth was asked for it.
      expect(mock.count("POST /auth/reauth")).toBe(0);
    });

    test("T-315: Copy writes the six-character prefix, which names the token and is not the value", async ({page, context, baseURL}) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      await openProfiles(context, baseURL);
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("row.copy", {name: "CI"})}).click();
      await expect(page.getByText(lang === "fa" ? "کپی شد" : "Copied").first()).toBeVisible();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("aB3dE9");
    });

    test("T-315: a failed list is an error with Retry", async ({page, context, baseURL}) => {
      let calls = 0;
      await openProfiles(context, baseURL, {handlers: {"GET /api-tokens": () => (++calls === 1 ? err(500, "internal") : {body: {tokens: []}})}});
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: retryLabel(lang)}).click();
      await expect(page.getByText(A("tokens.emptyTitle"))).toBeVisible();
    });
  });
}
