import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";

import {request as playwrightRequest, type BrowserContext, type Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {apiText, tokensPath} from "./s8-support.ts";
import {setupText} from "./setup-support.ts";

// Stack mode (spec p3 11.6, 11.7; spec 17.1, 17.7), package S8 against the real API behind Caddy at https://panel.localhost: an API token is made in the
// page, shown once, used as a bearer against the public API (a read token reads and a write is refused), and ends with Delete; a share link made for an
// Endpoint opens in a fresh context with no cookie, which reads the Endpoint's setup and nothing else of the account.
//
// WRITTEN, NOT RUN (owner decision D69: no stack on the build machine). It follows the pattern of account.stack.spec.ts and skips itself unless
// E2E_MODE=stack. Every test leaves the seeded user as it found it: a token or an Endpoint that a test made is removed in a `finally` block, through
// the API and with a live reauth, so a failed assertion in the middle does not leave one behind for the next file.
//
//   E2E_MODE=stack E2E_SEED_FILE=<private dir>/seed.json pnpm exec playwright test e2e/s8.stack.spec.ts

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded user");

// The real API answers 401 for the anonymous probe of a login page and for a token that was deleted, 403 for a write with a read token, and 409 when the
// deployment has no DNS zone yet. Chrome logs each as "Failed to load resource": only these statuses are allowed.
test.beforeEach(({guard}) => guard.allowConsole(/status of (401|403|409)/));

type Seed = {user: {phone: string; password: string}};
const seed = ((): Seed => {
  const file = process.env.E2E_SEED_FILE;
  if (file) return JSON.parse(readFileSync(file, "utf8")) as Seed;
  return {user: {phone: process.env.E2E_PHONE ?? "", password: process.env.E2E_PASSWORD ?? ""}};
})();

const TOKEN_NAME = "S8 stack token";
const ENDPOINT_NAME = "S8 stack endpoint";
const dialog = (page: Page) => page.getByRole("dialog");

async function signIn(page: Page, lang: "fa" | "en") {
  await page.goto(`/${lang}/login`);
  const submit = page.locator('form button[type="submit"]');
  await expect(submit.first()).toBeEnabled();
  await page.locator('input[name="phone"]').fill(seed.user.phone);
  await page.locator('input[name="password"]').fill(seed.user.password);
  await submit.first().click();
  await page.waitForURL(`**/${lang}/profiles`);
}

/** A fresh session with a live reauth, through the API: what a cleanup needs, whatever state the page was left in. */
async function reauthed(context: BrowserContext) {
  await context.clearCookies();
  const request = context.request;
  expect((await request.post("/api/v1/auth/login/password", {data: {phone: seed.user.phone, password: seed.user.password}})).status(), "sign in for the cleanup").toBe(200);
  expect((await request.post("/api/v1/auth/reauth", {data: {password: seed.user.password}})).status(), "reauth").toBe(204);
  return request;
}

async function removeTokens(context: BrowserContext) {
  const request = await reauthed(context);
  const list = (await (await request.get("/api/v1/api-tokens")).json()) as {tokens: {id: string; name: string}[]};
  for (const token of list.tokens.filter((t) => t.name === TOKEN_NAME)) expect((await request.delete(`/api/v1/api-tokens/${token.id}`)).status(), "delete token").toBe(204);
}

async function removeEndpoints(context: BrowserContext) {
  const request = await reauthed(context);
  const list = (await (await request.get("/api/v1/endpoints?limit=200")).json()) as {items: {id: string; name: string}[]};
  for (const endpoint of list.items.filter((e) => e.name === ENDPOINT_NAME)) expect((await request.post(`/api/v1/endpoints/${endpoint.id}:delete`, {data: {}})).status(), "delete endpoint").toBe(204);
}

test.describe("API tokens and share links against the real API", () => {
  const lang = "en";
  const A = (path: string, values?: Record<string, string | number>) => apiText(lang, path, values);

  test("an API token: made once, used as a bearer, a write refused for a read token, and dead after Delete", async ({page, context, baseURL}) => {
    test.setTimeout(120_000);
    try {
      await signIn(page, lang);
      await page.goto(tokensPath(lang));
      await page.getByRole("button", {name: A("create.open")}).first().click();
      await dialog(page).getByRole("textbox", {name: A("dialog.name")}).fill(TOKEN_NAME);
      await dialog(page).getByRole("button", {name: A("create.submit")}).click();
      // A fresh sign-in is inside the reauth window, so the dialog may not appear; when it does, the password is what it asks for.
      const value = page.getByTestId("token-value");
      const password = page.locator('input[name="password"]');
      await expect(value.or(password)).toBeVisible();
      if (await password.isVisible()) {
        await password.fill(seed.user.password);
        await page.locator('[role="dialog"] button[type="submit"]').last().click();
      }
      await expect(value).toBeVisible();
      const secret = /ctz_[A-Za-z0-9_-]{64}/.exec(await value.innerText())?.[0];
      expect(secret, "the value is ctz_ and 64 characters (spec p3 6.2)").toBeDefined();
      await page.getByTestId("token-value-done").click();
      await expect(page.locator("body")).not.toContainText(secret!);

      // The public API, with no cookie: the bearer is the only credential.
      const api = await playwrightRequest.newContext({baseURL, ignoreHTTPSErrors: true, extraHTTPHeaders: {Authorization: `Bearer ${secret}`}});
      try {
        expect((await api.get("/api/v1/account/limits")).status(), "a read operation with a read token").toBe(200);
        const write = await api.post("/api/v1/endpoint-groups", {data: {name: "S8 refused"}});
        expect(write.status(), "a write operation with a read token").toBe(403);
        expect(((await write.json()) as {code: string}).code).toBe("token_read_only");
        const none = await api.get("/api/v1/me");
        expect(none.status(), "an operation that takes no token").toBe(403);
        expect(((await none.json()) as {code: string}).code).toBe("token_not_allowed");

        await page.getByRole("button", {name: A("row.delete", {name: TOKEN_NAME})}).click();
        await page.getByRole("alertdialog").getByRole("button", {name: A("delete.confirm")}).click();
        await expect(page.locator("li[data-token]").filter({hasText: TOKEN_NAME})).toHaveCount(0);
        const dead = await api.get("/api/v1/account/limits");
        expect(dead.status(), "a deleted token").toBe(401);
        expect(((await dead.json()) as {code: string}).code).toBe("token_invalid");
      } finally {
        await api.dispose();
      }
    } finally {
      await removeTokens(context);
    }
  });

  test("a share link opens in a fresh context with no cookie and shows the Endpoint's setup and nothing else", async ({page, context, baseURL, guard}) => {
    test.setTimeout(120_000);
    try {
      await signIn(page, lang);
      const request = context.request;
      const profiles = (await (await request.get("/api/v1/profiles")).json()) as {items: {id: string}[]};
      const created = await request.post("/api/v1/endpoints", {headers: {"Idempotency-Key": randomUUID()}, data: {type: "windows", names: [ENDPOINT_NAME], profile_id: profiles.items[0]!.id}});
      expect(created.status(), "make an Endpoint").toBe(201);
      const endpoint = (await created.json()) as {id: string};
      const share = await request.post(`/api/v1/endpoints/${endpoint.id}/share-links`, {data: {}});
      test.skip(share.status() === 409, "the deployment has no DNS zone yet (setup_unavailable): the share link cannot be made");
      expect(share.status(), "make a share link").toBe(201);
      const url = new URL(((await share.json()) as {url: string}).url);

      const visitor = await guard.newContext({baseURL, ignoreHTTPSErrors: true});
      const tab = await visitor.newPage();
      await tab.goto(`/${lang}${url.pathname}`);
      await expect(tab.getByRole("heading", {level: 1, name: ENDPOINT_NAME})).toBeVisible();
      await expect(tab.getByTestId("share-setup")).toBeVisible();
      // The link's value is in the address and in the one POST body, and the visitor has no cookie and asks for nothing of the account.
      expect(await visitor.cookies()).toEqual([]);
      const asked: string[] = [];
      tab.on("request", (r) => asked.push(`${r.method()} ${new URL(r.url()).pathname}`));
      await tab.getByRole("radio", {name: setupText(lang, "resolvers.title")}).click();
      await expect(tab.getByTestId("resolver-sections")).toBeVisible();
      expect(asked.filter((a) => a.includes("/api/v1/") && !a.includes("/public/"))).toEqual([]);

      // The same link again is a second use (spec 7.1, 7.2); revoking it is the owner's, and the page then says the same as for any dead link.
      const links = (await (await request.get(`/api/v1/endpoints/${endpoint.id}/share-links`)).json()) as {links: {id: string; uses: number}[]};
      expect(links.links[0]!.uses, "one use for the open").toBe(1);
      expect((await request.delete(`/api/v1/endpoints/${endpoint.id}/share-links/${links.links[0]!.id}`)).status()).toBe(204);
      await tab.reload();
      await expect(tab.getByRole("heading", {name: setupText(lang, "share.notFoundTitle")})).toBeVisible();
    } finally {
      await removeEndpoints(context);
    }
  });
});
