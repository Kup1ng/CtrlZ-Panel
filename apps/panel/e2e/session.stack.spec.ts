import type {APIRequestContext, BrowserContext} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

// Stack mode (spec 17.1, 17.7): the real API behind Caddy, over https://panel.localhost, so
// the `__Host-` cookies exist and the refresh rule of AUTH 3.4 and 3.5 meets the server it
// was written for. First run through Caddy on the Compose stack: 2026-11-23, P1 web merge. ci-web.sh step 10f runs it (CTRLZ_WEB_STACK=1), after the seed of scripts/e2e-seed.mjs. It skips itself unless E2E_MODE=stack.
//
//   E2E_MODE=stack E2E_BASE_URL=https://panel.localhost E2E_PHONE=... E2E_PASSWORD=... \
//     pnpm exec playwright test   (with E2E_MODE=stack, which picks the stack project)
//
// The credentials come from the environment and are never printed.

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded user");

// The real API answers 401 where the mock of the same flow fulfils it quietly: the anonymous /me probe of a login page, a wrong password, a session
// cookie that is gone before a refresh. Chrome logs each as "Failed to load resource", and the first real run (merge item, step 10f) showed
// them. Only 401 is allowed: a 403, 5xx or network failure in these flows is still a failure.
test.beforeEach(({guard}) => guard.allowConsole(/status of 401/));

const SESSION = "__Host-ctrlz_session";
const REFRESH = "__Host-ctrlz_refresh";

async function login(request: APIRequestContext, rememberMe: boolean) {
  const response = await request.post("/api/v1/auth/login/password", {
    data: {phone: process.env.E2E_PHONE, password: process.env.E2E_PASSWORD, remember_me: rememberMe},
  });
  expect(response.status()).toBe(200);
  expect((await response.json()).status).toBe("authenticated");
}

const names = async (context: BrowserContext) => (await context.cookies()).map((c) => c.name);

test("Remember me: with only the refresh cookie left, one refresh rebuilds the session", async ({page, context}) => {
  await login(context.request, true);
  expect(await names(context)).toEqual(expect.arrayContaining([SESSION, REFRESH]));

  // A browser restart: the session cookie is a browser-session cookie and is gone.
  await context.clearCookies({name: SESSION});
  const refreshes: number[] = [];
  page.on("response", (r) => {
    if (r.url().endsWith("/api/v1/auth/refresh")) refreshes.push(r.status());
  });
  await page.goto("/en/profiles");
  await expect(page.locator(".shell-page")).toBeVisible();
  expect(refreshes).toEqual([204]);
  expect(await names(context)).toContain(SESSION);
});

test("no Remember me: the session cookie gone means the login page, with next", async ({page, context}) => {
  await login(context.request, false);
  expect(await names(context)).not.toContain(REFRESH);
  await context.clearCookies({name: SESSION});
  await page.goto("/en/profiles");
  await page.waitForURL("**/en/login?next=%2Fprofiles");
});

test("Log out clears both cookies and the other tab follows", async ({page, context}) => {
  await login(context.request, true);
  const other = await context.newPage();
  await other.goto("/en/profiles");
  await expect(other.locator(".shell-page")).toBeVisible();
  await page.goto("/en/profiles");
  await page.getByRole("row", {name: /Preferences/}).first().click();
  await page.getByRole("row", {name: /Log out/}).first().click();
  await page.getByRole("button", {name: "Log out", exact: true}).click();
  await page.waitForURL("**/en/login");
  await other.waitForURL("**/en/login");
  const left = await names(context);
  expect(left).not.toContain(SESSION);
  expect(left).not.toContain(REFRESH);
});

// wp4-r4-2 and wp4-r5-7: Back after logout must not show the account that left. Chrome evicts a page whose
// secure cookies changed, so this case passes in Chrome whether or not the pageshow handler works: it checks
// the outcome (the login page, no account data in the DOM) over the real cookies and proxy. The handler itself
// is covered by session.spec.ts (a synthetic pageshow in Chrome) and by the unit tests. The one browser that
// restores such a page, Safari, is not installable here (no `playwright install`, spec 17.1), so the real proof
// is a manual check by the owner on Safari, macOS or iOS: log in, open Account, log out, press Back.
test("back/forward: Back after logout lands on the login page and shows no account data", async ({page, context}) => {
  await login(context.request, true);
  await page.goto("/en/preferences/account");
  await expect(page.locator(".shell-page")).toBeVisible();
  // The Preferences group is open already on a page inside it, and a click on it would close it and take Log out away (found by the first
  // real run). On /profiles, as in the cross-tab case above, the group is closed, and one click opens it.
  const logout = page.getByRole("row", {name: /Log out/}).first();
  if (!(await logout.isVisible())) await page.getByRole("row", {name: /Preferences/}).first().click();
  await logout.click();
  await page.getByRole("button", {name: "Log out", exact: true}).click();
  await page.waitForURL("**/en/login");

  await page.goBack();
  await page.waitForURL("**/en/login**");
  await expect(page.locator(".shell-page")).toHaveCount(0);
  // The masked phone is the account's own datum on that page: its last digits must not be in the document.
  const lastDigits = (process.env.E2E_PHONE ?? "").slice(-4);
  if (lastDigits) expect(await page.locator("body").innerText()).not.toContain(lastDigits);
});
