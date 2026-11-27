import {createHmac} from "node:crypto";
import {readFileSync} from "node:fs";

import type {APIRequestContext, BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {adm, errText, nodesText} from "./admin-support.ts";

// Stack mode (spec 17.1, 17.7, 17.3 admin-auth): the real admin API behind Caddy at https://admin.localhost, so the
// `__Host-ctrlz_admin` cookie is the real one, the TOTP code is a computed one, and the session ends on the server.
//
// First run through Caddy on the Compose stack: 2026-11-23, P1 web merge. ci-web.sh step 10f runs it (CTRLZ_WEB_STACK=1), after the seed of scripts/e2e-seed.mjs. It needs deploy/compose/e2e-stack.yml and skips itself unless E2E_MODE=stack.
//
//   E2E_MODE=stack E2E_SEED_FILE=<private dir>/seed.json pnpm exec playwright test e2e/admin.stack.spec.ts
//
// A TOTP code is good for one 30 second step (AUTH 10.2: a spent step is `totp_step_reused`), so a test that signs in
// waits for a step nobody used yet (`nextStep`), and sets a timeout that has room for it. The seed spent the step it
// started in. The one write here is put back in a `finally` block, so the seeded stack is as it was found.

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded admin");

type Seed = {admin: {username: string; password: string; totp_secret: string}; user: {phone: string}};
const seed = ((): Seed => {
  const file = process.env.E2E_SEED_FILE;
  if (!file) throw new Error("E2E_SEED_FILE names the seed written by scripts/e2e-seed.mjs");
  return JSON.parse(readFileSync(file, "utf8")) as Seed;
})();

/** RFC 6238, SHA-1, 6 digits, 30 seconds: what the authenticator app does. */
function totp(secretBase32: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secretBase32.replace(/=+$/, "").replace(/\s/g, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0xf;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

let lastStep = Math.floor(Date.now() / 30_000);

/** Waits until the clock is in a step that no code of this run has used, and returns that step's code. */
async function nextStep(): Promise<string> {
  while (Math.floor(Date.now() / 30_000) <= lastStep) await new Promise((resolve) => setTimeout(resolve, 500));
  lastStep = Math.floor(Date.now() / 30_000);
  return totp(seed.admin.totp_secret);
}

async function apiLogin(request: APIRequestContext) {
  const response = await request.post("/api/v1/auth/login", {data: {username: seed.admin.username, password: seed.admin.password, totp_code: await nextStep()}});
  expect(response.status()).toBe(200);
  expect((await response.json()).state).toBe("ready");
}

const names = async (context: BrowserContext) => (await context.cookies()).map((c) => c.name);

async function uiLogin(page: Page, lang: "fa" | "en") {
  await page.goto(`/${lang}/login`);
  await expect(page.locator('form button[type="submit"]').first()).toBeEnabled();
  await page.locator('input[name="username"]').fill(seed.admin.username);
  await page.locator('input[name="password"]').fill(seed.admin.password);
  await page.locator('input[name="totp_code"]').focus();
  await page.keyboard.type(await nextStep());
  await page.waitForURL(`**/${lang}/overview`);
}

test("login with the password and a code, then Log out ends the session and clears the cookie", async ({page, context}) => {
  test.setTimeout(150_000);
  await uiLogin(page, "en");
  const cookie = (await context.cookies()).find((c) => c.name === "__Host-ctrlz_admin");
  expect(cookie?.httpOnly).toBe(true);
  expect(cookie?.secure).toBe(true);
  await expect(page.getByRole("heading", {level: 1, name: nodesText("en", "pages.overview.title")})).toBeVisible();

  await page.getByRole("button", {name: adm("en", "userMenu.label", {name: seed.admin.username})}).first().click();
  await page.getByRole("menuitem", {name: adm("en", "userMenu.logout")}).click();
  await page.getByRole("alertdialog").getByRole("button", {name: "Log out"}).click();
  await page.waitForURL("**/en/login");
  expect(await names(context)).not.toContain("__Host-ctrlz_admin");
  // The shell is gone for good: a protected page without the cookie goes back to the login.
  await page.goto("/en/users");
  await page.waitForURL("**/en/login?next=%2Fusers");
});

test("a wrong password is one neutral message", async ({page, guard}) => {
  // The 401 of the login call is the answer under test, and Chrome logs it (found by the first real run).
  guard.allowConsole(/status of 401/);
  await page.goto("/en/login");
  await expect(page.locator('form button[type="submit"]').first()).toBeEnabled();
  await page.locator('input[name="username"]').fill(seed.admin.username);
  await page.locator('input[name="password"]').fill("not-the-password-1234");
  await page.locator('form button[type="submit"]').first().click();
  await expect(page.getByText(errText("en", "invalid_credentials"))).toBeVisible();
});

// D19: nothing of a tenant's logs or secrets reaches the admin. The names are the ones a row of the users API could grow by mistake (a query
// log, a resolver endpoint, a credential); a key of that kind in any JSON answer that this page read fails the case (merge-r2-11).
const TENANT_DATA_KEYS = /^(query_?logs?|logs|log_entries|endpoint|endpoints|resolver|resolvers|domains|queried_domains|secret|totp_secret|password_hash|token|tokens|api_key)$/i;
function keysOf(value: unknown, out: string[] = []): string[] {
  if (Array.isArray(value)) for (const item of value) keysOf(item, out);
  else if (value && typeof value === "object") {
    for (const [key, inner] of Object.entries(value)) {
      out.push(key);
      keysOf(inner, out);
    }
  }
  return out;
}

test("Users finds the seeded user by a phone prefix, and no answer the page read carries a tenant's log or secret field", async ({page, context}) => {
  test.setTimeout(150_000);
  await apiLogin(context.request);
  const seen: string[] = [];
  const reads: Promise<void>[] = [];
  page.on("response", (response) => {
    if (!new URL(response.url()).pathname.startsWith("/api/") || !(response.headers()["content-type"] ?? "").includes("json")) return;
    reads.push(response.json().then((body) => void seen.push(...keysOf(body)), () => undefined));
  });
  await page.goto("/en/users");
  await page.getByRole("button", {name: "Search"}).first().click();
  await page.getByRole("searchbox").first().fill(seed.user.phone.slice(0, 8));
  await expect(page.getByRole("grid", {name: adm("en", "users.gridLabel")}).getByText(seed.user.phone.replace(/^0/, "+98"))).toBeVisible();
  await Promise.all(reads);
  expect(seen.length, "the page read some JSON from the API").toBeGreaterThan(0);
  expect(seen.filter((key) => TENANT_DATA_KEYS.test(key)), "a tenant's log or secret field in an admin answer").toEqual([]);
});

test("Audit shows the sign-in of this run", async ({page, context}) => {
  test.setTimeout(150_000);
  await apiLogin(context.request);
  await page.goto("/en/audit");
  await expect(page.getByRole("grid", {name: adm("en", "audit.gridLabel")}).getByRole("row").nth(1)).toBeVisible();
});

test("a write that needs a fresh code asks for one, repeats once, and the seeded mode is put back", async ({page, context, guard}) => {
  // The 403 totp_fresh_required that opens the dialog is the answer under test, and Chrome logs it.
  guard.allowConsole(/status of 403/);
  test.setTimeout(420_000);
  await apiLogin(context.request);
  // The sign-in with a code is itself a TOTP check, and an admin-fresh route is open for five minutes after one (session.Manager,
  // AdminFresh), so right after the login the write goes through and no dialog opens. Only a session past the window meets
  // totp_fresh_required, so this case waits it out: the real API is the only place that can show the dialog and its repeat (found by the first real run).
  await new Promise((resolve) => setTimeout(resolve, 5 * 60_000 + 5_000));
  try {
    await page.goto("/en/settings");
    await page.getByRole("radio", {name: adm("en", "settings.registration.mode.invite")}).click();
    await expect(page.getByTestId("registration-impact")).toBeVisible();
    await page.getByRole("button", {name: adm("en", "settings.registration.confirm", {mode: adm("en", "settings.registration.mode.invite")})}).click();
    const dialog = page.getByRole("dialog", {name: adm("en", "fresh.title")});
    await expect(dialog).toBeVisible();
    await page.locator('input[name="totp_code"]').focus();
    await page.keyboard.type(await nextStep());
    await expect(dialog).toHaveCount(0);
    await expect(page.getByTestId("settings-registration")).toBeVisible();
  } finally {
    // The seed left registration open. The fresh window the dialog opened is still live, so no code is needed here.
    const restored = await context.request.put("/api/v1/settings/registration", {data: {mode: "open", open_grace_days: 30}});
    expect(restored.ok(), "the seeded registration mode is put back, status " + restored.status()).toBe(true);
  }
});

// P4 (package PN, written and not yet run on the stack): the node pages read the real routes. Nothing is written: the enrolment page only
// lists, and a node that does not exist answers not_found, which the page shows as its own state and not as an error box.
test("the Enrol page lists the enrolments from the real API, and a node that does not exist is said so", async ({page, context, guard}) => {
  test.setTimeout(150_000);
  guard.allowConsole(/status of 404/);
  await apiLogin(context.request);
  await page.goto("/en/nodes/enrol");
  await expect(page.getByRole("heading", {level: 1, name: "Enrol a node"})).toBeVisible();
  // Either the empty state or a grid, never the section error: the route answered.
  await expect(page.getByTestId("enrol-list").locator('[role="alert"]')).toHaveCount(0);
  await page.goto("/en/nodes/00000000-0000-4000-8000-0000000fffff");
  await expect(page.getByText("Node not found")).toBeVisible();
});

// P4 (PG-r1-11, written and not yet run on the stack; it runs on GitHub Actions): the Pair, Domain and certificate routes answer with the
// paths and bodies the pages read. In mock mode they are checked only against nodeMock.ts, which a renamed field or a changed status of the
// real route would not touch. Read-only: nothing is written, so the seeded stack is as it was found. A deployment with no pair, no domain
// and no certificate yet is a valid answer: what is held for every row that does exist is the shape.
test("the Pair, Domain and certificate routes answer with the shapes the pages read, and a certificate row carries no key", async ({page, context, guard}) => {
  test.setTimeout(150_000);
  guard.allowConsole(/status of 404/);
  await apiLogin(context.request);
  const get = async (path: string) => {
    const response = await context.request.get(`/api/v1${path}`);
    expect(response.status(), `GET ${path}`).toBe(200);
    return (await response.json()) as Record<string, unknown>;
  };

  const pairs = await get("/pairs?limit=50");
  expect(Array.isArray(pairs.items), "pairs.items").toBe(true);
  for (const pair of pairs.items as Record<string, unknown>[]) {
    expect(Object.keys(pair)).toEqual(expect.arrayContaining(["id", "primary_node_id", "fallback_node_id", "is_global", "created_at"]));
    expect(typeof pair.is_global).toBe("boolean");
  }
  expect((pairs.items as {is_global: boolean}[]).filter((p) => p.is_global).length, "at most one global pair").toBeLessThanOrEqual(1);

  const domain = await get("/settings/domain");
  // The fields the Domain page reads (PG-r2-2): apply_pending is always there, the hosts and the zone only once they are set.
  expect(typeof domain.apply_pending, "domain.apply_pending").toBe("boolean");
  for (const key of ["dns_zone", "panel_host", "admin_host"]) {
    if (key in domain) expect(typeof domain[key], `domain.${key}`).toBe("string");
  }
  const impact = await get("/settings/domain/impact");
  expect(typeof impact.endpoints, "impact.endpoints").toBe("number");
  expect(typeof impact.apple_profiles, "impact.apple_profiles").toBe("number");

  const certificates = await get("/certificates?limit=50");
  expect(Array.isArray(certificates.items), "certificates.items").toBe(true);
  // The chain and the sealed key never leave the API (p4-nodes 4.3): not as a field, and not as text inside the answer.
  expect(JSON.stringify(certificates)).not.toMatch(/PRIVATE KEY|key_pem|chain_pem|sealed/i);

  // The pages read the same routes without a section error.
  await page.goto("/en/pair");
  await expect(page.getByRole("heading", {level: 1, name: nodesText("en", "pages.pair.title")})).toBeVisible();
  await expect(page.getByTestId("pair-grid-anchor")).toBeVisible();
  await page.goto("/en/domain");
  await expect(page.getByRole("heading", {level: 1, name: nodesText("en", "pages.domain.title")})).toBeVisible();
  // The content of the page, not the whole document: the stack run of 2026-11-27 counted one alert in the document at this point, and the shell has an empty alert element outside main (seen in the panel). Not re-run since.
  await expect(page.getByRole("main").getByRole("alert")).toHaveCount(0);
});
