import {execFileSync} from "node:child_process";
import {readFileSync} from "node:fs";

import type {BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import enEndpoints from "../../../packages/i18n/messages/en/endpoints.json";

// Stack mode (spec p3 11.6, T-267), the IPs page against the real API behind Caddy at https://panel.localhost: claim an address, open the proof
// dialog, start a challenge, and see a label the server made in the commands the dialog offers. The proof itself is the hub's: it is written as
// evidence by the `ctrlz_hub` role in the database (spec 11.4), which a browser cannot do, so the last step runs a fixture command the stack
// owner provides in `E2E_PROOF_FIXTURE` (a program that takes the label as its one argument and writes one observation of that challenge from an
// address inside the claim). Without it the spec stops after the commands, which is still the real answer of `POST .../challenges`.
//
// WRITTEN, NOT RUN (Plan.md D69): the Compose stack is not started on the build machine. It runs with the rest of the stack specs
// (CTRLZ_WEB_STACK=1, after the seed of scripts/e2e-seed.mjs) and skips itself unless E2E_MODE=stack. The seeded user needs one profile; the
// first real run may show a selector to fix.
//
//   E2E_MODE=stack E2E_SEED_FILE=<private dir>/seed.json [E2E_PROOF_FIXTURE=<program>] pnpm exec playwright test e2e/ips.stack.spec.ts
//
// The Endpoint the spec makes is deleted in a `finally` block by the API, which also removes its claims, so a failed step cannot leave one behind.

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded user");

// The real API answers 401 where the mock fulfils quietly (the anonymous /me probe of the login page); only 401 is allowed.
test.beforeEach(({guard}) => guard.allowConsole(/status of 401/));

type Seed = {user: {phone: string; password: string}};
const seed = ((): Seed => {
  const file = process.env.E2E_SEED_FILE;
  if (file) return JSON.parse(readFileSync(file, "utf8")) as Seed;
  return {user: {phone: process.env.E2E_PHONE ?? "", password: process.env.E2E_PASSWORD ?? ""}};
})();

const t = enEndpoints;
const NAME = "CTRLZ-STACK-IPS";
const ADDRESS = "203.0.113.77";

async function signIn(page: Page) {
  await page.goto("/en/login");
  const submit = page.locator('form button[type="submit"]');
  await expect(submit.first()).toBeEnabled();
  await page.locator('input[name="phone"]').fill(seed.user.phone);
  await page.locator('input[name="password"]').fill(seed.user.password);
  await submit.first().click();
  await page.waitForURL("**/en/profiles");
}

/** Deletes every Endpoint of this spec by the API, whatever state the page was left in. */
async function removeEndpoints(context: BrowserContext) {
  const list = await context.request.get(`/api/v1/endpoints?q=${encodeURIComponent(NAME)}`);
  if (list.status() !== 200) return;
  const body = (await list.json()) as {items: {id: string; name: string}[]};
  for (const e of body.items.filter((x) => x.name === NAME)) {
    expect([200, 204], "delete the Endpoint of the spec").toContain((await context.request.post(`/api/v1/endpoints/${e.id}:delete`, {data: {}})).status());
  }
}

test.describe("IP claims against the real API", () => {
  test("T-267: a claimed address gets a real challenge, whose name and commands are shown, and fixture evidence proves it", async ({page, context}) => {
    test.setTimeout(180_000);
    try {
      await signIn(page);
      await page.goto("/en/endpoints?deviceDialog=add");
      const add = page.getByRole("dialog", {name: enEndpoints.dialogs.add.title});
      await expect(add).toBeVisible();
      await add.getByRole("textbox", {name: enEndpoints.dialogs.fields.name}).fill(NAME);
      await add.getByRole("button", {name: enEndpoints.dialogs.add.submit, exact: true}).click();
      await expect(page).toHaveURL(/deviceDialog=resolvers&deviceId=[0-9a-f-]{36}/);
      const id = /deviceId=([0-9a-f-]{36})/.exec(page.url())![1]!;

      await page.goto(`/en/endpoints/${id}/ips?ipDialog=claim`);
      const claim = page.getByRole("dialog", {name: t.ips.claim.title});
      await claim.getByRole("textbox", {name: t.ips.claim.field}).fill(ADDRESS);
      await claim.getByRole("button", {name: t.ips.claim.submit, exact: true}).click();

      // The claim waits for proof, and the dialog of the proof replaces the claim dialog.
      // The server may write the address as a /32, so the title is matched by the address.
      const proof = page.getByRole("dialog", {name: /203\.0\.113\.77/});
      await expect(proof).toBeVisible();
      await proof.getByRole("button", {name: t.ips.proof.start}).click();
      const steps = proof.getByTestId("proof-steps");
      await expect(steps).toBeVisible();

      // The name the server made is one label of letters and digits under `verify`, and both commands carry it.
      const tcp = proof.getByRole("region", {name: t.ips.proof.tcp.title});
      await expect(tcp).toContainText(/dig \+tcp TXT [a-z0-9]{1,63}\.verify\./);
      const label = /dig \+tcp TXT ([a-z0-9]{1,63})\.verify\./.exec((await tcp.textContent()) ?? "")![1]!;

      const fixture = process.env.E2E_PROOF_FIXTURE;
      test.skip(!fixture, "no fixture command to write the evidence of the hub");
      execFileSync(fixture!, [label], {stdio: "ignore", timeout: 30_000});
      // The dialog reads the claims every 3 seconds and takes the claim on its own for an observation that needs no code.
      await expect(proof.getByText(t.ips.proof.provenText)).toBeVisible({timeout: 30_000});
    } finally {
      await removeEndpoints(context);
    }
  });
});
