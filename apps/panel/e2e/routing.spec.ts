import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {allowAuthErrors, inviteInfoFixture, lastBody, openAnonymous} from "./auth-support.ts";

// Spec 17.3 `routing.spec.ts`, 4.1 and AUTH 11.3 (gate-r3-11). The invite link that the admin sends has no language segment:
// `https://<panel host>/invite#<code>`. The proxy answers it with a 307 to `/fa/invite`, and the code survives only because that
// Location has no fragment of its own, so the browser carries the original one over. Every other spec opens `/<lang>/invite#...`
// directly, so nothing else sends a request through this hop. A Location with its own `#`, an absolute one, or a rewrite instead of a
// redirect would lose the code, and the invitee would land on an empty form.

test.beforeEach(({guard}) => allowAuthErrors(guard));
test.use({viewport: {width: 1280, height: 800}});

const CODE = "ABCDEFGHJKMNPQRSTVWX";

test.describe("the invite link without a language", () => {
  test("/invite#CODE is redirected to /fa/invite, keeps its fragment through the hop, and the page reads it from there", async ({page, context}) => {
    const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
    const hops: {status: number; location: string | undefined; from: string}[] = [];
    page.on("response", (response) => {
      if (response.status() >= 300 && response.status() < 400) hops.push({status: response.status(), location: response.headers()["location"], from: response.request().url()});
    });
    await page.goto(`/invite#${CODE}`);
    await expect(page).toHaveURL(/\/fa\/invite$/);
    // The hop: a redirect whose own Location carries no fragment, from a request that did carry it.
    const hop = hops.find((h) => new URL(h.from).pathname === "/invite");
    expect(hop, "the request to /invite was answered with a redirect").toBeDefined();
    expect(hop!.status).toBe(307);
    expect(hop!.location).toBeDefined();
    expect(hop!.location!, "the redirect names the page, without a fragment of its own").not.toContain("#");
    expect(new URL(hop!.location!, hop!.from).pathname).toBe("/fa/invite");
    // What matters to the invitee: the code reached the lookup, and the page took it off the address bar.
    await expect.poll(() => lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE});
    expect(new URL(page.url()).hash).toBe("");
    expect(page.url()).not.toContain(CODE.slice(0, 4));
  });

  test("the language-less paths of the other public pages go to /fa as well", async ({page, context}) => {
    await openAnonymous(context);
    // "/" is the redirect that every visitor meets first; the page it lands on may send a visitor without a session on to login.
    await page.goto("/");
    await expect(page).toHaveURL(/\/fa(\/|\?|$)/);
    for (const [from, to] of [["/login", "/fa/login"], ["/register", "/fa/register"], ["/forgot-password", "/fa/forgot-password"]] as const) {
      await page.goto(from);
      await expect(page, from).toHaveURL(new RegExp(`${to}$`));
    }
  });

  test("a link that already names a language is not redirected, and its fragment is read the same way", async ({page, context}) => {
    const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
    const hops: number[] = [];
    page.on("response", (response) => {
      if (response.status() >= 300 && response.status() < 400) hops.push(response.status());
    });
    await page.goto(`/en/invite#${CODE}`);
    await expect(page).toHaveURL(/\/en\/invite$/);
    expect(hops).toEqual([]);
    await expect.poll(() => lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE});
  });
});
