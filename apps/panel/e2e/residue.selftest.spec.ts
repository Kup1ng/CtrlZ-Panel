import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

// gate-r16-8: a check that never fails looks the same as a page that is clean. The helper reads real browser state, so each place it reads is
// written to on purpose here and the helper must name it; the twin with nothing written must pass.

const SECRET = "JBSWY3DPEHPK3PXP";

async function open(page: Page) {
  // A regular expression, so that a query on the address still matches the route.
  await page.route(/\/guard-selftest\/residue/, (route) =>
    route.fulfill({contentType: "text/html", body: "<!doctype html><meta charset=utf-8><title>residue</title><p>quiet</p>"}));
  await page.goto("/guard-selftest/residue");
}

async function message(run: () => Promise<void>): Promise<string> {
  return run().then(
    () => "",
    (e: unknown) => String((e as Error).message),
  );
}

test.describe("the secret residue check (gate-r16-8)", () => {
  test("passes on a page that holds only what our code writes", async ({page}) => {
    await open(page);
    await page.evaluate(() => {
      localStorage.setItem("ctrlz.haptics", "1");
      sessionStorage.setItem("ctrlz_clip_pending", "1");
      document.cookie = "ctrlz_theme=dark; path=/";
    });
    await expectNoSecretResidue(page, [SECRET]);
  });

  for (const [place, write] of [
    ["localStorage", (s: string) => localStorage.setItem("ctrlz.haptics", s)],
    ["sessionStorage", (s: string) => sessionStorage.setItem("ctrlz_clip_pending", s)],
    ["history.state", (s: string) => history.replaceState({ticket: s}, "")],
    ["the address", (s: string) => history.replaceState(null, "", `?x=${s}`)],
    ["a cookie", (s: string) => void (document.cookie = `ctrlz_theme=${s}; path=/`)],
    ["window.name", (s: string) => void (window.name = s)],
  ] as const) {
    test(`finds a secret in ${place}, and names it without printing it`, async ({page}) => {
      await open(page);
      await page.evaluate(write, SECRET);
      const text = await message(() => expectNoSecretResidue(page, [SECRET]));
      expect(text).toContain("holds secret #0");
      expect(text).not.toContain(SECRET);
    });
  }

  test("finds a key that our code does not write", async ({page}) => {
    await open(page);
    await page.evaluate(() => sessionStorage.setItem("draft", "x"));
    expect(await message(() => expectNoSecretResidue(page, [SECRET]))).toContain("sessionStorage key draft is not one that our code writes");
  });

  // gate-r17-5: what the page ends on is clean, and the secret was written on the way. A snapshot of the last page cannot see it.
  test("finds a secret that a history call wrote and a later call replaced", async ({page}) => {
    await open(page);
    await page.evaluate((s) => {
      history.pushState({ticket: s}, "", "?step=2");
      history.replaceState(null, "", location.pathname);
    }, SECRET);
    // The page itself is clean now: the entry holds nothing.
    expect(await page.evaluate(() => JSON.stringify(history.state))).toBe("null");
    const text = await message(() => expectNoSecretResidue(page, [SECRET]));
    expect(text).toContain("a history.pushState or replaceState call");
    expect(text).toContain("holds secret #0");
    expect(text).not.toContain(SECRET);
  });

  test("finds a secret in an address that a later navigation left", async ({page}) => {
    await open(page);
    await page.goto(`/guard-selftest/residue?t=${SECRET}`);
    await open(page);
    const text = await message(() => expectNoSecretResidue(page, [SECRET]));
    expect(text).toContain("the address of a navigation");
    expect(text).not.toContain(SECRET);
  });

  test("finds a secret that the page printed to the console, at any level", async ({page}) => {
    await open(page);
    await page.evaluate((s) => console.info("restoring " + s), SECRET);
    const text = await message(() => expectNoSecretResidue(page, [SECRET]));
    expect(text).toContain("a console message");
    expect(text).not.toContain(SECRET);
  });

  // gate-r18-5: a visitor who arrives with the code in the address (arrivedWith) exempts the link and nothing else. What the page wrote or printed
  // before it stripped the code is judged, in the real format of the guard's record (a history call is "method address state").
  async function arrive(page: Page) {
    await page.route(/\/guard-selftest\/residue/, (route) =>
      route.fulfill({contentType: "text/html", body: "<!doctype html><meta charset=utf-8><title>residue</title><p>quiet</p>"}));
    await page.goto(`/guard-selftest/residue#${SECRET}`);
    // What Next and the invite page do: write the address back with the code, then strip it.
    await page.evaluate(() => history.replaceState({__NA: true}, "", location.href));
  }
  const strip = (page: Page) => page.evaluate(() => history.replaceState({__NA: true}, "", location.pathname));

  test("the link that the visitor arrived with is not a leak, once the page has stripped it", async ({page}) => {
    await arrive(page);
    await strip(page);
    await expectNoSecretResidue(page, [SECRET], "the flow", {arrivedWith: [SECRET]});
  });

  test("a console line before the strip is a leak although the visitor arrived with the code (gate-r18-5)", async ({page}) => {
    await arrive(page);
    await page.evaluate((s) => console.info("hash " + s), SECRET);
    await strip(page);
    const text = await message(() => expectNoSecretResidue(page, [SECRET], "the flow", {arrivedWith: [SECRET]}));
    expect(text).toContain("a console message");
    expect(text).not.toContain(SECRET);
  });

  test("a history state that holds the code before the strip is a leak although the address is the link (gate-r18-5)", async ({page}) => {
    await arrive(page);
    await page.evaluate((s) => history.pushState({invite: s}, "", location.href), SECRET);
    await strip(page);
    const text = await message(() => expectNoSecretResidue(page, [SECRET], "the flow", {arrivedWith: [SECRET]}));
    expect(text).toContain("a history.pushState or replaceState call");
    expect(text).not.toContain(SECRET);
  });

  test("fails the test when a console line holds the code that the visitor arrived with (gate-r18-5)", async ({page}) => {
    test.fail();
    await arrive(page);
    await page.evaluate((s) => console.info("hash " + s), SECRET);
    await strip(page);
    await expectNoSecretResidue(page, [SECRET], "the flow", {arrivedWith: [SECRET]});
  });

  test("passes when the page wrote and printed things that hold no secret", async ({page}) => {
    await open(page);
    await page.evaluate(() => {
      history.pushState({step: 2}, "", "?step=2");
      history.replaceState({step: 3}, "");
      console.log("hello");
    });
    await expectNoSecretResidue(page, [SECRET]);
  });

  test("fails the test when a secret was only on the way", async ({page}) => {
    test.fail();
    await open(page);
    await page.evaluate((s) => {
      history.pushState({ticket: s}, "", "?step=2");
      history.replaceState(null, "", location.pathname);
    }, SECRET);
    await expectNoSecretResidue(page, [SECRET]);
  });

  test("fails the test when a secret is left in the browser", async ({page}) => {
    test.fail();
    await open(page);
    await page.evaluate((s) => sessionStorage.setItem("ctrlz_clip_pending", s), SECRET);
    await expectNoSecretResidue(page, [SECRET]);
  });
});
