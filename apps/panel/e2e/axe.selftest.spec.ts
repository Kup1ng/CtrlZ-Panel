import AxeBuilder from "@axe-core/playwright";
import type {Page} from "@playwright/test";
import type {LibraryDefect} from "@ctrlz/ui/testing/axeLogic.ts";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

// Spec 17.5, gate-r2-12 and gate-r2-20. A library defect is excused by the region its element sits in, and the region has to be
// decided while axe looks at the page. React Aria removes its live announcer 7 seconds after an announcement, which on a slow run
// is between axe's analysis and the next look at the page, and the check used to fail the run on the defect it had excused.
//
// The page here has the same shape (a `role="log"` holding an empty `role="img"` whose `aria-labelledby` points at nothing). The tests
// make the removal happen at exactly that moment: right after `analyze()` returns and before the result is classified, which no
// timing on a quiet machine would reproduce.

const ANNOUNCER: LibraryDefect = {rule: "role-img-alt", within: '[role="log"]', element: '[role="img"]', note: "selftest"};
const PAGE = (body: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>axe selftest</title></head><body><main><h1>axe selftest</h1>${body}</main></body></html>`;
const IN_LOG = `<div role="log" aria-live="polite"><div role="img" aria-labelledby="gone-id"></div></div>`;
const OUTSIDE = `<section><div role="img" aria-labelledby="gone-id"></div></section>`;

async function open(page: Page, body: string) {
  await page.route("**/axe-selftest", (route) => route.fulfill({contentType: "text/html", body: PAGE(body)}));
  await page.goto("/axe-selftest");
}

/** Runs `after` right after every analysis, in the page, before the helper reads the result. Restored when the test ends. */
function afterAnalysis(page: Page, after: () => void) {
  const original = AxeBuilder.prototype.analyze;
  AxeBuilder.prototype.analyze = async function (this: AxeBuilder) {
    const result = await original.call(this);
    await page.evaluate(after);
    return result;
  } as typeof original;
  return () => {
    AxeBuilder.prototype.analyze = original;
  };
}

test.describe("expectAccessible and a library defect", () => {
  test("is excused by its region, and the page is not asked again after the analysis", async ({page}) => {
    await open(page, IN_LOG);
    const restore = afterAnalysis(page, () => document.querySelector('[role="log"]')?.replaceChildren());
    try {
      await expectAccessible(page, {screen: "axe-selftest", libraryDefects: [ANNOUNCER]});
    } finally {
      restore();
    }
    expect(test.info().annotations.filter((a) => a.type === "axe-known").map((a) => a.description).join("\n")).toContain("role-img-alt");
  });

  test("leaves nothing of its marks behind", async ({page}) => {
    await open(page, IN_LOG);
    await expectAccessible(page, {screen: "axe-selftest", libraryDefects: [ANNOUNCER]});
    expect(await page.locator("[data-ctrlz-region]").count()).toBe(0);
  });
});

test.describe("expectAccessible fails on", () => {
  // The same defect outside the region is the page's own and must not be excused, whatever happens to the node.
  test("the defect of the library's element when it sits outside the region", async ({page}) => {
    test.fail();
    await open(page, OUTSIDE);
    await expectAccessible(page, {screen: "axe-selftest", libraryDefects: [ANNOUNCER]});
  });

  test("the same defect outside the region, after the node is gone", async ({page}) => {
    test.fail();
    await open(page, OUTSIDE);
    const restore = afterAnalysis(page, () => document.querySelector("section")?.replaceChildren());
    try {
      await expectAccessible(page, {screen: "axe-selftest", libraryDefects: [ANNOUNCER]});
    } finally {
      restore();
    }
  });
});
