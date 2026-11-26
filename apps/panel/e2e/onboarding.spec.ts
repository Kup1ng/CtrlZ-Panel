import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {LAB, signIn} from "./feedback-support.ts";
import {shell} from "./notices-support.ts";

// Spec 17.3 `onboarding.spec.ts` (T-119), in mock mode: the done state of a step of the starting checklist. The dismissal, its confirmation and
// the hint switch are in `shell.spec.ts`, `session.spec.ts` and `account.spec.ts`. P1 has no profile or endpoint to count, so no real screen shows a
// step done: the feedback lab draws the card with facts that are true (a fixture, spec question 10; P2 and P3 fill the real ones), and this is
// the case of what a done step looks like: a check and a word, never colour alone, and no button to start what is finished.

const LANGS = [
  {lang: "fa", dir: "rtl", digit: (n: number) => "۰۱۲۳۴۵۶۷۸۹"[n]!},
  {lang: "en", dir: "ltr", digit: (n: number) => String(n)},
] as const;

// The lab's facts: the first two steps are done, the next two are not, and the tutorial has no fact to be done by.
const DONE = ["createProfile", "enableFilter"] as const;
const OPEN_WITH_BUTTON = ["addEndpoint", "configureEndpoint"] as const;

for (const {lang, dir, digit} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    for (const width of [375, 1280]) {
      test.describe(`at ${width}px`, () => {
        test.use({viewport: {width, height: 900}});

        test("a done step has a check and the word Done, no Start button; an open one has its button; the count says so (T-119)", async ({page, context, baseURL}) => {
          await signIn(context, baseURL);
          await page.goto(LAB(lang));
          const card = page.getByTestId("sample-onboarding").locator(".onboarding");
          await expect(card).toBeVisible();
          await expect(card.getByText(shell(lang, "onboarding.progress", {done: digit(2), total: digit(5)}), {exact: true})).toBeVisible();

          const steps = card.locator(".onboarding__steps > *");
          await expect(steps).toHaveCount(5);
          const word = shell(lang, "onboarding.done");
          const start = shell(lang, "onboarding.start");
          for (const id of DONE) {
            const step = steps.filter({hasText: shell(lang, `onboarding.steps.${id}.title`)});
            await expect(step, id).toHaveCount(1);
            // Done is a word and a mark that is not colour: the text is there for everyone, and the check is the icon's shape.
            await expect(step.getByText(word, {exact: true}), `${id} says Done`).toBeVisible();
            await expect(step.locator("svg").first(), `${id} has its check`).toBeVisible();
            await expect(step.getByRole("button", {name: start}), `${id} has no Start`).toHaveCount(0);
          }
          for (const id of OPEN_WITH_BUTTON) {
            const step = steps.filter({hasText: shell(lang, `onboarding.steps.${id}.title`)});
            await expect(step.getByText(word, {exact: true}), `${id} is not done`).toHaveCount(0);
            await expect(step.getByRole("button", {name: start}), `${id} has Start`).toBeVisible();
          }
          // The check is a different drawing from the step's own icon, so a done step differs from an open one by shape and not by colour alone.
          const iconOf = (id: string) => steps.filter({hasText: shell(lang, `onboarding.steps.${id}.title`)}).locator("svg").first().innerHTML();
          expect(await iconOf("createProfile")).not.toBe(await iconOf("addEndpoint"));
          expect(await iconOf("createProfile")).toBe(await iconOf("enableFilter"));
          // The tutorial is not a fact and has no target yet: neither Done nor Start.
          const tutorial = steps.filter({hasText: shell(lang, "onboarding.steps.tutorial.title")});
          await expect(tutorial.getByText(word, {exact: true})).toHaveCount(0);
          await expect(tutorial.getByRole("button")).toHaveCount(0);
          // Exactly the two done words are on the card.
          await expect(card.getByText(word, {exact: true})).toHaveCount(2);
          expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "no sideways scroll").toBe(true);
        });
      });
    }
  });
}
