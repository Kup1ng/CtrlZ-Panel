import {notificationFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {badge, openBell, openWith, shell} from "./notices-support.ts";

// Spec 17.3 `bell.spec.ts` (T-118), in mock mode: what one row of the bell list shows. The model is in
// `packages/ui/src/shell/useBellData.test.ts` and the reading, the unsafe link and the polling are in `session.spec.ts`; this file holds
// the two things that only a browser can say: the date is relative and written in the language, and the unread mark is one named
// element that sits on the unread row and on no other.

const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;

// The page's clock is fixed, so "5 minutes ago" does not turn into "6" while a slow machine renders the list. Only Date.now() is fixed:
// timers still run, so the bell's polling and TanStack Query behave as they do in production.
const NOW = "2026-11-25T12:00:00Z";
const FIVE_MINUTES_AGO = "2026-11-25T11:55:00Z";
const THREE_HOURS_AGO = "2026-11-25T09:00:00Z";

// The relative text of Intl, which is the app's one formatter (format.ts): a Persian digit in `fa`, a Latin one in `en`.
const FIVE_MINUTES = {fa: "۵ دقیقه پیش", en: "5 minutes ago"} as const;
const THREE_HOURS = {fa: "۳ ساعت پیش", en: "3 hours ago"} as const;

for (const {lang} of LANGS) {
  test.describe(`${lang}`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    test("an unread and a read item: the relative time of each, and the unread mark on the unread one only (T-118)", async ({page, context, baseURL}) => {
      const unread = notificationFixture({kind: "password_reset", created_at: FIVE_MINUTES_AGO});
      const read = notificationFixture({kind: "phone_changed", created_at: THREE_HOURS_AGO, read_at: "2026-11-25T10:00:00Z"});
      await page.clock.setFixedTime(new Date(NOW));
      await openWith(context, baseURL, {notifications: [unread, read]});
      await page.goto(`/${lang}/profiles`);
      await expect(page.locator(".shell-page")).toBeVisible();
      // The badge counts the one unread item, in the language's digits.
      await expect(badge(page)).toHaveText(lang === "fa" ? "۱" : "1");

      await openBell(page);
      const dialog = page.getByRole("dialog");
      const items = dialog.locator(".accordion__item");
      await expect(items).toHaveCount(2);

      // Newest first: the unread one, five minutes old.
      const [first, second] = [items.nth(0), items.nth(1)];
      const firstTime = first.getByTestId("notice-time");
      await expect(firstTime).toHaveText(FIVE_MINUTES[lang]);
      // A real <time>: the machine value is the creation instant, and the full date is behind it in the language's calendar.
      await expect(firstTime).toHaveJSProperty("tagName", "TIME");
      await expect(firstTime).toHaveAttribute("datetime", FIVE_MINUTES_AGO);
      await expect(second.getByTestId("notice-time")).toHaveText(THREE_HOURS[lang]);
      await expect(second.getByTestId("notice-time")).toHaveAttribute("datetime", THREE_HOURS_AGO);

      // The unread mark is one element, named for a screen reader, with the dot for the eye. The read item has none.
      const mark = dialog.getByTestId("unread-mark");
      await expect(mark).toHaveCount(1);
      await expect(first.getByTestId("unread-mark")).toHaveCount(1);
      await expect(second.getByTestId("unread-mark")).toHaveCount(0);
      await expect(mark).toHaveText(shell(lang, "bell.unreadMark"));
      await expect(mark.locator("[aria-hidden='true']")).toHaveCount(1);
      // The mark comes first in the row, so the trigger is read "Unread, <title>, <when>".
      const trigger = first.getByRole("button");
      await expect(trigger).toContainText(shell(lang, "bell.unreadMark"));
      const order = await trigger.evaluate((el) => {
        const at = (selector: string) => {
          const hit = el.querySelector(selector);
          return hit ? [...el.querySelectorAll("*")].indexOf(hit) : -1;
        };
        return {mark: at("[data-testid='unread-mark']"), time: at("[data-testid='notice-time']")};
      });
      expect(order.mark).toBeGreaterThanOrEqual(0);
      expect(order.mark).toBeLessThan(order.time);
    });

    test.describe("at 375px", () => {
      test.use({viewport: {width: 375, height: 812}});

      // The design critique of T-464: at a phone width a long title of a read item pushed its date and chevron out of the dialog (the
      // trigger's automatic minimum width was its content), and a read title began where the unread dot sits, so the titles of two rows
      // did not line up. The title is what gets cut, the chevron stays inside, and every title starts at the same place.
      test("a long title is cut, the date and chevron stay inside the dialog, and read and unread titles start together", async ({page, context, baseURL}) => {
        const unread = notificationFixture({kind: "password_reset", created_at: FIVE_MINUTES_AGO});
        const read = notificationFixture({kind: "phone_changed", created_at: THREE_HOURS_AGO, read_at: "2026-11-25T10:00:00Z"});
        await page.clock.setFixedTime(new Date(NOW));
        await openWith(context, baseURL, {notifications: [unread, read]});
        await page.goto(`/${lang}/profiles`);
        await expect(page.locator(".shell-page")).toBeVisible();
        await openBell(page);
        const dialog = page.getByRole("dialog");
        const items = dialog.locator(".accordion__item");
        await expect(items).toHaveCount(2);

        const geometry = await dialog.evaluate((el) => {
          const box = el.getBoundingClientRect();
          const rtl = getComputedStyle(el).direction === "rtl";
          // The edge a row starts from: its right edge in a right-to-left page.
          const start = (node: Element) => (rtl ? node.getBoundingClientRect().right : node.getBoundingClientRect().left);
          const rows = [...el.querySelectorAll(".accordion__item")].map((item) => ({
            title: start(item.querySelector(".truncate")!),
            // How far the chevron is from the dialog's edge on the side it sits (the end of the row), positive when inside.
            chevronInside: rtl
              ? item.querySelector(".accordion__indicator")!.getBoundingClientRect().left - box.left
              : box.right - item.querySelector(".accordion__indicator")!.getBoundingClientRect().right,
          }));
          return {rows};
        });
        for (const row of geometry.rows) expect(row.chevronInside).toBeGreaterThan(0);
        expect(Math.abs(geometry.rows[0]!.title - geometry.rows[1]!.title)).toBeLessThan(1);
      });
    });
  });
}
