import type {Page} from "@playwright/test";
import {notificationFixture, securityNoticeFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {banners, openBell, openWith, securityBlock, type Lang} from "./notices-support.ts";
import type {Notification} from "@ctrlz/api-client/testing/fixtures.ts";

// The smoke case of the security notices of Question 19 (spec 8.5, 8.8, 17.1) on all 12 projects (three widths, two languages,
// two themes): the page renders in the project's language, direction and theme, has no sideways scroll (a banner with three
// links and a long Persian sentence at 375 px is what could break it), carries dark text on the accent, and has no serious
// or critical axe violation (17.5).

type Screen = {
  name: string;
  notifications: Notification[];
  after: (page: Page, lang: Lang) => Promise<void>;
};

const SCREENS: Screen[] = [
  {
    name: "banner-markable",
    notifications: [securityNoticeFixture()],
    after: async (page) => {
      await expect(banners(page)).toHaveCount(1);
      await expect(banners(page).getByRole("link")).toHaveCount(3);
    },
  },
  {
    name: "banner-not-markable",
    notifications: [securityNoticeFixture({markable: false}), securityNoticeFixture({kind: "recovery_codes_regenerated", markable: false})],
    after: async (page) => {
      await expect(banners(page)).toHaveCount(2);
      await expect(banners(page).getByRole("button")).toHaveCount(0);
    },
  },
  {
    name: "bell-block",
    notifications: [securityNoticeFixture(), securityNoticeFixture({kind: "recovery_codes_regenerated", markable: false}), notificationFixture({kind: "phone_changed"})],
    after: async (page) => {
      await openBell(page);
      await expect(securityBlock(page).getByRole("listitem")).toHaveCount(2);
      await expect(securityBlock(page).getByTestId("not-markable")).toHaveCount(1);
    },
  },
];

for (const screen of SCREENS) {
  test(`${screen.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    await openWith(context, baseURL, {notifications: screen.notifications, theme: matrix!.theme});
    const response = await page.goto(`/${matrix!.lang}/profiles`);
    await expect(page.locator(".shell-page")).toBeVisible();
    await screen.after(page, matrix!.lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `notices-${screen.name}`});
  });
}
