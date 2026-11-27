import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import type {LibraryDefect} from "@ctrlz/ui/testing/axeLogic.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {openList, tick} from "./endpoint-screens-support.ts";
import {gridCell, text} from "./endpoint-pages-support.ts";
import {CLAIM, ENDPOINT, endpointPath, type Lang} from "./endpoints-support.ts";

// The smoke case of the Schedule, Clients and IPs pages and each of their dialogs (spec p3 11.6, FE 17.1, 17.5) on all 12 projects (three
// widths, two languages, two themes): the page renders in the project's language, direction and theme, has no sideways scroll, carries dark
// text on the accent, and has no serious or critical axe violation, with one dialog open at a time.

// React Aria's live announcer, which a Button with `isPending` creates the first time it is pressed (the proof dialog's Start; see account.matrix.spec.ts):
// the library's own element, inert, and listed by the region it sits in.
const LIVE_ANNOUNCER: LibraryDefect = {
  rule: "role-img-alt",
  within: '[role="log"]',
  element: '[role="img"]',
  note: "React Aria live announcer: an empty role=img with a dangling aria-labelledby",
};

type Case = {
  name: string;
  path: (lang: Lang) => string;
  ready: (page: Page, lang: Lang) => Promise<void>;
};

const dialogShown = (page: Page) => expect(page.getByRole("dialog")).toBeVisible();
const screenOf = (page: Page, name: string) => expect(page.locator(`[data-screen="${name}"]`)).toBeVisible();
const ips = (lang: Lang, dialog = "") => `${endpointPath(lang, ENDPOINT.home, "ips")}${dialog ? `?ipDialog=${dialog}` : ""}`;
const clients = (lang: Lang, query = "") => `${endpointPath(lang, ENDPOINT.home, "clients")}${query}`;

const CASES: Case[] = [
  {name: "schedule-empty", path: (l) => endpointPath(l, ENDPOINT.home, "schedule"), ready: (p) => screenOf(p, "endpoint-schedule")},
  {
    name: "schedule-with-windows",
    path: (l) => endpointPath(l, ENDPOINT.office, "schedule"),
    ready: async (p) => {
      await expect(gridCell(p, 0, 20)).toHaveAttribute("aria-label", /Office/);
    },
  },
  {
    name: "schedule-window-editor",
    path: (l) => endpointPath(l, ENDPOINT.office, "schedule"),
    ready: async (p) => {
      await gridCell(p, 0, 20).click();
      await dialogShown(p);
    },
  },
  {
    name: "schedule-copy-day",
    path: (l) => endpointPath(l, ENDPOINT.office, "schedule"),
    ready: async (p, lang) => {
      await p.getByRole("button", {name: text(lang, "schedule.copy.button"), exact: true}).click();
      await dialogShown(p);
    },
  },
  {name: "clients", path: (l) => clients(l), ready: (p) => expect(p.locator(".client-list [role=listitem]").first()).toBeVisible()},
  {name: "clients-empty", path: (l) => endpointPath(l, ENDPOINT.laptop, "clients"), ready: (p) => screenOf(p, "endpoint-clients")},
  {
    name: "clients-selecting",
    path: (l) => clients(l),
    ready: async (p, lang) => {
      await p.getByRole("button", {name: text(lang, "clients.menu.label")}).click();
      await p.getByRole("menuitem", {name: text(lang, "clients.menu.select")}).click();
      await tick(p.getByRole("checkbox").first());
      await expect(p.getByRole("toolbar")).toBeVisible();
    },
  },
  {name: "client-create-dialog", path: (l) => clients(l, `?deviceDialog=client&deviceId=${ENDPOINT.home}`), ready: dialogShown},
  {
    name: "client-edit-dialog",
    path: (l) => clients(l),
    ready: async (p, lang) => {
      await p.getByRole("button", {name: text(lang, "clients.row.editAria", {name: "device-11"})}).click();
      await dialogShown(p);
    },
  },
  {
    name: "client-delete-inactive-dialog",
    path: (l) => clients(l),
    ready: async (p, lang) => {
      await p.getByRole("button", {name: text(lang, "clients.menu.label")}).click();
      await p.getByRole("menuitem", {name: text(lang, "clients.menu.inactive")}).click();
      await expect(p.getByTestId("delete-count")).not.toContainText(text(lang, "clients.delete.counting"));
    },
  },
  {
    name: "client-delete-all-dialog",
    path: (l) => clients(l),
    ready: async (p, lang) => {
      await p.getByRole("button", {name: text(lang, "clients.menu.label")}).click();
      await p.getByRole("menuitem", {name: text(lang, "clients.menu.all")}).click();
      await expect(p.getByTestId("delete-count")).not.toContainText(text(lang, "clients.delete.counting"));
    },
  },
  {name: "ips", path: (l) => ips(l), ready: (p) => expect(p.getByTestId("authorized-section")).toBeVisible()},
  {name: "ips-empty", path: (l) => endpointPath(l, ENDPOINT.laptop, "ips"), ready: (p) => screenOf(p, "endpoint-ips")},
  {name: "ip-claim-dialog", path: (l) => ips(l, "claim"), ready: dialogShown},
  {
    name: "ip-proof-dialog-start",
    path: (l) => ips(l, `proof:${CLAIM.pending}`),
    ready: async (p, lang) => {
      await expect(p.getByRole("dialog").getByRole("button", {name: text(lang, "ips.proof.again")})).toBeVisible();
    },
  },
  {
    name: "ip-proof-dialog-steps",
    path: (l) => ips(l, `proof:${CLAIM.pending}`),
    ready: async (p, lang) => {
      await p.getByRole("dialog").getByRole("button", {name: text(lang, "ips.proof.again")}).click();
      await expect(p.getByTestId("proof-steps")).toBeVisible();
    },
  },
  {name: "ip-add-dialog", path: (l) => ips(l, "add"), ready: dialogShown},
  {
    name: "ip-delete-dialog",
    path: (l) => ips(l),
    ready: async (p, lang) => {
      await p.getByRole("button", {name: text(lang, "ips.authorized.deleteAria", {cidr: "198.51.100.0/24"})}).click();
      await dialogShown(p);
    },
  },
  {
    name: "ip-release-dialog",
    path: (l) => ips(l),
    ready: async (p, lang) => {
      await p.getByRole("button", {name: text(lang, "ips.claims.releaseAria", {cidr: "198.51.100.0/24"})}).click();
      await dialogShown(p);
    },
  },
];

test.use({allowConsole: [/status of 4\d\d/]});

for (const c of CASES) {
  test(`${c.name}: language, direction, theme, no overflow, accessible`, async ({page, context, baseURL, matrix}) => {
    expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
    const mock = await openList(context, baseURL, {theme: matrix!.theme});
    mock.screens.endpoints = mock.screens.endpoints.map((e) => (e.id === ENDPOINT.home ? {...e, authorize_ddns: c.name === "ips"} : e));
    const response = await page.goto(c.path(matrix!.lang));
    await c.ready(page, matrix!.lang);
    await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
    await expectAccessible(page, {screen: `endpoint-pages-${c.name}`, libraryDefects: [LIVE_ANNOUNCER]});
  });
}
