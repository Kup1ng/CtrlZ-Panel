import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {NextIntlClientProvider} from "next-intl";
import type {ReactNode} from "react";
import {renderToString} from "react-dom/server";
import {describe, expect, it, vi} from "vitest";

import common from "../../../i18n/messages/en/common.json";
import errors from "../../../i18n/messages/en/errors.json";
import shell from "../../../i18n/messages/en/shell.json";
import admin from "../../../i18n/messages/en/admin.json";

vi.mock("next/navigation", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/users",
  useRouter: () => ({push: () => undefined, replace: () => undefined, back: () => undefined}),
}));

import {BannerStack} from "./BannerStack.tsx";
import {BellButton, BellDialog} from "./Bell.tsx";
import {LogoutDialog} from "./LogoutDialog.tsx";
import {AppContextProvider} from "../providers/appContext.tsx";
import {AppShell} from "./AppShell.tsx";
import {FreshTotpProvider} from "../auth/FreshTotpDialog.tsx";
import {adminClockKeys} from "@ctrlz/api-client/admin/clockSkew.ts";
import {adminMeKeys} from "@ctrlz/api-client/admin/session.ts";
import {adminMeFixture} from "@ctrlz/api-client/testing/fixtures.ts";

type ShellApp = "panel" | "admin";

// Spec 13 and 14: the admin app mounts the same shell on its own API, which has no
// refresh, no bell and no feeds. A panel hook mounted there would ask the panel
// `/me` (a query it should never have), and on a 401 the panel client would POST
// `/auth/refresh` to the admin host. A query exists in the cache once a hook has
// asked for it, even on the server, so the cache shows which hooks ran.

function Shell({app, client, children}: {app: ShellApp; client: QueryClient; children: ReactNode}) {
  return (
    <QueryClientProvider client={client}>
      <NextIntlClientProvider locale="en" messages={{common, errors, shell, admin}}>
        {/* The admin shell sits inside this provider (AdminShellFrame): its banners acknowledge an alert through the fresh-code recovery (gate-r32-3). */}
        <AppContextProvider value={app}>{app === "admin" ? <FreshTotpProvider>{children}</FreshTotpProvider> : children}</AppContextProvider>
      </NextIntlClientProvider>
    </QueryClientProvider>
  );
}

function everyPart(app: ShellApp) {
  const client = new QueryClient();
  renderToString(
    <Shell app={app} client={client}>
      <BannerStack />
      <BellButton />
      <BellDialog />
      <LogoutDialog isOpen={false} onOpenChange={() => undefined} />
    </Shell>,
  );
  return client;
}

const keysOf = (client: QueryClient) => client.getQueryCache().getAll().map((q) => JSON.stringify(q.queryKey));

describe("the shell on the admin app", () => {
  it("mounts no panel query: no /me, no notifications, no announcements, so nothing can refresh against the admin API", () => {
    // The admin's own banners ask the admin API (13.6): its `/me` and its alerts, and nothing of the panel's.
    const keys = everyPart("admin").getQueryCache().getAll().map((q) => q.queryKey);
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.every((key) => key[0] === "admin")).toBe(true);
    expect(keysOf(everyPart("admin"))).not.toEqual(expect.arrayContaining([JSON.stringify(["me"])]));
  });

  it("renders no bell for admin (spec 13)", () => {
    const html = renderToString(
      <Shell app="admin" client={new QueryClient()}>
        <BellButton />
      </Shell>,
    );
    expect(html).toBe("");
  });

  // wp4-r5-9: the app is the one AppProviders got from the layout. AppShell has no prop of its own to forget,
  // so a shell mounted as the admin app can only run the admin gate.
  it("the whole shell, with no app prop, runs the admin gate and no panel query", () => {
    const client = new QueryClient();
    renderToString(
      <Shell app="admin" client={client}>
        <AppShell nav={[]} defaultSidebarOpen>
          <p>page</p>
        </AppShell>
      </Shell>,
    );
    const keys = client.getQueryCache().getAll().map((q) => q.queryKey);
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.every((key) => key[0] === "admin")).toBe(true);
  });

  it("has no panel default: a shell part outside AppProviders throws", () => {
    expect(() =>
      renderToString(
        <QueryClientProvider client={new QueryClient()}>
          <BannerStack />
        </QueryClientProvider>,
      ),
    ).toThrow(/AppProviders/);
  });

  it("still asks the panel queries on the panel app, so the check above can fail", () => {
    expect(keysOf(everyPart("panel"))).toEqual(
      expect.arrayContaining([JSON.stringify(["me"]), JSON.stringify(["notifications", "list"]), JSON.stringify(["announcements", "list"])]),
    );
  });
});

// Spec 7.10 and 11.9 (T-088): the banner the clock offset of GET /me raises. The offset itself, from the Date header and a faked
// browser clock, is tested in packages/api-client/src/admin/clockSkew.test.ts; this is what the shell does with it.
describe("the admin shell's clock banner", () => {
  const bannersFor = (offset: number | null | undefined) => {
    const client = new QueryClient();
    client.setQueryData(adminMeKeys.all, adminMeFixture());
    if (offset !== undefined) client.setQueryData(adminClockKeys.skew, offset);
    return renderToString(
      <Shell app="admin" client={client}>
        <BannerStack />
      </Shell>,
    );
  };

  it("says the device is behind the server above 30 s, with the seconds", () => {
    const html = bannersFor(45_000);
    expect(html).toContain("clock is not the server");
    expect(html).toContain("about 45 seconds behind");
  });

  it("says the device is ahead when it is ahead", () => {
    expect(bannersFor(-95_000)).toContain("about 95 seconds ahead of");
  });

  it("shows nothing at 30 s, with no answer yet, or when the answer had no Date", () => {
    for (const offset of [30_000, -30_000, undefined, null]) expect(bannersFor(offset)).not.toContain("seconds");
  });
});
