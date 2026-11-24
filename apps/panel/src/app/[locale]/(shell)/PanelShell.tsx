import {AppShell} from "@ctrlz/ui/shell/AppShell.tsx";
import {panelNav} from "@ctrlz/ui/shell/panelNav.ts";
import {cookies} from "next/headers";
import {getTranslations} from "next-intl/server";
import type {ReactNode} from "react";

// The tenant shell, as a function of the request. Used by (shell)/layout.tsx and
// by not-found.tsx, which renders inside the shell for a signed-in visitor.
export async function PanelShell({children}: {children: ReactNode}) {
  const [t, store] = await Promise.all([getTranslations("shell"), cookies()]);
  // AppLayout writes this cookie while uncontrolled, so a collapsed sidebar is
  // already collapsed on the first byte and does not flash open (T-114).
  const defaultSidebarOpen = store.get("sidebar_state")?.value !== "false";

  const nav = panelNav({
    profiles: t("nav.profiles"),
    endpoints: t("nav.endpoints"),
    analytics: t("nav.analytics"),
    statistics: t("nav.statistics"),
    activityLog: t("nav.activityLog"),
    domainTest: t("nav.domainTest"),
    preferences: t("nav.preferences"),
    account: t("nav.account"),
    api: t("nav.api"),
    logout: t("nav.logout"),
  });

  return (
    <AppShell nav={nav} defaultSidebarOpen={defaultSidebarOpen}>
      {children}
    </AppShell>
  );
}
