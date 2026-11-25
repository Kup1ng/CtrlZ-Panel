import {cookies} from "next/headers";
import {getTranslations} from "next-intl/server";
import type {ReactNode} from "react";

import {adminNav, adminUserMenu} from "../../../nav.ts";
import {AdminShellFrame} from "@ctrlz/ui/admin/shell/AdminShellFrame.tsx";

// The admin shell, as a function of the request. Used by (shell)/layout.tsx and by not-found.tsx, which renders
// inside the shell for a visitor who has an admin session cookie.
export async function AdminShell({children}: {children: ReactNode}) {
  const [t, store] = await Promise.all([getTranslations("admin"), cookies()]);
  // The first byte already has the sidebar as the admin left it (T-114), so it does not flash open.
  const defaultSidebarOpen = store.get("sidebar_state")?.value !== "false";

  const nav = adminNav({
    users: t("nav.users"),
    invites: t("nav.invites"),
    sms: t("nav.sms"),
    settings: t("nav.settings"),
    audit: t("nav.audit"),
  });
  const userMenu = adminUserMenu({account: t("userMenu.account"), logout: t("userMenu.logout")});

  return (
    <AdminShellFrame nav={nav} userMenu={userMenu} defaultSidebarOpen={defaultSidebarOpen}>
      {children}
    </AdminShellFrame>
  );
}
