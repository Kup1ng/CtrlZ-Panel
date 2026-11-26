"use client";

import type {NavItem} from "../../shell/nav.ts";
import {AppShell} from "../../shell/AppShell.tsx";
import {FreshTotpProvider} from "../../auth/FreshTotpDialog.tsx";
import {useState, type ReactNode} from "react";

import type {AdminUserMenuItem} from "./userMenu.ts";
import {AdminAccountDialog} from "./AdminAccountDialog.tsx";
import {AdminUserMenu} from "./AdminUserMenu.tsx";
import {useSetupRedirect} from "./useSetupRedirect.ts";

// The client half of the admin shell. It holds what the server layout cannot: the state of the Account dialog (a
// state-only Modal, spec 13) and the fresh-TOTP provider that every write page runs its calls through (11.3).
// Both sit above the shell, so the idle cover of AppProviders unmounts them with everything else and a half-typed
// password never outlives the page.

export function AdminShellFrame({
  nav,
  userMenu,
  defaultSidebarOpen,
  children,
}: {
  nav: NavItem[];
  userMenu: AdminUserMenuItem[];
  defaultSidebarOpen: boolean;
  children: ReactNode;
}) {
  const [accountOpen, setAccountOpen] = useState(false);
  // Any 403 `setup_required` from any call of any page goes to /setup (spec 11.2).
  useSetupRedirect();
  return (
    <FreshTotpProvider>
      <AppShell
        nav={nav}
        defaultSidebarOpen={defaultSidebarOpen}
        userMenu={<AdminUserMenu items={userMenu} onAccount={() => setAccountOpen(true)} />}
      >
        {children}
      </AppShell>
      <AdminAccountDialog isOpen={accountOpen} onClose={() => setAccountOpen(false)} />
    </FreshTotpProvider>
  );
}
