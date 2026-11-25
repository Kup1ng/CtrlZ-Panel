"use client";

import {AppLayout, Sidebar, useSidebar} from "@heroui-pro/react";
import {useTranslations} from "next-intl";
import {useMemo, useState, type ReactNode} from "react";

import {useShellShortcuts} from "../hooks/useShellShortcuts.ts";
import {useDirection} from "../hooks/useLogicalEdge.ts";
import {BannerStack} from "./BannerStack.tsx";
import {BellDialog} from "./Bell.tsx";
import {JumpPalette} from "./JumpPalette.tsx";
import {LogoutDialog} from "./LogoutDialog.tsx";
import {MobileBar} from "./MobileBar.tsx";
import type {NavItem} from "./nav.ts";
import {SectionHelp} from "./SectionHelp.tsx";
import {SessionGate} from "./SessionGate.tsx";
import {ShellSidebar} from "./ShellSidebar.tsx";
import {ShellUiContext, type ShellUi} from "./shellContext.tsx";

// Spec 8.1. AppLayout makes its own Sidebar.Provider, so there is none of ours.
// `scrollMode="content"` keeps the shell still and scrolls the main column, which
// sticky page headers and virtual lists need.

/**
 * Lives inside AppLayout because useSidebar needs its provider.
 *
 * The Sidebar's own mod+b reads `event.key`, and on a Persian layout the B key
 * types "ذ", so it never fires there (measured: a keydown with key "ذ" and code
 * "KeyB" does nothing, a real Ctrl+B on a Latin layout works). AppShell therefore
 * passes toggleShortcut={false} and binds the physical key here.
 */
function ShellKeys({openPalette}: {openPalette: () => void}) {
  const {toggleSidebar} = useSidebar();
  useShellShortcuts({toggleSidebar, openPalette});
  return null;
}

// AppLayout does not write the cookie on its own (measured: no sidebar_state
// after a toggle, although the docs say the provider does), so the shell does.
// It is a preference, not a secret, and the server reads it for the first paint.
function writeSidebarCookie(open: boolean) {
  try {
    document.cookie = `sidebar_state=${open}; Path=/; Secure; SameSite=Lax; Max-Age=31536000`;
  } catch {
    // Cookies blocked: the sidebar still toggles, it just does not persist.
  }
}

export type AppShellProps = {
  nav: NavItem[];
  /** From the `sidebar_state` cookie, read on the server, so a collapsed sidebar does not flash open (T-114). */
  defaultSidebarOpen: boolean;
  /** The admin's user menu (spec 13): a node of the app, shown at the foot of the sidebar in both the desktop and the mobile panel. */
  userMenu?: ReactNode;
  children: ReactNode;
};

// The app (panel or admin) is not a prop: it comes from AppProviders, which each app's layout feeds (wp4-r5-9).
export function AppShell({nav, defaultSidebarOpen, userMenu, children}: AppShellProps) {
  const c = useTranslations("common");
  const dir = useDirection();
  const [logoutOpen, setLogoutOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(defaultSidebarOpen);

  const ui = useMemo<ShellUi>(
    () => ({openLogout: () => setLogoutOpen(true), openPalette: () => setPaletteOpen(true)}),
    [],
  );

  return (
    <ShellUiContext.Provider value={ui}>
      <div className="shell">
        <a className="skip-link" href="#main-content">
          {c("skipToContent")}
        </a>
        <BannerStack />
        <AppLayout
          // The sidebar sits at the inline start of the row, which is the right in RTL (8.2).
          sidebarSide={dir === "rtl" ? "right" : "left"}
          sidebarVariant="sidebar"
          sidebarCollapsible="icon"
          sidebarOpen={sidebarOpen}
          onSidebarOpenChange={(open) => {
            setSidebarOpen(open);
            writeSidebarCookie(open);
          }}
          toggleShortcut={false}
          scrollMode="content"
          navbar={<MobileBar />}
          sidebar={
            <>
              <ShellSidebar nav={nav} userMenu={userMenu} />
              <Sidebar.Mobile backdrop="opaque">
                <ShellSidebar nav={nav} userMenu={userMenu} mobile />
              </Sidebar.Mobile>
            </>
          }
        >
          <ShellKeys openPalette={ui.openPalette} />
          <SessionGate>
            <div id="main-content" tabIndex={-1} className="shell-page">
              {children}
            </div>
          </SessionGate>
        </AppLayout>
        <BellDialog />
        <SectionHelp />
        <LogoutDialog isOpen={logoutOpen} onOpenChange={setLogoutOpen} />
        <JumpPalette nav={nav} isOpen={paletteOpen} onOpenChange={setPaletteOpen} />
      </div>
    </ShellUiContext.Provider>
  );
}
