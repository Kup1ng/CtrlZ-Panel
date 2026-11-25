"use client";

import {freshUntil} from "@ctrlz/api-client/admin/fresh.ts";
import {useAdminSession} from "@ctrlz/api-client/admin/session.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Avatar, Button, Dropdown, Label} from "@heroui/react";
import {useSidebar} from "@heroui-pro/react";
import {Tech} from "../../data/Tech.tsx";
import {useShellUi} from "../../shell/shellContext.tsx";
import {useTranslations} from "next-intl";
import {useEffect, useState} from "react";

import type {AdminUserMenuItem} from "./userMenu.ts";

// Spec 13 and 11.3. A Dropdown on the username at the foot of the sidebar: Account and Log out. Under the name sits
// the small indicator of the fresh-TOTP window (`AdminMe.fresh_until`): while it is open, the writes that need a
// code do not ask for one. The indicator is text with a time, never a colour alone, and it goes away by itself when
// the window ends, since nothing refetches `/me` at that moment.

/** How often the menu reads the clock again. Under the minute of slack that `freshUntil` allows a stale reading. */
const CLOCK_MS = 15_000;

/** The end of the window while it is open. A timer re-renders at the end, so the line does not outlive the window. */
function useFreshWindow(freshUntilText: string | undefined): Date | undefined {
  const [now, setNow] = useState(() => Date.now());
  const end = freshUntil({fresh_until: freshUntilText}, now);
  const endMs = end?.getTime();
  // The clock is read again every few seconds, so a window that `/me` has just opened is not judged by a stale `now`, and
  // once more at the moment the open window ends, so the line goes away on time.
  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), CLOCK_MS);
    return () => clearInterval(tick);
  }, []);
  useEffect(() => {
    if (endMs === undefined) return;
    const timer = setTimeout(() => setNow(Date.now()), Math.max(0, endMs - Date.now()) + 50);
    return () => clearTimeout(timer);
  }, [endMs]);
  return end;
}

export function AdminUserMenu({items, onAccount}: {items: AdminUserMenuItem[]; onAccount: () => void}) {
  const t = useTranslations("admin");
  const format = useAppFormat();
  const {me, status} = useAdminSession();
  const ui = useShellUi();
  const {setMobileOpen} = useSidebar();
  const fresh = useFreshWindow(me?.fresh_until);

  // Nothing to show before `/me` answers, and nothing in the setup state, which has no shell.
  if (status !== "ready" || !me) return null;

  const initial = [...me.username][0]?.toUpperCase() ?? "?";

  return (
    <Dropdown>
      <Button variant="ghost" className="admin-user-trigger" aria-label={t("userMenu.label", {name: me.username})}>
        <Avatar size="sm">
          <Avatar.Fallback>{initial}</Avatar.Fallback>
        </Avatar>
        <span className="admin-user-text" data-sidebar="label">
          <span className="admin-user-name">
            <Tech mono={false}>{me.username}</Tech>
          </span>
          {fresh ? <span className="admin-user-fresh">{t("userMenu.freshUntil", {time: format.time(fresh)})}</span> : null}
        </span>
      </Button>
      <Dropdown.Popover placement="top start" className="min-w-56">
        <Dropdown.Menu
          aria-label={t("userMenu.menuLabel")}
          onAction={(key) => {
            // The mobile panel is a full-screen sheet: it closes first, or the dialog would open behind it.
            setMobileOpen(false);
            if (key === "account") onAccount();
            else if (key === "logout") ui.openLogout();
          }}
        >
          {items.map((item) => (
            <Dropdown.Item key={item.id} id={item.id} textValue={item.label} variant={item.id === "logout" ? "danger" : undefined}>
              <Icon name={item.icon} className="size-4 shrink-0" />
              <Label>{item.label}</Label>
            </Dropdown.Item>
          ))}
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  );
}
