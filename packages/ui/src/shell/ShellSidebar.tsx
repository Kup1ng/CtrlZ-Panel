"use client";

import {Button} from "@heroui/react";
import {Sidebar, useSidebar} from "@heroui-pro/react";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {usePathname} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

import {BellButton} from "./Bell.tsx";
import {LogoMenu} from "./LogoMenu.tsx";
import {groupsHolding, isCurrentPath, type NavAction, type NavGroup, type NavItem, type NavLink} from "./nav.ts";
import {useShellUi} from "./shellContext.tsx";
import {useShellCounts} from "./useShellCounts.ts";

// Spec 8.3. A React Aria Tree: every item has an id and a textValue, and the
// selection props are not used (the API table disallows them). The current page
// comes from the URL, with `isCurrent`.

export function ShellSidebar({nav, userMenu, mobile = false}: {nav: NavItem[]; userMenu?: ReactNode; mobile?: boolean}) {
  const t = useTranslations("shell");
  const pathname = usePathname();
  const counts = useShellCounts();
  const format = useAppFormat();
  const ui = useShellUi();
  const c = useTranslations("common");
  const {setMobileOpen} = useSidebar();

  function renderLink(item: NavLink) {
    const count = item.countKey ? counts?.[item.countKey] : undefined;
    return (
      <Sidebar.MenuItem
        key={item.id}
        id={item.id}
        href={item.href}
        isCurrent={isCurrentPath(pathname, item.href)}
        textValue={item.label}
      >
        <Sidebar.MenuIcon>
          <Icon name={item.icon} className="size-5" />
        </Sidebar.MenuIcon>
        <Sidebar.MenuLabel>{item.label}</Sidebar.MenuLabel>
        {count !== undefined ? <Sidebar.MenuChip>{format.number(count)}</Sidebar.MenuChip> : null}
      </Sidebar.MenuItem>
    );
  }

  function renderAction(item: NavAction) {
    return (
      <Sidebar.MenuItem key={item.id} id={item.id} textValue={item.label} onAction={() => ui.openLogout()}>
        <Sidebar.MenuIcon>
          <Icon name={item.icon} className="size-5" />
        </Sidebar.MenuIcon>
        <Sidebar.MenuLabel>{item.label}</Sidebar.MenuLabel>
      </Sidebar.MenuItem>
    );
  }

  function renderGroup(group: NavGroup) {
    return (
      <Sidebar.MenuItem key={group.id} id={group.id} textValue={group.label}>
        <Sidebar.MenuIcon>
          <Icon name={group.icon} className="size-5" />
        </Sidebar.MenuIcon>
        <Sidebar.MenuLabel>
          {group.label}
          <Sidebar.MenuTrigger>
            <Sidebar.MenuIndicator />
          </Sidebar.MenuTrigger>
        </Sidebar.MenuLabel>
        <Sidebar.Submenu>{group.items.map((i) => (i.kind === "link" ? renderLink(i) : renderAction(i)))}</Sidebar.Submenu>
      </Sidebar.MenuItem>
    );
  }

  const body = (
    <>
      <Sidebar.Header>
        <div className="shell-sidebar-brand">
          <LogoMenu />
          <div className="flex items-center gap-1">
            <BellButton />
            {/* A full-screen panel needs a way out that is not a menu choice. */}
            {mobile ? (
              <Button isIconOnly size="sm" variant="ghost" aria-label={c("close")} onPress={() => setMobileOpen(false)}>
                <Icon name="close" className="size-5" />
              </Button>
            ) : null}
          </div>
        </div>
      </Sidebar.Header>
      <Sidebar.Content>
        <Sidebar.Group>
          <Sidebar.Menu aria-label={t("nav.main")} defaultExpandedKeys={groupsHolding(nav, pathname)}>
            {nav.map((item) =>
              item.kind === "group" ? renderGroup(item) : item.kind === "link" ? renderLink(item) : renderAction(item),
            )}
          </Sidebar.Menu>
        </Sidebar.Group>
      </Sidebar.Content>
      {userMenu || !mobile ? (
        <Sidebar.Footer>
          {userMenu}
          {mobile ? null : <Sidebar.Trigger aria-label={t("sidebar.toggle")} />}
        </Sidebar.Footer>
      ) : null}
    </>
  );

  if (mobile) return body;
  return (
    <Sidebar>
      {body}
      <Sidebar.Rail />
    </Sidebar>
  );
}
