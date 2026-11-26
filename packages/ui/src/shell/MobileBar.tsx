"use client";

import {AppLayout, Navbar} from "@heroui-pro/react";
import {Logo} from "@ctrlz/icons/generated/brand/Logo.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import {BellButton} from "./Bell.tsx";

// WF has no top bar on desktop, only a header per page. This bar exists for the
// mobile hamburger, and shell.css hides it from 48rem (spec 8.1).

export function MobileBar() {
  const t = useTranslations("shell");
  const c = useTranslations("common");
  return (
    <Navbar maxWidth="full" height="3.5rem" aria-label={t("nav.main")}>
      <Navbar.Header>
        <AppLayout.MenuToggle aria-label={t("sidebar.openMenu")}>
          <Icon name="menu" className="size-5" />
        </AppLayout.MenuToggle>
        <Navbar.Brand className="flex items-center gap-2">
          <Logo aria-hidden className="shell-logo" />
          <span className="text-sm font-semibold">{c("appName")}</span>
        </Navbar.Brand>
        <Navbar.Spacer />
        <BellButton />
      </Navbar.Header>
    </Navbar>
  );
}
