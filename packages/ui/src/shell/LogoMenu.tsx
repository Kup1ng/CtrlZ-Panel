"use client";

import {Button, Dropdown, Header, Label} from "@heroui/react";
import {Logo} from "@ctrlz/icons/generated/brand/Logo.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {isLocale, localeAutonym, locales, type Locale} from "@ctrlz/i18n/locale.ts";
import {useLocale, useTranslations} from "next-intl";
import type {Key} from "react-aria-components";

import {useTheme} from "../theme/useTheme.ts";
import type {ThemeMode} from "../theme/config.ts";
import {useLocaleSwitch} from "./localeSwitch.ts";

// T-124. The logo is the menu trigger: version, language and theme. P3 adds
// Docs, Status, Request Feature and Contact (T-125).

const VERSION = process.env.NEXT_PUBLIC_CTRLZ_VERSION ?? "dev";

const THEME_ICON = {light: "sun", dark: "moon", system: "system"} as const;
const THEME_MODES = ["light", "dark", "system"] as const satisfies readonly ThemeMode[];

export function LogoMenu() {
  const t = useTranslations("shell");
  const c = useTranslations("common");
  const locale = useLocale();
  const switchLocale = useLocaleSwitch();
  const {mode, setMode} = useTheme();

  return (
    <Dropdown>
      <Button aria-label={t("logoMenu.label")} className="shell-logo-trigger" variant="ghost">
        <Logo aria-hidden className="shell-logo" />
        <span className="shell-logo-name" data-sidebar="label">
          {c("appName")}
        </span>
      </Button>
      <Dropdown.Popover placement="bottom start" className="min-w-56">
        <div className="text-muted px-3 pt-2 pb-1 text-xs">
          {t.rich("logoMenu.version", {version: VERSION, v: (chunks) => <bdi dir="ltr">{chunks}</bdi>})}
        </div>
        <Dropdown.Menu aria-label={t("logoMenu.label")}>
          <Dropdown.Section
            selectionMode="single"
            selectedKeys={[locale]}
            onSelectionChange={(keys) => {
              const next = [...keys][0] as Key | undefined;
              if (typeof next === "string" && isLocale(next) && next !== locale) void switchLocale(next as Locale);
            }}
          >
            <Header>{c("language.label")}</Header>
            {locales.map((l) => (
              <Dropdown.Item key={l} id={l} textValue={localeAutonym[l]}>
                <Icon name="language" className="text-muted size-4 shrink-0" />
                <Label>{localeAutonym[l]}</Label>
                <Dropdown.ItemIndicator />
              </Dropdown.Item>
            ))}
          </Dropdown.Section>
          <Dropdown.Section
            selectionMode="single"
            selectedKeys={[mode]}
            onSelectionChange={(keys) => {
              const next = [...keys][0];
              if (next === "light" || next === "dark" || next === "system") setMode(next);
            }}
          >
            <Header>{c("theme.label")}</Header>
            {THEME_MODES.map((m) => (
              <Dropdown.Item key={m} id={m} textValue={c(`theme.${m}`)}>
                <Icon name={THEME_ICON[m]} className="text-muted size-4 shrink-0" />
                <Label>{c(`theme.${m}`)}</Label>
                <Dropdown.ItemIndicator />
              </Dropdown.Item>
            ))}
          </Dropdown.Section>
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  );
}
