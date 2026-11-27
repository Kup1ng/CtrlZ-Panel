"use client";

import {isLocale, localeAutonym, locales, type Locale} from "@ctrlz/i18n/locale.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Description, Dropdown, Header, Label} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import type {Key} from "react-aria-components";

import {useLocaleSwitch} from "../shell/localeSwitch.ts";
import type {ThemeMode} from "../theme/config.ts";
import {useTheme} from "../theme/useTheme.ts";

// The language and the theme of a page with no shell and no session (the share page). The language is a full load of the same address
// (localeSwitch.ts), and a share link spends a use each time it is opened, so the other language says so under its name. The theme is
// the one controller of FE 5.1 and costs nothing.

const THEME_ICON = {light: "sun", dark: "moon", system: "system"} as const;
const THEME_MODES = ["light", "dark", "system"] as const satisfies readonly ThemeMode[];

export function ShareCorner() {
  const t = useTranslations("setup");
  const c = useTranslations("common");
  const locale = useLocale();
  const switchLocale = useLocaleSwitch();
  const {mode, setMode} = useTheme();

  return (
    <Dropdown>
      <Button isIconOnly variant="ghost" aria-label={t("share.corner")}>
        <Icon name="language" className="size-5" />
      </Button>
      <Dropdown.Popover placement="bottom end" className="min-w-56">
        <Dropdown.Menu aria-label={t("share.corner")}>
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
                <div className="flex min-w-0 flex-col gap-0.5">
                  <Label>{localeAutonym[l]}</Label>
                  {l !== locale ? <Description>{t("share.languageUse")}</Description> : null}
                </div>
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
