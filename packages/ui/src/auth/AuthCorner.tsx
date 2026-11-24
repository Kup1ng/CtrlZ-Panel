"use client";

import {isLocale, localeAutonym, locales, type Locale} from "@ctrlz/i18n/locale.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Description, Dropdown, Header, Label} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import type {Key} from "react-aria-components";

import {useAuthBusy, useAuthHolding, useAuthHoldingFinishOnly} from "../forms/useAuthBusy.ts";
import {useLocaleSwitch} from "../shell/localeSwitch.ts";
import type {ThemeMode} from "../theme/config.ts";
import {useTheme} from "../theme/useTheme.ts";

// Spec 10: "language switch at the corner". The pages here have no shell, so no logo menu, and a
// visitor still needs both choices before signing in: the language (a full load, like the shell's)
// and the theme (the one controller of 5.1, which writes the cookie).

const THEME_ICON = {light: "sun", dark: "moon", system: "system"} as const;
const THEME_MODES = ["light", "dark", "system"] as const satisfies readonly ThemeMode[];

export function AuthCorner() {
  const t = useTranslations("auth");
  const c = useTranslations("common");
  const locale = useLocale();
  const switchLocale = useLocaleSwitch();
  // The language switch is a full page load: while a sign-in call runs its answer would open a session behind a
  // blank login page, so the languages wait for it (wp8-r9-6). The theme has no such cost.
  const busy = useAuthBusy();
  // A step that holds a ticket or a challenge would be lost by the reload, so the other language is off there too,
  // with the reason under it (wp8-r10-2).
  const holding = useAuthHolding();
  const finishOnly = useAuthHoldingFinishOnly();
  const {mode, setMode} = useTheme();

  return (
    <Dropdown>
      <Button isIconOnly variant="ghost" aria-label={t("corner.label")}>
        <Icon name="language" className="size-5" />
      </Button>
      <Dropdown.Popover placement="bottom end" className="min-w-52">
        <Dropdown.Menu aria-label={t("corner.label")}>
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
              <Dropdown.Item key={l} id={l} textValue={localeAutonym[l]} isDisabled={(busy || holding) && l !== locale}>
                {/* The reason sits under the name, not beside it. */}
                <div className="flex min-w-0 flex-col gap-0.5">
                  <Label>{localeAutonym[l]}</Label>
                  {holding && l !== locale ? <Description>{t(finishOnly ? "corner.languageHeldSetup" : "corner.languageHeld")}</Description> : null}
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
