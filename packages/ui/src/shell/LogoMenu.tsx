"use client";

import {Button, Dropdown, Header, Label} from "@heroui/react";
import {Logo} from "@ctrlz/icons/generated/brand/Logo.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {isLocale, localeAutonym, locales, type Locale} from "@ctrlz/i18n/locale.ts";
import {useLocale, useTranslations} from "next-intl";
import {useState} from "react";
import type {Key} from "react-aria-components";
import type {FeedbackKind} from "@ctrlz/api-client/hooks/apiTokens.ts";

import {FeedbackDialog} from "./FeedbackDialog.tsx";
import {useTheme} from "../theme/useTheme.ts";
import type {ThemeMode} from "../theme/config.ts";
import {useLocaleSwitch} from "./localeSwitch.ts";
import {useApp} from "../providers/appContext.tsx";

// T-124, T-125. The logo is the menu trigger: version, Docs, Status, Request Feature and Contact, language and theme. Every destination is
// inside the product (spec p3 10): Docs and Status are pages of the panel, and the last two open the message dialog that posts `/feedback`.
// The admin console shares this menu but has none of those: no /docs or /status route, and its API has no /feedback (spec p3 9.2 is the
// tenant panel only, and the panel client must never start on the admin host). So it holds the version, language and theme only (S8-r3-1).

// `||`, not `??`: a build that passed an empty --build-arg would otherwise show an empty version. The value comes from scripts/ctrlz-version.mjs.
const VERSION = process.env.NEXT_PUBLIC_CTRLZ_VERSION || "dev";

const THEME_ICON = {light: "sun", dark: "moon", system: "system"} as const;
const THEME_MODES = ["light", "dark", "system"] as const satisfies readonly ThemeMode[];

export function LogoMenu() {
  const t = useTranslations("shell");
  const c = useTranslations("common");
  const locale = useLocale();
  const switchLocale = useLocaleSwitch();
  const {mode, setMode} = useTheme();
  const app = useApp();
  const [feedback, setFeedback] = useState<FeedbackKind | null>(null);

  return (
    <>
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
            {app === "panel" && (
              <Dropdown.Section aria-label={t("logoMenu.links")}>
                <Dropdown.Item id="docs" textValue={t("logoMenu.docs")} href="/docs">
                  <Icon name="help" className="text-muted size-4 shrink-0" />
                  <Label>{t("logoMenu.docs")}</Label>
                </Dropdown.Item>
                <Dropdown.Item id="status" textValue={t("logoMenu.status")} href="/status">
                  <Icon name="statistics" className="text-muted size-4 shrink-0" />
                  <Label>{t("logoMenu.status")}</Label>
                </Dropdown.Item>
                <Dropdown.Item id="feature" textValue={t("logoMenu.feature")} onAction={() => setFeedback("feature")}>
                  <Icon name="plus" className="text-muted size-4 shrink-0" />
                  <Label>{t("logoMenu.feature")}</Label>
                </Dropdown.Item>
                <Dropdown.Item id="contact" textValue={t("logoMenu.contact")} onAction={() => setFeedback("contact")}>
                  <Icon name="sms" className="text-muted size-4 shrink-0" />
                  <Label>{t("logoMenu.contact")}</Label>
                </Dropdown.Item>
              </Dropdown.Section>
            )}
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
      {app === "panel" && <FeedbackDialog kind={feedback} onClose={() => setFeedback(null)} />}
    </>
  );
}
