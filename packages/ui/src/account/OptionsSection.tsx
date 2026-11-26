"use client";

import {updatePreferences} from "@ctrlz/api-client/hooks/preferences.ts";
import type {Me} from "@ctrlz/api-client/session.ts";
import {isLocale, type Locale} from "@ctrlz/i18n/locale.ts";
import {toast} from "@heroui/react";
import {Segment, CellSwitch} from "@heroui-pro/react";
import {useQueryClient} from "@tanstack/react-query";
import {useLocale, useTranslations} from "next-intl";
import {useState, useSyncExternalStore} from "react";

import {useErrorText} from "../feedback/errorText.ts";
import {hapticsEnabled, setHapticsEnabled} from "../hooks/useHaptics.ts";
import {useLocaleSwitch} from "../shell/localeSwitch.ts";
import {parseThemeMode} from "../theme/config.ts";
import {useTheme} from "../theme/useTheme.ts";
import {AccountSection, SettingRow} from "./AccountSection.tsx";
import {HomeCountries} from "./HomeCountries.tsx";

// Spec 12.6 (T-307 to T-311, T-310): the options, each applied the moment it is changed (there is no Save).
//
//   Theme       the one theme store; the shell writes the choice to the account (`onThemeModeChange`)
//   Hints       `PATCH /account/preferences {onboarding_hints: {enabled}}`
//   Haptic      this device only (localStorage), and only where the pointer is coarse (a touch screen)
//   Language    a full load into the other language (spec 4.2), saved to the account on the way
//   Home        up to three countries, section HomeCountries

const COARSE = "(pointer: coarse)";

function subscribeCoarse(notify: () => void) {
  const query = matchMedia(COARSE);
  query.addEventListener("change", notify);
  return () => query.removeEventListener("change", notify);
}

export function OptionsSection({me}: {me: Me}) {
  const t = useTranslations("account");
  const c = useTranslations("common");
  const queryClient = useQueryClient();
  const errorText = useErrorText();
  const locale = useLocale();
  const switchLocale = useLocaleSwitch();
  const {mode, setMode} = useTheme();
  const coarse = useSyncExternalStore(
    subscribeCoarse,
    () => matchMedia(COARSE).matches,
    () => false,
  );
  const [haptic, setHaptic] = useState(() => hapticsEnabled());
  const hints = me.user.onboarding_hints.enabled;

  async function setHints(enabled: boolean) {
    try {
      await updatePreferences(queryClient, {onboarding_hints: {enabled}});
    } catch (error) {
      toast.danger(errorText(error));
    }
  }

  return (
    <AccountSection id="options" title={t("sections.options")}>
      <SettingRow
        id="theme"
        label={c("theme.label")}
        control={
          <Segment
            aria-label={c("theme.label")}
            selectedKey={mode}
            onSelectionChange={(key) => setMode(parseThemeMode(String(key)))}
          >
            <Segment.Item id="dark">{c("theme.dark")}</Segment.Item>
            <Segment.Item id="light">{c("theme.light")}</Segment.Item>
            <Segment.Item id="system">{c("theme.system")}</Segment.Item>
          </Segment>
        }
      />
      <CellSwitch aria-label={t("options.hints")} isSelected={hints} onChange={(next) => void setHints(next)}>
        <CellSwitch.Trigger>
          <CellSwitch.Label>{t("options.hints")}</CellSwitch.Label>
          <CellSwitch.Control />
        </CellSwitch.Trigger>
      </CellSwitch>
      {coarse ? (
        <CellSwitch
          aria-label={t("options.haptic")}
          isSelected={haptic}
          onChange={(next) => {
            setHaptic(next);
            setHapticsEnabled(next);
          }}
        >
          <CellSwitch.Trigger>
            <CellSwitch.Label>{t("options.haptic")}</CellSwitch.Label>
            <CellSwitch.Control />
          </CellSwitch.Trigger>
        </CellSwitch>
      ) : null}
      <SettingRow
        id="language"
        label={c("language.label")}
        control={
          <Segment
            aria-label={c("language.label")}
            selectedKey={locale}
            onSelectionChange={(key) => {
              const next = String(key);
              if (isLocale(next) && next !== locale) void switchLocale(next as Locale);
            }}
          >
            <Segment.Item id="fa">{c("language.fa")}</Segment.Item>
            <Segment.Item id="en">{c("language.en")}</Segment.Item>
          </Segment>
        }
      />
      <HomeCountries countries={me.tenant.home_countries} />
    </AccountSection>
  );
}
