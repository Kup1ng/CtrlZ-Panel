"use client";

import {PageHeader} from "../../shell/PageHeader.tsx";
import {useTranslations} from "next-intl";

import {RegistrationCard} from "./RegistrationCard.tsx";
import {WebauthnCard} from "./WebauthnCard.tsx";

// Spec 13.4, T-331. Two sections, each a card with its own form: the registration mode and the Passkey configuration.
// Both writes are `admin-fresh`, and both show what they would change before they are confirmed. A column of at most
// the width of a settings form, so a wide screen does not stretch a field across it.
export function SettingsPage() {
  const t = useTranslations("admin");
  return (
    <>
      <PageHeader icon="settings" title={t("pages.settings.title")} subtitle={t("pages.settings.subtitle")} />
      <div className="flex max-w-3xl flex-col gap-6">
        <RegistrationCard />
        <WebauthnCard />
      </div>
    </>
  );
}
