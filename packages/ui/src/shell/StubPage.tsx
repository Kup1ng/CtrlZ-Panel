"use client";

import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";
import {useTranslations} from "next-intl";

import {OnboardingCard} from "./OnboardingCard.tsx";
import {PageHeader} from "./PageHeader.tsx";
import type {HelpKey} from "./SectionHelp.tsx";

// Spec 8.9. The page of a later phase: its header and a neutral "not available
// yet". T-113 needs the route to exist. Each stub has one owner phase, which
// replaces the page file.

export function StubPage({
  icon,
  title,
  subtitle,
  helpKey,
  withOnboarding = false,
}: {
  icon: GeneralIconName;
  title: string;
  subtitle: string;
  helpKey: HelpKey;
  /** The first-run checklist sits at the top of /profiles (spec 8.12). */
  withOnboarding?: boolean;
}) {
  const t = useTranslations("shell");
  return (
    <>
      <PageHeader icon={icon} title={title} subtitle={subtitle} helpKey={helpKey} />
      {withOnboarding ? <OnboardingCard /> : null}
      <SectionEmpty icon={icon} title={t("stub.title")} description={t("stub.text")} />
    </>
  );
}
