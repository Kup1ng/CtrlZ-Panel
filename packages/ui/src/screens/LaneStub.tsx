"use client";

import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";
import {useTranslations} from "next-intl";

import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {StubPage} from "../shell/StubPage.tsx";
import type {HelpKey} from "../shell/SectionHelp.tsx";

// What a screen shows until its lane fills it. Every route of P2 and P3 has a page file that renders ONE component of a lane
// (`screens/lanes.ts` lists them), so a lane edits that component and no shared file. Until then the component is one of these, which
// carries `data-screen` for the page-level specs (routes.spec.ts finds the component by it) and says "not available yet".

/** A screen that has its own header (a list page, API tokens, Docs, Status). It keeps the look of the P1 stubs of spec 8.9. */
export function PageStub({screen, icon, title, subtitle, helpKey, withOnboarding = false}: {screen: string; icon: GeneralIconName; title: string; subtitle: string; helpKey: HelpKey; withOnboarding?: boolean}) {
  return (
    <div data-screen={screen}>
      <StubPage icon={icon} title={title} subtitle={subtitle} helpKey={helpKey} withOnboarding={withOnboarding} />
    </div>
  );
}

/** A screen under a frame, which already has the header and the tabs: only the empty state. */
export function FrameStub({screen, icon = "search"}: {screen: string; icon?: GeneralIconName}) {
  const t = useTranslations("shell");
  return (
    <div data-screen={screen}>
      <SectionEmpty icon={icon} title={t("stub.title")} description={t("stub.text")} />
    </div>
  );
}

/** A screen with no shell around it (the share page): a bare main with the empty state. */
export function BareStub({screen, title}: {screen: string; title: string}) {
  const t = useTranslations("shell");
  return (
    <main data-screen={screen} id="main-content" tabIndex={-1} className="mx-auto flex min-h-dvh w-full max-w-xl flex-col justify-center gap-4 px-4 py-8">
      <h1 className="sr-only">{title}</h1>
      <SectionEmpty icon="search" title={t("stub.title")} description={t("stub.text")} />
    </main>
  );
}
