"use client";

import {Button, toast} from "@heroui/react";
import {errorMessageArgs, errorMessageKey} from "@ctrlz/api-client/errors.ts";
import {ItemCard} from "@heroui-pro/react";
import {useEndpointCount} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useOnboarding} from "@ctrlz/api-client/hooks/preferences.ts";
import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState} from "react";

import {ConfirmFrame} from "../dialog/ConfirmFrame.tsx";

// T-119, T-309, spec 8.12. The first-run checklist at the top of /profiles.
//
// Steps 1 to 4 are FACTS derived from API data as phases deliver it (a profile
// exists, a filter is on, ...). They are never stored, or they would drift. Only
// `dismissed_at` and `tutorial_seen_at` live on the server, in
// users.onboarding_state.

export type OnboardingFacts = {
  createProfile: boolean;
  enableFilter: boolean;
  addEndpoint: boolean;
  configureEndpoint: boolean;
};

/**
 * The four facts, from the tenant's own data (T-119). They are read, never stored: a profile exists, a filter is on in one of them, an Endpoint
 * exists, and an Endpoint has been configured (it has seen a query: `status` is `active`). The profile list and the one-row Endpoint read are the
 * queries the sidebar's counters use, so the card adds no request of its own. While an answer has not come, or has failed, its fact is false: the
 * card shows a step to do, which is the safe side, and the person can skip it.
 */
export function useOnboardingFacts(): OnboardingFacts {
  const profiles = useProfiles().data;
  const endpoints = useEndpointCount().data;
  return {
    createProfile: (profiles?.length ?? 0) > 0,
    enableFilter: profiles?.some((p) => p.counts.filters > 0) ?? false,
    addEndpoint: (endpoints?.total ?? 0) > 0,
    configureEndpoint: (endpoints?.active ?? 0) > 0,
  };
}

/**
 * `onboarding_state` and `onboarding_hints.enabled` come with `Me`. `dismiss` is
 * PATCH /account/preferences {onboarding_state}, which replaces the whole object, so
 * the client sends all of it (spec 8.12).
 */
export function useOnboardingState() {
  return useOnboarding();
}

type StepId = keyof OnboardingFacts | "tutorial";

const STEPS: readonly {id: StepId; icon: GeneralIconName; href?: string}[] = [
  {id: "createProfile", icon: "profiles"},
  {id: "enableFilter", icon: "filters"},
  {id: "addEndpoint", icon: "endpoints", href: "/endpoints"},
  {id: "configureEndpoint", icon: "settings", href: "/endpoints"},
  // The tutorial is the docs (P7); no page to open yet. Its button appears with its target.
  {id: "tutorial", icon: "help"},
];

/**
 * The card goes once the dismissal is saved, and the Hide button that had focus goes with it, so focus
 * would fall to <body> and a keyboard or screen-reader user would start again from the top (spec 17.5).
 * It moves to the page region, which takes focus on purpose (tabIndex -1). Only when focus is nowhere,
 * on the card, or still in the confirm dialog (a portal, closing): a person who has moved on keeps where
 * they are. Called after the card has left the DOM, which is when focus is really lost.
 */
function keepFocusInPage() {
  const active = document.activeElement;
  if (active && active !== document.body && !active.closest(".onboarding, [role='alertdialog'], [role='dialog']")) return;
  document.getElementById("main-content")?.focus();
}

/**
 * `facts` is for the lab only (T-119): P1 has no profile or endpoint to count, so the checklist cannot show a done step on a real screen
 * until P2 and P3 fill `useOnboardingFacts`. The lab passes facts that are true, and the screens pass nothing.
 */
export function OnboardingCard({facts: given}: {facts?: OnboardingFacts} = {}) {
  const t = useTranslations("shell");
  const c = useTranslations("common");
  const e = useTranslations("errors");
  const format = useAppFormat();
  const router = useRouter();
  const own = useOnboardingFacts();
  const facts = given ?? own;
  const {hintsEnabled, dismissed, dismiss} = useOnboardingState();
  const [confirmOpen, setConfirmOpen] = useState(false);
  // Set when THIS card saved the dismissal, so that hiding it through Account (hints off) moves no focus.
  const savedHere = useRef(false);
  useEffect(() => {
    if (dismissed && savedHere.current) {
      savedHere.current = false;
      keepFocusInPage();
    }
  }, [dismissed]);

  // Hints off in Account hides the card without dismissing it.
  if (!hintsEnabled || dismissed) return null;

  const isDone = (id: StepId) => (id === "tutorial" ? false : facts[id]);
  const done = STEPS.filter((s) => isDone(s.id)).length;

  return (
    <section className="onboarding" aria-labelledby="onboarding-title">
      <div className="onboarding__head">
        <div className="min-w-0 flex-1">
          <h2 id="onboarding-title" className="text-base font-semibold">
            {t("onboarding.title")}
          </h2>
          <p className="text-muted text-sm">
            {t("onboarding.progress", {done: format.number(done), total: format.number(STEPS.length)})}
          </p>
        </div>
        <Button size="sm" variant="ghost" onPress={() => setConfirmOpen(true)}>
          {t("onboarding.dismiss")}
        </Button>
      </div>

      <div className="onboarding__steps">
        {STEPS.map((step) => {
          const stepDone = isDone(step.id);
          return (
            <ItemCard key={step.id}>
              <ItemCard.Icon>
                {stepDone ? <Icon name="check" className="text-success-soft-foreground size-5" /> : <Icon name={step.icon} className="size-5" />}
              </ItemCard.Icon>
              <ItemCard.Content>
                <ItemCard.Title>{t(`onboarding.steps.${step.id}.title`)}</ItemCard.Title>
                <ItemCard.Description>{t(`onboarding.steps.${step.id}.text`)}</ItemCard.Description>
              </ItemCard.Content>
              {/* Done is a check and a word, never colour alone. */}
              {stepDone ? (
                <ItemCard.Action>
                  <span className="text-success-soft-foreground text-sm">{t("onboarding.done")}</span>
                </ItemCard.Action>
              ) : step.href ? (
                <ItemCard.Action>
                  <Button size="sm" variant="outline" onPress={() => router.push(step.href!)}>
                    {t("onboarding.start")}
                  </Button>
                </ItemCard.Action>
              ) : null}
            </ItemCard>
          );
        })}
      </div>

      <ConfirmFrame
        isOpen={confirmOpen}
        onOpenChange={setConfirmOpen}
        status="warning"
        title={t("onboarding.confirm.title")}
        footer={
          <>
            <Button slot="close" variant="tertiary">
              {c("cancel")}
            </Button>
            <Button
              variant="danger"
              onPress={async () => {
                setConfirmOpen(false);
                savedHere.current = true;
                try {
                  await dismiss();
                } catch (error) {
                  savedHere.current = false;
                  // The card stays, so say why instead of leaving a rejection nobody reads.
                  toast.danger(e(errorMessageKey(error), errorMessageArgs(error)));
                }
              }}
            >
              {t("onboarding.confirm.action")}
            </Button>
          </>
        }
      >
        <p>{t("onboarding.confirm.text")}</p>
      </ConfirmFrame>
    </section>
  );
}
