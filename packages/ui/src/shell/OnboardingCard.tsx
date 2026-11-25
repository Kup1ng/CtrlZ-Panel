"use client";

import {AlertDialog, Button} from "@heroui/react";
import {ItemCard} from "@heroui-pro/react";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";
import {useTranslations} from "next-intl";
import {useCallback, useState} from "react";

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

/** P1 has no profile or endpoint to count, so every fact is false. P2 and P3 fill it from their queries. */
export function useOnboardingFacts(): OnboardingFacts {
  return {createProfile: false, enableFilter: false, addEndpoint: false, configureEndpoint: false};
}

/**
 * STUB until WP4 lands. The real state is `onboarding_state` and
 * `onboarding_hints.enabled` from GET /account/preferences, and `dismiss` is
 * PATCH /account/preferences {onboarding_state}, which replaces the whole
 * object, so the client sends all of it. Until then the dismissal lasts for this
 * page view only, and "Show hints" is always on.
 */
export function useOnboardingState() {
  const [dismissed, setDismissed] = useState(false);
  const dismiss = useCallback(async () => setDismissed(true), []);
  return {hintsEnabled: true, dismissed, dismiss};
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

export function OnboardingCard() {
  const t = useTranslations("shell");
  const c = useTranslations("common");
  const format = useAppFormat();
  const router = useRouter();
  const facts = useOnboardingFacts();
  const {hintsEnabled, dismissed, dismiss} = useOnboardingState();
  const [confirmOpen, setConfirmOpen] = useState(false);

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

      <AlertDialog.Backdrop isOpen={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialog.Container placement="center">
          <AlertDialog.Dialog className="sm:max-w-[400px]">
            <AlertDialog.CloseTrigger aria-label={c("close")} />
            <AlertDialog.Header>
              <AlertDialog.Icon status="warning" />
              <AlertDialog.Heading>{t("onboarding.confirm.title")}</AlertDialog.Heading>
            </AlertDialog.Header>
            <AlertDialog.Body>
              <p>{t("onboarding.confirm.text")}</p>
            </AlertDialog.Body>
            <AlertDialog.Footer>
              <Button slot="close" variant="tertiary">
                {c("cancel")}
              </Button>
              <Button
                variant="danger"
                onPress={async () => {
                  setConfirmOpen(false);
                  await dismiss();
                }}
              >
                {t("onboarding.confirm.action")}
              </Button>
            </AlertDialog.Footer>
          </AlertDialog.Dialog>
        </AlertDialog.Container>
      </AlertDialog.Backdrop>
    </section>
  );
}
