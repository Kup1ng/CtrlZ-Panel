"use client";

import {Button, buttonVariants} from "@heroui/react";
import type {ResolverView} from "@ctrlz/api-client/hooks/setup.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useEffect, useRef} from "react";

import {TechCopyRow} from "../data/TechCopyRow.tsx";
import {CopyBlock} from "./CopyBlock.tsx";
import {SecretCopyNote} from "./SecretCopyNote.tsx";
import {SECRET_VALUES, valueOf, type GuideVersion} from "./guide.ts";
import {SetupVerify} from "./SetupVerify.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// WF "Endpoints", the manual wizard: numbered steps with dots, Previous and Next (spec p3 8.3, T-242). One step is on screen; its number is
// in the address (`step`), so a reload, a link and the Back button all come back to it. The values a step shows are the Resolver view's,
// each with its Copy button, in the order the primary comes first (T-544); the step text never holds one itself.

export function Wizard({
  version,
  step,
  onStep,
  view,
  endpointId,
  plainDns = false,
  onDone,
}: {
  version: GuideVersion;
  /** 1-based, already within 1..steps. */
  step: number;
  onStep: (step: number) => void;
  view: ResolverView;
  /** Present for the owner: steps that send to the Addresses page get their button. The share page has no such page. */
  endpointId?: string;
  /** The Endpoint's Plain DNS switch (`legacy_dns`); false for the share page. Only with it on, and on a platform that uses the addresses, does the partial verify state talk of networks. */
  plainDns?: boolean;
  onDone: () => void;
}) {
  const t = useTranslations("setup");
  const c = useTranslations("common");
  const format = useAppFormat();
  const total = version.steps.length;
  const current = version.steps[step - 1]!;
  const heading = useRef<HTMLHeadingElement>(null);
  const first = useRef(true);
  // The address changes a moment after a press, and a second press in that moment would otherwise count from the old step and send the same
  // number again (two quick presses of Next moved one step). The step last asked for is the base of the next press; a render with the
  // address's own step puts it back (an effect: a ref is not written while rendering).
  const asked = useRef(step);
  useEffect(() => {
    asked.current = step;
  }, [step]);
  const go = (delta: number) => {
    const n = Math.min(total, Math.max(1, asked.current + delta));
    asked.current = n;
    onStep(n);
  };

  // The focus follows the step, so a keyboard or screen reader person lands on the new title and not on a button that just moved. Not on
  // the first render: opening the wizard keeps the focus where the dialog put it.
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    heading.current?.focus();
  }, [step]);

  return (
    <div className="flex flex-col gap-4" data-testid="wizard" data-step={step}>
      <ol aria-label={t("wizard.steps")} className="flex flex-wrap items-center justify-center gap-1">
        {version.steps.map((_, index) => {
          const n = index + 1;
          return (
            <li key={n}>
              <button
                type="button"
                aria-label={t("wizard.goto", {n: format.number(n), total: format.number(total)})}
                aria-current={n === step ? "step" : undefined}
                onClick={() => onStep(n)}
                className="focus-visible:ring-focus flex size-6 items-center justify-center rounded-full outline-none focus-visible:ring-2"
              >
                <span className={n === step ? "bg-accent size-2.5 rounded-full" : "bg-muted/40 size-2 rounded-full"} aria-hidden="true" />
              </button>
            </li>
          );
        })}
      </ol>

      <section aria-labelledby="wizard-step-title" className="flex flex-col gap-3">
        <h3 id="wizard-step-title" ref={heading} tabIndex={-1} className="flex items-start gap-2 text-base font-medium outline-none">
          <span className="bg-accent text-accent-foreground flex size-6 shrink-0 items-center justify-center rounded-full text-xs" aria-hidden="true">
            {format.number(step)}
          </span>
          <span>
            <span className="sr-only">{t("wizard.stepOf", {n: format.number(step), total: format.number(total)})}: </span>
            {current.title}
          </span>
        </h3>
        {/* The first step of the Plain DNS platforms sends the owner to claim the network; a visitor of a setup link cannot, and is told whose it is (S7-r2-4). */}
        <p className="text-sm">{current.link === "ips" && !endpointId ? t("wizard.shareClaim") : current.text}</p>

        {current.show?.map((key) => {
          const value = valueOf(view, key);
          if (!value) return null;
          const label = t(`wizard.values.${key}`);
          return key === "resolved_conf" ? (
            <CopyBlock key={key} label={label} text={value} secret={SECRET_VALUES.includes(key)} />
          ) : (
            <TechCopyRow key={key} label={label} value={value} secret={SECRET_VALUES.includes(key)} />
          );
        })}

        {current.show?.some((key) => SECRET_VALUES.includes(key) && valueOf(view, key)) ? <SecretCopyNote /> : null}

        {current.link === "ips" && endpointId ? (
          <Link href={`/endpoints/${endpointId}/ips?ipDialog=claim`} className={buttonVariants({variant: "secondary", size: "sm"})}>
            <Icon name="globe" className="size-4" />
            {t("wizard.openAddresses")}
          </Link>
        ) : null}

        {current.verify ? <SetupVerify view={view} endpointId={endpointId} plainDns={plainDns && version.steps.some((s) => s.link === "ips")} /> : null}
      </section>

      <div className="flex items-center justify-between gap-2">
        <Button variant="secondary" isDisabled={step <= 1} onPress={() => go(-1)}>
          <Icon name="chevron" className="size-4 rotate-180 rtl:rotate-0" />
          {t("wizard.previous")}
        </Button>
        {step < total ? (
          <PrimaryButton onPress={() => go(1)}>
            {t("wizard.next")}
            <Icon name="chevron" flip className="size-4" />
          </PrimaryButton>
        ) : (
          <PrimaryButton onPress={onDone}>
            {c("done")}
          </PrimaryButton>
        )}
      </div>
    </div>
  );
}
