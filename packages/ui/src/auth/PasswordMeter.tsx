"use client";

import {Label, Meter} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useDeferredValue, useEffect, useMemo, useState} from "react";

import {hintFor, loadScorer, meterColor, meterValue, USER_RULE, type PasswordRule, type Scorer} from "./passwordStrength.ts";

// Spec 10, "PasswordMeter". Advisory only: it never blocks a submit and sends nothing (the scorer runs
// in the browser, passwordStrength.ts). It has a fixed height, so the form below does not jump when the
// first character appears. The level is also in a status region, which changes only when the level does.

export function PasswordMeter({
  password,
  userInputs = [],
  rule = USER_RULE,
  shortText,
}: {
  password: string;
  userInputs?: readonly string[];
  /** The admin app passes ADMIN_RULE (14 code points, score 4, AUTH 4.2). */
  rule?: PasswordRule;
  /** The line for a password under the rule minimum, when the generic one (which says 10) is not true for this rule. */
  shortText?: string;
}) {
  const t = useTranslations("auth");
  // Typing stays responsive: the scoring of the last keystroke may lag the field by a frame.
  const deferred = useDeferredValue(password);
  const [scorer, setScorer] = useState<Scorer | null>(null);
  const hasText = password.length > 0;

  useEffect(() => {
    if (!hasText || scorer) return;
    let live = true;
    loadScorer().then(
      (s) => live && setScorer(() => s),
      // No scorer (the chunk did not load): the length hint still works, and the server decides anyway.
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [hasText, scorer]);

  const inputsKey = userInputs.join("\u0000");
  const score = useMemo(
    () => (scorer && deferred ? scorer(deferred, inputsKey ? inputsKey.split("\u0000") : []) : null),
    [scorer, deferred, inputsKey],
  );

  const hint = hintFor(password, score, rule);
  const level = score === null ? null : t(`strength.level${score}`);

  return (
    <div className="flex min-h-[3.75rem] flex-col gap-1.5" data-testid="password-meter">
      {hasText ? (
        <Meter
          aria-label={t("strength.label")}
          value={score === null ? 0 : meterValue(score)}
          color={score === null ? "default" : meterColor(score)}
          size="sm"
          valueLabel={level ?? undefined}
        >
          <Label>{t("strength.label")}</Label>
          {/* No figure until the scorer has answered: the default would read "0%" for a password it has not looked at. */}
          {level === null ? null : <Meter.Output />}
          <Meter.Track>
            <Meter.Fill />
          </Meter.Track>
        </Meter>
      ) : null}
      {hint === "none" ? null : <p className="text-muted text-xs">{hint === "short" && shortText ? shortText : t(`strength.${hint}`)}</p>}
      <span role="status" className="sr-only">
        {level}
      </span>
    </div>
  );
}
