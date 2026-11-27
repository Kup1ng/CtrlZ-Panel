"use client";

import {Button} from "@heroui/react";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {useTranslations} from "next-intl";
import {useState, type ComponentProps} from "react";

import {DateTimePicker} from "../../calendar/DateTimePicker.tsx";
import {EXPIRY_SHORTCUTS} from "../../calendar/dateTime.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import type {ExpiryChoice} from "./rulesModel.ts";

// The expiry of a rule (spec p2 9.6, WF "Rules", T-184): the clock icon opens, inside the dialog, the four shortcuts (an hour, a day, a week,
// a month) and a calendar with a clock, in the person's calendar (Jalali in Persian). A shortcut is sent as `expires_in`, counted by the
// server's clock; a picked time as `expires_at`. "No expiry" clears it.

export type ExpiryFieldProps = {
  choice: ExpiryChoice;
  onChange: (choice: ExpiryChoice) => void;
  /** The expiry the rule has now (an edit, or a group edit's "keep"). */
  current?: string;
  /** Names the calendar: "Expiry of example.com". */
  subject: string;
  isDisabled?: boolean;
};

// A choice that is picked is the primary button of its row and the others stay quiet; both press like any other button, so a picked one
// gives the primary pulse of T-310 through PrimaryButton.
function ChoiceButton({selected, ...props}: Omit<ComponentProps<typeof Button>, "variant" | "size"> & {selected: boolean}) {
  return selected ? <PrimaryButton size="sm" {...props} /> : <Button size="sm" variant="secondary" {...props} />;
}

export function ExpiryField({choice, onChange, current, subject, isDisabled = false}: ExpiryFieldProps) {
  const t = useTranslations("rules");
  const format = useAppFormat();
  const [open, setOpen] = useState(false);
  const [calendar, setCalendar] = useState(false);

  const summary =
    choice.kind === "none"
      ? t("expiry.none")
      : choice.kind === "keep"
        ? current
          ? t("expiry.summary", {when: format.dateTime(current)})
          : t("expiry.none")
        : choice.kind === "shortcut"
          ? t(`expiry.in${choice.value}`)
          : t("expiry.summary", {when: format.dateTime(choice.at)});
  const has = choice.kind === "shortcut" || choice.kind === "at" || (choice.kind === "keep" && Boolean(current));
  const atValue = choice.kind === "at" ? choice.at : choice.kind === "keep" && current ? new Date(current) : null;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="secondary" isDisabled={isDisabled} aria-expanded={open} aria-label={t("expiry.open", {subject})} onPress={() => setOpen((v) => !v)}>
          <SubIcon group="rules" name="expiry" className="size-4" />
          {t("expiry.label")}
        </Button>
        <span className="text-sm" aria-live="polite">
          {summary}
        </span>
        {has ? (
          <Button isIconOnly size="sm" variant="ghost" isDisabled={isDisabled} aria-label={t("expiry.clear", {subject})} onPress={() => onChange({kind: "none"})}>
            <Icon name="close" className="size-4" />
          </Button>
        ) : null}
      </div>
      {open ? (
        <div className="bg-default/40 flex flex-col gap-3 p-3">
          <div role="group" aria-label={t("expiry.shortcutsLabel")} className="flex flex-wrap gap-2">
            {EXPIRY_SHORTCUTS.map((value) => (
              <ChoiceButton
                key={value}
                selected={choice.kind === "shortcut" && choice.value === value}
                aria-pressed={choice.kind === "shortcut" && choice.value === value}
                isDisabled={isDisabled}
                onPress={() => {
                  onChange({kind: "shortcut", value});
                  setCalendar(false);
                }}
              >
                {t(`expiry.in${value}`)}
              </ChoiceButton>
            ))}
            <ChoiceButton selected={calendar || choice.kind === "at"} aria-pressed={calendar} isDisabled={isDisabled} onPress={() => setCalendar((v) => !v)}>
              {t("expiry.pick")}
            </ChoiceButton>
          </div>
          {calendar ? (
            <DateTimePicker
              label={subject}
              value={atValue}
              onApply={(value) => {
                onChange(value ? {kind: "at", at: value} : {kind: "none"});
                setCalendar(false);
              }}
              onCancel={() => setCalendar(false)}
            />
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
