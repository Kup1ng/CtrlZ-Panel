"use client";

import {Button, Calendar, Description, Label, TimeField} from "@heroui/react";
import {TIME_ZONE} from "@ctrlz/i18n/locale.ts";
import {getLocalTimeZone, Time, today, type CalendarDate} from "@internationalized/date";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {expiryProblem, joinDateTime, MAX_EXPIRY_DAYS, splitDateTime} from "./dateTime.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// A month grid and a clock for one date and time (the expiry of a rule, T-184). In `fa` the grid is Jalali, with Persian digits and
// the week starting on Saturday, because the page's `I18nProvider` (providers/AppProviders.tsx) gives React Aria `fa-IR-u-ca-persian`;
// nothing here picks a calendar. The value is a JS `Date`, an instant; the grid and the clock show it in Iran's zone.
//
// The picked date is kept apart from the clock until Apply, so a half-chosen value is never sent: choosing a day alone keeps the clock
// that the value had (12:00 for a new one) and enables Apply. A date that is past, or more than a year ahead, cannot be chosen: the
// grid's `minValue` and `maxValue` are today and today plus a year, and a time that makes it past the same day is told under the
// clock in words. The API decides last.

export type DateTimePickerProps = {
  /** The instant now, or `null` for none. */
  value: Date | null;
  /** Called with the new instant on Apply, or `null` on Clear. */
  onApply: (value: Date | null) => void;
  /** Names the grid: "Expiry of example.com". */
  label: string;
  /** The reader of the clock. Tests pass a fixed one. */
  now?: () => Date;
  onCancel?: () => void;
};

export function DateTimePicker({value, onApply, label, now = () => new Date(), onCancel}: DateTimePickerProps) {
  const t = useTranslations("common");
  const r = useTranslations("rules");
  const start = value ? splitDateTime(value, TIME_ZONE) : null;
  const [date, setDate] = useState<CalendarDate | null>(start?.date ?? null);
  const [time, setTime] = useState<Time | null>(start?.time ?? new Time(12, 0));
  const current = now();
  const zone = TIME_ZONE;
  const todayDate = today(zone ?? getLocalTimeZone());
  const picked = date && time ? joinDateTime(date, time, zone) : null;
  const problem = picked ? expiryProblem(picked, current) : null;

  return (
    <div className="flex flex-col gap-3">
      <Calendar
        aria-label={`${t("calendar.date")}: ${label}`}
        value={date}
        onChange={(d) => setDate(d as CalendarDate | null)}
        minValue={todayDate}
        maxValue={todayDate.add({days: MAX_EXPIRY_DAYS})}
      >
        <Calendar.Header>
          <Calendar.YearPickerTrigger className="min-h-6">
            <Calendar.YearPickerTriggerHeading />
            <Calendar.YearPickerTriggerIndicator />
          </Calendar.YearPickerTrigger>
          <Calendar.NavButton slot="previous" aria-label={t("calendar.previous")} />
          <Calendar.NavButton slot="next" aria-label={t("calendar.next")} />
        </Calendar.Header>
        <Calendar.Grid weekdayStyle="narrow">
          <Calendar.GridHeader>{(day) => <Calendar.HeaderCell>{day}</Calendar.HeaderCell>}</Calendar.GridHeader>
          <Calendar.GridBody>{(d) => <Calendar.Cell date={d} />}</Calendar.GridBody>
        </Calendar.Grid>
        <Calendar.YearPickerGrid>
          <Calendar.YearPickerGridBody>{({year}) => <Calendar.YearPickerCell year={year} />}</Calendar.YearPickerGridBody>
        </Calendar.YearPickerGrid>
      </Calendar>

      <TimeField aria-label={`${t("calendar.time")}: ${label}`} value={time} onChange={setTime} hourCycle={24} granularity="minute">
        <Label>{t("calendar.time")}</Label>
        <TimeField.Group>
          {/* A segment is a target of its own: at least 24px each way (WCAG 2.5.8), or the hour and the minute sit too close to be told apart by touch. */}
          <TimeField.Input>{(segment) => <TimeField.Segment segment={segment} className="inline-flex min-h-6 min-w-6 items-center justify-center" />}</TimeField.Input>
        </TimeField.Group>
        {problem ? <Description className="text-danger-soft-foreground">{r(problem === "past" ? "expiry.past" : "expiry.tooFar")}</Description> : null}
      </TimeField>

      <div className="flex items-center justify-between gap-2">
        <Button size="sm" variant="ghost" onPress={() => onApply(null)}>
          {t("calendar.clear")}
        </Button>
        <div className="flex items-center gap-2">
          {onCancel ? (
            <Button size="sm" variant="tertiary" onPress={onCancel}>
              {t("cancel")}
            </Button>
          ) : null}
          <PrimaryButton size="sm" isDisabled={!picked || problem !== null} onPress={() => picked && onApply(picked)}>
            {t("calendar.apply")}
          </PrimaryButton>
        </div>
      </div>
    </div>
  );
}
