"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useDisableProfile, useEnableProfile, type Profile} from "@ctrlz/api-client/hooks/profiles.ts";
import {sessionGuard} from "@ctrlz/api-client/sessionEnd.ts";
import {Button, Switch, ToggleButton, ToggleButtonGroup, toast} from "@heroui/react";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useEffect, useState} from "react";

import {DateTimePicker} from "../../calendar/DateTimePicker.tsx";
import {useErrorText} from "../../feedback/errorText.ts";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {OptionRow} from "./OptionRow.tsx";
import {DISABLE_CHOICES, disableBody, freshUntil, isDisabledNow, type DisableChoice, type OptionRow as RowName} from "./optionModel.ts";

// Disable (T-138): stop the profile for 5 minutes, 1 hour, 1 day or until a date, with a switch. The choice is made first and the switch
// applies it: turning the switch on sends `PUT /disabled` with `for` or `until`, turning it off sends `DELETE`. While the profile is
// disabled the choice is shown, as words, and cannot change; the end of the pause is written out. Disable is a guarded write
// (`x-ctrlz-lock: guard`), so a locked profile shows it and cannot change it.
//
// "Disabled" is read from `disabled_until` against the clock, and a timer turns the switch off by itself at that moment, so a page left open
// does not say "disabled" after the profile is back.

export function DisableRow({profile, readOnly, onLearnMore}: {profile: Profile; readOnly: boolean; onLearnMore: (name: RowName) => void}) {
  const t = useTranslations("rules");
  const format = useAppFormat();
  const errorText = useErrorText();
  const disable = useDisableProfile();
  const enable = useEnableProfile();
  const title = t("options.rows.disable.name");
  const [choice, setChoice] = useState<DisableChoice>("1h");
  const [customUntil, setCustomUntil] = useState<Date | null>(null);
  // Did this page start the pause that is on? The choice group shows a choice only then: on a profile that was disabled elsewhere (another
  // tab, a phone, before a reload) the choice is not known, and a made-up "1 hour" beside another end time would contradict the row (S2-r1-4).
  const [appliedHere, setAppliedHere] = useState(false);
  const [picking, setPicking] = useState(false);
  const [missing, setMissing] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const until = profile.disabled_until;
  const on = isDisabledNow(until, now);
  const pending = disable.isPending || enable.isPending;
  const pickText = customUntil ? t("options.disable.picked", {when: format.dateTime(customUntil)}) : t("options.disable.pick");
  const [wasOn, setWasOn] = useState(on);
  if (on !== wasOn) {
    setWasOn(on);
    if (!on) setAppliedHere(false);
  }
  // The profile got locked while the date picker was open: the picker goes with it, and does not come back by itself when it is unlocked (S2-r2-6).
  const [wasReadOnly, setWasReadOnly] = useState(readOnly);
  if (readOnly !== wasReadOnly) {
    setWasReadOnly(readOnly);
    if (readOnly) {
      setPicking(false);
      setMissing(false);
    }
  }

  // The moment the pause ends, the row reads the clock again. A timer cannot wait more than about 24.8 days, so a longer pause is waited
  // out in parts: each time the clock is read, `now` changes and this runs again for what is left (S2-r3-4).
  useEffect(() => {
    if (!until) return;
    const wait = Date.parse(until) - Date.now();
    if (!Number.isFinite(wait) || wait <= 0) return;
    const timer = window.setTimeout(() => setNow(Date.now()), Math.min(wait + 250, 2_147_000_000));
    return () => window.clearTimeout(timer);
  }, [until, now]);

  async function toggle(next: boolean) {
    // An answer that comes after the session ended is not the present person's: it sets no state and shows no toast (S2-r2-7).
    const alive = sessionGuard();
    try {
      if (next) {
        // A custom date that has passed since it was picked is asked for again, with the same words as a date that was never picked.
        const date = freshUntil(customUntil, Date.now());
        if (customUntil && !date) setCustomUntil(null);
        const body = disableBody(choice, date);
        if (body === null) {
          setMissing(true);
          setPicking(true);
          return;
        }
        await disable.mutateAsync({id: profile.id, ...body});
        if (!alive()) return;
        setAppliedHere(true);
        setNow(Date.now());
      } else {
        await enable.mutateAsync(profile.id);
        if (!alive()) return;
        setNow(Date.now());
      }
    } catch (error) {
      if (!alive()) return;
      if (!isHandledError(error) && !hasCode(error, "profile_locked")) toast.danger(`${t("options.failed", {name: title})} ${errorText(error)}`);
    }
  }

  return (
    <OptionRow
      name="disable"
      title={title}
      description={t("options.rows.disable.description")}
      onLearnMore={onLearnMore}
      control={
        <>
          <span data-testid="disable-state" className="text-muted text-xs">
            {on ? t("options.disable.on") : t("options.disable.idle")}
          </span>
          <Switch isSelected={on} isDisabled={readOnly} isReadOnly={pending} aria-label={title} onChange={(next) => void toggle(next)}>
            <Switch.Content>
              <Switch.Control>
                <Switch.Thumb />
              </Switch.Control>
            </Switch.Content>
          </Switch>
        </>
      }
    >
      {on && until ? (
        <p className="text-sm" role="status" data-testid="disable-until">
          {t("options.disable.until", {when: format.dateTime(until)})}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <ToggleButtonGroup
          aria-label={`${title}: ${t("options.disable.group")}`}
          selectionMode="single"
          disallowEmptySelection
          size="sm"
          isDisabled={readOnly || on}
          selectedKeys={on && !appliedHere ? [] : [choice]}
          onSelectionChange={(keys) => {
            const next = [...keys][0];
            if (typeof next !== "string" || !(DISABLE_CHOICES as readonly string[]).includes(next)) return;
            setChoice(next as DisableChoice);
            setMissing(false);
            setPicking(next === "custom" && customUntil === null);
          }}
        >
          {DISABLE_CHOICES.map((id, index) => (
            <ToggleButton key={id} id={id} aria-label={`${t(`options.disable.choice.${id}`)}: ${title}`}>
              {index > 0 ? <ToggleButtonGroup.Separator /> : null}
              {t(`options.disable.choice.${id}`)}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
        {choice === "custom" && !on ? (
          <Button size="sm" variant="outline" isDisabled={readOnly} aria-expanded={picking} aria-label={`${pickText}: ${title}`} onPress={() => setPicking((p) => !p)}>
            <Icon name="calendar" className="size-4" />
            {pickText}
          </Button>
        ) : null}
      </div>
      {missing ? (
        <p role="alert" className="text-sm text-(--danger-text)">
          {t("options.disable.pickFirst")}
        </p>
      ) : null}
      {choice === "custom" && picking && !on && !readOnly ? (
        <div className="max-w-sm" data-testid="disable-picker">
          <DateTimePicker
            value={customUntil}
            label={t("options.disable.pickLabel", {name: title})}
            onApply={(date) => {
              setCustomUntil(date);
              setPicking(false);
              setMissing(false);
            }}
            onCancel={() => setPicking(false)}
          />
        </div>
      ) : null}
    </OptionRow>
  );
}
