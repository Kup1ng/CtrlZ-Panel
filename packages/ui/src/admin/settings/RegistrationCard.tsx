"use client";

import {
  GRACE_DAYS_DEFAULT,
  GRACE_DAYS_MAX,
  GRACE_DAYS_MIN,
  registrationQueryOptions,
  useRegistration,
  useRegistrationImpact,
  useSaveRegistration,
  type RegistrationMode,
  type RegistrationSettings,
} from "@ctrlz/api-client/admin/hooks/settings.ts";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {Button, Card, Skeleton, toast} from "@heroui/react";
import {Segment} from "@heroui-pro/react";
import {SectionError} from "../../feedback/SectionError.tsx";
import {ConflictNote} from "../shared/ConflictNote.tsx";
import {IntegerField} from "../shared/IntegerField.tsx";
import {LiveStatus} from "../shared/LiveStatus.tsx";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerDraft} from "../shared/useServerDraft.ts";
import {ImpactFailed} from "./ImpactFailed.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useId, useRef, useState} from "react";
import {useTranslations} from "next-intl";
import {keepFocus, keepRetry} from "../shared/restoreFocus.ts";

// Spec 13.4, T-331. The registration mode. Picking a mode does not change anything: it opens a draft, and the draft shows
// what the change would do (`GET /settings/registration/impact?to=`: how many unproven claims get a grace period and
// how many are suspended at once) BEFORE the admin confirms. Confirming is `PUT /settings/registration`, which needs the
// fresh TOTP window; the dialog opens and the call is repeated once (`useCheckedWrite`). `open_grace_days` is asked
// only when the draft is `open`, inside the API's bounds (1 to 365).

const MODES: readonly RegistrationMode[] = ["closed", "invite", "open"];

type Value = {mode: RegistrationMode; days: number};
const valueOf = (settings: RegistrationSettings): Value => ({mode: settings.mode, days: graceOf(settings)});
const sameValue = (a: Value, b: Value) => a.mode === b.mode && a.days === b.days;
/** The grace length the field starts from: the server's, or the default when the server holds none. */
const graceOf = (settings: RegistrationSettings): number => (settings.open_grace_days >= GRACE_DAYS_MIN ? settings.open_grace_days : GRACE_DAYS_DEFAULT);

export function RegistrationCard() {
  const t = useTranslations("admin");
  const registration = useRegistration();
  return (
    <Card className="gap-4 p-6" data-testid="settings-registration">
      <Card.Header className="flex flex-col gap-1">
        <Card.Title className="text-base">{t("settings.registration.title")}</Card.Title>
        <Card.Description>{t("settings.registration.text")}</Card.Description>
      </Card.Header>
      <Card.Content>
        {registration.isPending ? (
          <Skeleton className="h-24 w-full rounded-(--radius-box)" />
        ) : !registration.data ? (
          <SectionError error={registration.error} onRetry={keepRetry(() => registration.refetch())} />
        ) : (
          <>
            <RefreshFailed error={registration.error} onRetry={() => registration.refetch()} />
            <Editor current={registration.data} />
          </>
        )}
      </Card.Content>
    </Card>
  );
}

function Editor({current}: {current: RegistrationSettings}) {
  const t = useTranslations("admin");
  // A number on screen goes through the page's formatter, so Persian digits show in fa; only what is sent is ASCII (spec 4.4, wp10-r7-3).
  const format = useAppFormat();
  const save = useSaveRegistration();
  // The read, the fresh-code dialog and the PUT are one pending state (wp10-r7-2, wp10-r7-5).
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm();
  const labelId = useId();
  const [draft, setDraft] = useState<RegistrationMode | null>(null);
  // The grace length follows the server when the field is untouched (wp10-r3-3).
  const {draft: days, setDraft: setDays, saved: savedDays, conflict: daysChanged, serverValue: serverDays, keepMine: keepDays, reset: takeServerDays} = useServerDraft<number | undefined>(
    graceOf(current),
  );
  // The mode the server held when the admin picked a mode, and the one they answered a change of it for (wp10-r5-3): if another
  // admin changed the mode after that, applying this admin's pick would undo it, so the card says so and waits for an answer.
  const [pickedFrom, setPickedFrom] = useState<RegistrationMode | null>(null);
  const [answeredFor, setAnsweredFor] = useState<RegistrationMode | null>(null);
  // Another admin set the very mode this admin picked (wp10-r6-3): there is nothing left to change, and a Confirm would ask for a fresh
  // code and write an audit row for a no-op. The pick is done, so the card returns to showing the server's mode. Adjusted while
  // rendering, as useServerDraft does, so no frame shows the impact of a change that has already happened.
  if (draft !== null && draft === current.mode) {
    setDraft(null);
    setPickedFrom(null);
    setAnsweredFor(null);
  }
  const modeChanged = draft !== null && pickedFrom !== null && current.mode !== pickedFrom && draft !== current.mode && answeredFor !== current.mode;
  const conflicted = modeChanged || (draft === "open" && daysChanged);
  const busy = useRef(false);
  const impact = useRegistrationImpact(draft ?? undefined);
  const shown = draft ?? current.mode;

  async function confirm() {
    if (busy.current || form.blocked || draft === null || conflicted) return;
    // The numbers are what the admin agrees to: a Retry of a failed save and Enter come here without the button, and a count
    // that failed to refresh (TanStack keeps the old data and sets the error) is not a count the page shows (wp10-r3-6).
    if (impact.isPending || impact.error || !impact.data) return;
    if (draft === "open" && (days === undefined || !Number.isInteger(days) || days < GRACE_DAYS_MIN || days > GRACE_DAYS_MAX)) {
      return form.setFieldError("open_grace_days", t("settings.registration.graceRange", {min: GRACE_DAYS_MIN, max: GRACE_DAYS_MAX}));
    }
    busy.current = true;
    form.clear();
    try {
      // The page does not refetch while it stays open, so the mode and the grace days this write replaces are read before every
      // try of it, the one after the fresh-code dialog included (wp10-r6-5, wp10-r7-5). A mode another admin changed shows as the
      // conflict note (modeChanged), and nothing is sent.
      const written = await write({options: registrationQueryOptions(), pick: valueOf, seen: valueOf(current), same: sameValue}, () =>
        save.mutateAsync({mode: draft, ...(draft === "open" ? {open_grace_days: days} : {})}),
      );
      if (!written) return;
      if (draft === "open") savedDays(days);
      toast.success(t("settings.registration.saved"));
      setDraft(null);
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void confirm()}>
      <div className="flex flex-col gap-1.5">
        <span id={labelId} className="text-sm font-medium">
          {t("settings.registration.mode.label")}
        </span>
        <Segment
          aria-labelledby={labelId}
          selectedKey={shown}
          isDisabled={pending}
          onSelectionChange={(key) => {
            form.clear();
            setDraft(key === current.mode ? null : (key as RegistrationMode));
            // Choosing again is an answer: the admin has the current mode in front of them.
            setPickedFrom(current.mode);
          }}
        >
          {MODES.map((mode) => (
            <Segment.Item key={mode} id={mode}>
              {t(`settings.registration.mode.${mode}`)}
            </Segment.Item>
          ))}
        </Segment>
        <p className="text-muted text-sm">{t(`settings.registration.modeText.${shown}`)}</p>
      </div>

      {draft !== null ? (
        <div className="flex flex-col gap-4" data-testid="registration-draft">
          {modeChanged ? (
            <ConflictNote
              name="mode"
              value={t(`settings.registration.mode.${current.mode}`)}
              onKeep={() => setAnsweredFor(current.mode)}
              onUseServer={() => {
                setDraft(null);
                form.clear();
              }}
            />
          ) : null}
          {draft === "open" ? (
            <IntegerField
              name="open_grace_days"
              label={t("settings.registration.grace")}
              description={t("settings.registration.graceHint", {min: GRACE_DAYS_MIN, max: GRACE_DAYS_MAX})}
              value={days}
              onChange={(value) => {
                setDays(value);
                form.clearField("open_grace_days");
              }}
              min={GRACE_DAYS_MIN}
              max={GRACE_DAYS_MAX}
              isDisabled={pending}
              error={form.fieldMessage("open_grace_days")}
              invalidMessage={t("settings.registration.graceRange", {min: GRACE_DAYS_MIN, max: GRACE_DAYS_MAX})}
              className="max-w-64"
            />
          ) : null}
          {draft === "open" && daysChanged ? (
            <ConflictNote
              name="open_grace_days"
              value={serverDays === undefined ? "" : format.number(serverDays, {useGrouping: false})}
              onKeep={keepDays}
              onUseServer={() => {
                takeServerDays();
                form.clearField("open_grace_days");
              }}
            />
          ) : null}

          {/* The impact is shown before the button that applies it. It is asked for the draft, never cached across drafts. */}
          <LiveStatus className="bg-surface-secondary flex flex-col gap-1 rounded-(--radius-box) p-4 text-sm" testId="registration-impact">
            <span className="font-medium">{t("settings.registration.impact.title", {mode: t(`settings.registration.mode.${draft}`)})}</span>
            {impact.isPending ? (
              <span className="text-muted">{t("settings.impactLoading")}</span>
            ) : impact.error || !impact.data ? (
              <ImpactFailed onRetry={() => impact.refetch()} />
            ) : (
              <>
                <span data-testid="impact-graced">{t("settings.registration.impact.graced", {count: impact.data.graced})}</span>
                <span data-testid="impact-suspended">
                  {t("settings.registration.impact.suspended", {count: impact.data.suspended_at_once})}
                </span>
              </>
            )}
          </LiveStatus>

          <FormError error={form.formError} onRetry={() => keepFocus(() => confirm())} />
          <OfflineNotice />
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="tertiary" isDisabled={pending} onPress={() => keepFocus(() => setDraft(null))}>
              {t("settings.cancel")}
            </Button>
            <Button
              type="submit"
              variant="primary"
              isPending={pending}
              // The numbers are what the admin agrees to, so the button waits for them.
              isDisabled={impact.isPending || !impact.data || impact.error !== null || conflicted || form.retryIn > 0}
            >
              {form.retryIn > 0 ? t("settings.retryIn", {seconds: form.retryIn}) : t("settings.registration.confirm", {mode: t(`settings.registration.mode.${draft}`)})}
            </Button>
          </div>
        </div>
      ) : null}
    </AuthForm>
  );
}
