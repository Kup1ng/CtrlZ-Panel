"use client";

// /endpoints/[id]/schedule (spec p3 10, WF note of Plan "ویرایشگر Schedule", T-252 to T-254, T-488): the week of an Endpoint as a grid of
// 30-minute cells. A page and not a 440px dialog, because the grid needs the width (a recorded deviation, T-482).
//
// The week the person edits is a DRAFT held here (scheduleModel.ts); Copy day, Clear all and every window are changes of the draft, and
// "Save schedule" sends the whole set in one PUT (the server replaces the set). Save is separate from the Endpoint's own Save, as in the
// wireframe note. A locked profile in a window that the change takes away, or a destination that stops being available, asks in the
// state-only dialogs of useGuardedWrite.

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {usePutSchedule, useSchedule, useTimezones} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Alert, Button, ComboBox, FieldError, Input, Label, ListBox, Skeleton, toast} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import {useMemo, useRef, useState} from "react";

import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError} from "../forms/FormError.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {SectionError} from "../feedback/SectionError.tsx";
import {useEndpointFrame} from "./EndpointFrameContext.tsx";
import {CopyDayDialog, WindowEditor} from "./schedule/ScheduleDialogs.tsx";
import {ScheduleGrid, type GridLabels} from "./schedule/ScheduleGrid.tsx";
import {
  cellsOf,
  copyDay,
  dayOrder,
  defaultPair,
  emptyWeek,
  MAX_WINDOWS,
  paint,
  pairOf,
  removeRun,
  runAt,
  runsOf,
  sameWeek,
  slotOf,
  tooManyWindows,
  windowsOf,
  type Run,
  type Slot,
} from "./schedule/scheduleModel.ts";
import {Cancelled, useGuardedWrite} from "./useGuardedWrite.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

const DEFAULT_ZONE = "Asia/Tehran";

export function EndpointScheduleScreen({endpointId}: {endpointId: string}) {
  const {endpoint} = useEndpointFrame();
  const query = useSchedule(endpointId);
  if (query.isError && !query.data) return <SectionError error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return <ScheduleSkeleton />;
  // The editor is mounted once the schedule is read, and keyed by the server's copy of it: a save, or a change made in another tab and read
  // again, starts the draft over from what the server holds.
  const serverKey = `${query.data.timezone}|${query.data.windows.map((w) => `${w.start}-${w.end}-${w.profile_id}-${w.profile2_id ?? ""}`).join(",")}`;
  return <ScheduleEditor key={serverKey} endpointId={endpointId} endpoint={endpoint} schedule={query.data} />;
}

function ScheduleSkeleton() {
  const t = useTranslations("endpoints");
  return (
    <div data-screen="endpoint-schedule" role="status" aria-label={t("schedule.loading")} className="flex flex-col gap-3">
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-96 w-full" />
    </div>
  );
}

function ScheduleEditor({endpointId, endpoint, schedule}: {endpointId: string; endpoint: ReturnType<typeof useEndpointFrame>["endpoint"]; schedule: {timezone: string; windows: {start: number; end: number; profile_id: string; profile2_id?: string}[]}}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const locale = useLocale();
  const format = useAppFormat();
  const profiles = useProfiles();
  const zones = useTimezones();
  const put = usePutSchedule();
  const guarded = useGuardedWrite();
  const form = useApiForm({fieldNamespace: "profiles"});
  const busy = useRef(false);
  const [pending, setPending] = useState(false);

  const rtl = locale === "fa";
  const order = useMemo(() => dayOrder(rtl ? 6 : 0), [rtl]);
  const saved = useMemo(() => cellsOf(schedule.windows), [schedule.windows]);
  const [cells, setCells] = useState<Slot[]>(saved);
  const [zone, setZone] = useState(schedule.timezone || DEFAULT_ZONE);
  const [selected, setSelected] = useState<Run | null>(null);
  const [copyOpen, setCopyOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const profileList = useMemo(() => (profiles.data ?? []).map((p) => ({id: p.id, name: p.name, locked: p.locked})), [profiles.data]);
  const nameById = (id: string) => profileList.find((p) => p.id === id)?.name ?? "…";
  const nameOfSlot = (slot: string) => {
    const pair = pairOf(slot);
    return pair.profile2_id ? t("schedule.pairName", {first: nameById(pair.profile_id), second: nameById(pair.profile2_id)}) : nameById(pair.profile_id);
  };
  const toneOf = (slot: string) => Math.max(0, profileList.findIndex((p) => p.id === pairOf(slot).profile_id));

  const dirty = !sameWeek(cells, saved) || zone !== schedule.timezone;
  const windowCount = runsOf(cells).length;
  const hasCap = tooManyWindows(cells);

  const timeLabel = (row: number) => {
    const minutes = row * 30;
    const hh = Math.floor(minutes / 60);
    const mm = minutes % 60;
    const two = (n: number) => format.number(n, {minimumIntegerDigits: 2, useGrouping: false});
    return `${two(hh)}:${two(mm)}`;
  };
  const dayName = (day: number, kind: "long" | "short") => t(`schedule.days.${kind}.${day as 0 | 1 | 2 | 3 | 4 | 5 | 6}`);

  const labels: GridLabels = {
    grid: t("schedule.gridLabel", {name: endpoint.name}),
    dayShort: (d) => dayName(d, "short"),
    dayLong: (d) => dayName(d, "long"),
    time: timeLabel,
    hour: (row) => timeLabel(row),
    nameOf: nameOfSlot,
    cell: ({day, time, name, selected: isSelected, anchor}) =>
      [name ? t("schedule.cellWindow", {day, time, name}) : t("schedule.cellEmpty", {day, time}), isSelected ? t("schedule.cellSelected") : "", anchor ? t("schedule.cellStart") : ""].filter(Boolean).join(". "),
    announceStart: (a) => t("schedule.announceStart", a),
    announceCancelled: t("schedule.announceCancelled"),
    blocked: t("schedule.blocked"),
  };

  const base = {profile_id: endpoint.profile_id};
  const newSlot = () => slotOf(defaultPair(profileList.map((p) => p.id), base));

  function create(from: number, to: number) {
    if (windowCount >= MAX_WINDOWS) {
      setNotice(t("schedule.tooMany", {max: MAX_WINDOWS}));
      return;
    }
    const next = paint(cells, from, to, newSlot());
    if (!next) return;
    setNotice(null);
    setCells(next);
    // The new window opens in the editor, since it starts on a profile of the app's choosing and the person's next move is to pick one.
    setSelected(runAt(next, from));
  }

  const zoneOptions = useMemo(() => (zones.data ?? [DEFAULT_ZONE]).slice().sort((a, b) => a.localeCompare(b)), [zones.data]);
  const offsetText = (name: string) => {
    const minutes = format.utcOffset(name);
    if (minutes === null) return "";
    const sign = minutes < 0 ? "-" : "+";
    const abs = Math.abs(minutes);
    return `UTC${sign}${format.number(Math.floor(abs / 60), {useGrouping: false})}:${format.number(abs % 60, {minimumIntegerDigits: 2, useGrouping: false})}`;
  };

  async function save() {
    if (busy.current || form.blocked) return;
    if (hasCap) return setNotice(t("schedule.tooMany", {max: MAX_WINDOWS}));
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      const windows = windowsOf(cells);
      // The profiles of the new set and of the old one: a locked profile that a window leaves needs its password, and one that enters may too.
      const involved = [endpoint, ...schedule.windows, ...windows].map((w) => ({profile_id: w.profile_id, profile2_id: w.profile2_id}));
      await guarded.run((extra) => put.mutateAsync({id: endpointId, timezone: zone, windows, ...extra}), involved, {reset: put.reset});
      toast.success(t("schedule.saved"));
    } catch (error) {
      if (!(error instanceof Cancelled)) form.fail(error);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  const days = order.map((day) => ({day, name: dayName(day, "long")}));

  return (
    <div data-screen="endpoint-schedule" className="flex flex-col gap-4">
      <AuthForm form={form} onSubmit={() => void save()}>
        <div className="flex flex-wrap items-end gap-3">
          <ComboBox
            aria-label={t("schedule.tz.label")}
            variant="secondary"
            name="timezone"
            className="min-w-56 flex-1 sm:max-w-xs"
            isDisabled={pending}
            isInvalid={form.fieldMessage("timezone") !== undefined}
            defaultItems={zoneOptions.map((z) => ({id: z, name: z}))}
            selectedKey={zone}
            onSelectionChange={(key) => {
              if (key !== null) {
                form.clearField("timezone");
                setZone(String(key));
              }
            }}
            defaultFilter={(text, input) => normalizeFaSearch(text).toLowerCase().includes(normalizeFaSearch(input.trim()).toLowerCase())}
            menuTrigger="focus"
          >
            <Label>{t("schedule.tz.label")}</Label>
            <ComboBox.InputGroup>
              <Input placeholder={t("schedule.tz.placeholder")} />
              <ComboBox.Trigger />
            </ComboBox.InputGroup>
            <FieldError>{form.fieldMessage("timezone")}</FieldError>
            <ComboBox.Popover>
              <ListBox renderEmptyState={() => <p className="text-muted p-3 text-sm">{t("schedule.tz.empty")}</p>}>
                {(item: {id: string; name: string}) => (
                  <ListBox.Item id={item.id} textValue={item.name}>
                    <span dir="ltr" className="min-w-0 flex-1 truncate">
                      {item.name}
                    </span>
                    <span dir="ltr" className="text-muted text-xs tabular-nums">
                      {offsetText(item.name)}
                    </span>
                    <ListBox.ItemIndicator />
                  </ListBox.Item>
                )}
              </ListBox>
            </ComboBox.Popover>
          </ComboBox>
          <p className="text-muted pb-2 text-xs tabular-nums" data-testid="tz-offset">
            <span dir="ltr">{offsetText(zone)}</span>
          </p>
          <div className="ms-auto flex flex-wrap items-center gap-2">
            <Button size="sm" variant="outline" isDisabled={pending} onPress={() => setCopyOpen(true)}>
              {t("schedule.copy.button")}
            </Button>
            <Button size="sm" variant="outline" isDisabled={pending || windowCount === 0} aria-label={t("schedule.clearAria")} onPress={() => {
              setCells(emptyWeek());
              setSelected(null);
            }}>
              {t("schedule.clear")}
            </Button>
          </div>
        </div>

        <p className="text-muted text-sm">{t("schedule.hint")}</p>

        {notice ? (
          <Alert status="warning" role="status">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{notice}</Alert.Title>
            </Alert.Content>
          </Alert>
        ) : null}

        <ScheduleGrid
          cells={cells}
          order={order}
          labels={labels}
          selected={selected}
          toneOf={toneOf}
          isDisabled={pending}
          onSelect={setSelected}
          onCreate={create}
          onRemove={(run) => {
            setCells((prev) => removeRun(prev, run));
            setSelected(null);
          }}
        />

        <FormError error={form.formError} form={form} onRetry={() => void save()} message={hasCode(form.formError, "validation_failed") ? e("fields.invalid") : undefined} />

        <div className="bg-surface sticky bottom-0 z-20 flex flex-wrap items-center gap-2 py-2" data-testid="schedule-bar">
          <p className="text-muted me-auto text-sm" role="status">
            {dirty ? t("schedule.unsaved", {count: windowCount}) : windowCount === 0 ? t("schedule.none") : t("schedule.count", {count: windowCount})}
          </p>
          <Button
            variant="tertiary"
            isDisabled={!dirty || pending}
            onPress={() => {
              setCells(saved);
              setZone(schedule.timezone);
              setSelected(null);
              setNotice(null);
              form.clear();
            }}
          >
            {t("schedule.discard")}
          </Button>
          <PrimaryButton type="submit" isPending={pending} isDisabled={!dirty || form.retryIn > 0}>
            {t("schedule.save")}
          </PrimaryButton>
        </div>
      </AuthForm>

      {selected ? (
        // No key: the editor is a modal, so it always opens from "no selection", and a key on the start cell would remount it (and its focus)
        // each time the start day or time changes.
        <WindowEditor
          run={selected}
          cells={cells}
          profiles={profileList}
          days={days}
          timeLabel={timeLabel}
          onChange={(next, run) => {
            setCells(next);
            setSelected(run);
          }}
          onRemove={() => {
            setCells((prev) => removeRun(prev, selected));
            setSelected(null);
          }}
          onClose={() => setSelected(null)}
        />
      ) : null}
      {copyOpen ? (
        <CopyDayDialog
          days={days}
          onApply={(from, to) => {
            setCells((prev) => copyDay(prev, from, to));
            setSelected(null);
            setCopyOpen(false);
          }}
          onClose={() => setCopyOpen(false)}
        />
      ) : null}
      {guarded.dialogs}
    </div>
  );
}
