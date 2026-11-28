"use client";

import {Button, Checkbox, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {SelectField, type Choice} from "../fields.tsx";
import {CELLS_PER_DAY, cellOfDay, pairOf, repair, reshape, runAt, slotOf, type Run, type Slot} from "./scheduleModel.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// The two small dialogs over the grid of a Schedule (spec p3 10): the editor of one window, and Copy day. Neither writes to the server: they
// change the week the screen holds, and "Save schedule" sends it (Plan: Save schedule is separate from Save of the Endpoint).

export type ProfileChoice = {id: string; name: string; locked: boolean};

type EditorProps = {
  run: Run;
  cells: readonly Slot[];
  profiles: readonly ProfileChoice[];
  /** The names of the days, in the order the grid draws them. */
  days: readonly {day: number; name: string}[];
  /** The label of a time: row 0 is "00:00", and row 48 is "24:00". */
  timeLabel: (row: number) => string;
  onChange: (cells: Slot[], run: Run) => void;
  onRemove: () => void;
  onClose: () => void;
};

/** The editor of the window the person selected: its start, end and profiles, a way to remove it, and Close. */
export function WindowEditor({run, cells, profiles, days, timeLabel, onChange, onRemove, onClose}: EditorProps) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const [error, setError] = useState<string | null>(null);
  const pair = pairOf(run.slot);

  const startDay = Math.floor(run.from / CELLS_PER_DAY);
  const startRow = run.from % CELLS_PER_DAY;
  // The end is a boundary: 17:00 on a day is the boundary after row 33, and midnight is shown as 24:00 of the day that ends, not 00:00 of the next.
  const endDay = Math.floor((run.to - 1) / CELLS_PER_DAY);
  const endRow = ((run.to - 1) % CELLS_PER_DAY) + 1;

  const dayChoices: Choice[] = days.map((d) => ({id: String(d.day), label: d.name, textValue: d.name}));
  const startRows: Choice[] = Array.from({length: CELLS_PER_DAY}, (_, row) => ({id: String(row), label: timeLabel(row), textValue: timeLabel(row)}));
  const endRows: Choice[] = Array.from({length: CELLS_PER_DAY}, (_, i) => ({id: String(i + 1), label: timeLabel(i + 1), textValue: timeLabel(i + 1)}));
  const profileChoices: Choice[] = profiles.map((p) => ({id: p.id, label: p.locked ? t("dialogs.fields.profileLocked", {name: p.name}) : p.name, textValue: p.name}));
  const secondChoices: Choice[] = [{id: "", label: t("schedule.window.noSecond"), textValue: t("schedule.window.noSecond")}, ...profileChoices.filter((p) => p.id !== pair.profile_id)];

  function apply(from: number, to: number, slot: string) {
    const next = reshape(cells, run, from, to, slot);
    if (!next) {
      setError(to <= from ? t("schedule.window.endBeforeStart") : t("schedule.window.overlap"));
      return;
    }
    setError(null);
    // The grid may have merged the new range with a neighbour of the same pair: the selection is the run the grid now shows.
    onChange(next, runAt(next, from) ?? {from, to, slot});
  }

  const setPair = (profile_id: string, profile2_id: string) => {
    // Profile 2 has to differ from Profile 1: choosing the same one as the first drops the second.
    const second = profile2_id && profile2_id !== profile_id ? profile2_id : undefined;
    const slot = slotOf({profile_id, profile2_id: second});
    setError(null);
    const next = repair(cells, run, slot);
    onChange(next, runAt(next, run.from) ?? {...run, slot});
  };

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      title={t("schedule.window.title")}
      footer={
        <>
          <Button
            variant="danger-soft"
            aria-label={t("schedule.window.deleteAria")}
            onPress={() => {
              onRemove();
            }}
          >
            {t("schedule.window.delete")}
          </Button>
          <PrimaryButton onPress={onClose}>
            {c("done")}
          </PrimaryButton>
        </>
      }
    >
      <div className="flex flex-col gap-4" data-testid="window-editor">
        <fieldset className="flex flex-col gap-3">
          <legend className="text-muted mb-1 text-xs">{t("schedule.window.startGroup")}</legend>
          <div className="grid grid-cols-2 gap-3">
            <SelectField label={t("schedule.window.startDay")} options={dayChoices} value={String(startDay)} onChange={(v) => apply(cellOfDay(Number(v), startRow), run.to, run.slot)} />
            <SelectField label={t("schedule.window.startTime")} options={startRows} value={String(startRow)} onChange={(v) => apply(cellOfDay(startDay, Number(v)), run.to, run.slot)} />
          </div>
        </fieldset>
        <fieldset className="flex flex-col gap-3">
          <legend className="text-muted mb-1 text-xs">{t("schedule.window.endGroup")}</legend>
          <div className="grid grid-cols-2 gap-3">
            <SelectField label={t("schedule.window.endDay")} options={dayChoices} value={String(endDay)} onChange={(v) => apply(run.from, cellOfDay(Number(v), 0) + endRow, run.slot)} />
            <SelectField label={t("schedule.window.endTime")} options={endRows} value={String(endRow)} onChange={(v) => apply(run.from, cellOfDay(endDay, 0) + Number(v), run.slot)} />
          </div>
        </fieldset>
        <SelectField label={t("dialogs.fields.profile")} options={profileChoices} value={pair.profile_id} onChange={(v) => setPair(v, pair.profile2_id ?? "")} />
        <SelectField label={t("dialogs.fields.profileTwo")} options={secondChoices} value={pair.profile2_id ?? ""} onChange={(v) => setPair(pair.profile_id, v)} />
        {error ? (
          <p role="alert" className="text-danger-soft-foreground text-sm">
            {error}
          </p>
        ) : null}
      </div>
    </DialogFrame>
  );
}

/** Copy day: one day's cells replace the cells of the days ticked. Nothing is sent until the schedule is saved. */
export function CopyDayDialog({days, onApply, onClose}: {days: readonly {day: number; name: string}[]; onApply: (from: number, to: number[]) => void; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const [from, setFrom] = useState<number>(days[0]?.day ?? 0);
  const [to, setTo] = useState<number[]>([]);
  const targets = days.filter((d) => d.day !== from);
  const choices: Choice[] = days.map((d) => ({id: String(d.day), label: d.name, textValue: d.name}));
  const picked = to.filter((d) => d !== from);

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      title={t("schedule.copy.title")}
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>
            {c("cancel")}
          </Button>
          <PrimaryButton
            isDisabled={picked.length === 0}
            onPress={() => {
              onApply(from, picked);
              toast.success(t("schedule.copy.done"));
            }}
          >
            {t("schedule.copy.apply")}
          </PrimaryButton>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <SelectField label={t("schedule.copy.from")} options={choices} value={String(from)} onChange={(v) => setFrom(Number(v))} />
        <fieldset className="flex flex-col gap-2">
          <legend className="mb-1 text-sm font-medium">{t("schedule.copy.to")}</legend>
          {targets.map((d) => (
            <Checkbox
              key={d.day}
              name={`copy-to-${d.day}`}
              isSelected={to.includes(d.day)}
              onChange={(on) => setTo((prev) => (on ? [...prev, d.day] : prev.filter((x) => x !== d.day)))}
            >
              <Checkbox.Content>
                <Checkbox.Control>
                  <Checkbox.Indicator />
                </Checkbox.Control>
                <span className="text-sm">{d.name}</span>
              </Checkbox.Content>
            </Checkbox>
          ))}
          <Button size="sm" variant="ghost" className="self-start" onPress={() => setTo(targets.map((d) => d.day))}>
            {t("schedule.copy.all")}
          </Button>
        </fieldset>
        <p className="text-muted text-xs">{t("schedule.copy.note")}</p>
      </div>
    </DialogFrame>
  );
}
