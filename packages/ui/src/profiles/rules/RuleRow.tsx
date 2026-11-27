"use client";

import {buttonVariants, Switch} from "@heroui/react";
import type {Folder, Rule} from "@ctrlz/api-client/hooks/rules.ts";
import type {AppFormat} from "@ctrlz/i18n/format.ts";
import type {Target} from "@ctrlz/api-client/hooks/services.ts";
import {Flag} from "@ctrlz/icons/Flag.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {useTranslations} from "next-intl";
import {memo, useEffect, useRef, type CSSProperties, type ReactNode, type Ref} from "react";

import type {Action} from "../../controls/threeState.ts";
import {DenseRow} from "../../data/DenseRow.tsx";
import {Tech} from "../../data/Tech.tsx";
import {effectiveRuleAction, isGeoKind, parseAsn, parseGeo, recordsOf, ruleState} from "./rulesModel.ts";

// One rule of the Rules list (spec p2 9.6, WF "Rules", T-179, T-190, T-191): the action's icon or the flag of its country, the domain, the action
// in words, the A and AAAA capsules, and the switch at the end. Hover, or the keyboard focus, swaps the tags for Copy, Move, Edit and Delete; the
// delete is confirmed in the row, so there is no dialog for the one thing a pointer slip can do. On a touch screen there is no hover: a tap
// selects the row and its actions show in place of the tags (DenseRow), and in selection mode the bar above the list works on the selection.
//
// Marked states are in words with an icon, never in colour alone: the name acts as Bypass (`iranian_bypass`), the destination is not available
// (`location_unavailable`), the rule has expired, the rule is off.

const RECORD_A = "A";
const RECORD_AAAA = "AAAA";

export type RuleRowProps = {
  rule: Rule;
  place: {style: CSSProperties; index: number; count: number; setSize: number};
  compact: boolean;
  readOnly: boolean;
  selecting: boolean;
  selected: boolean;
  confirming: boolean;
  /** Draw the folder's name in the detail line (the list shows rules of every folder). */
  showFolder: boolean;
  folders: readonly Folder[];
  /** The instant the list was drawn at, so an expiry is judged the same for every row. */
  now: number;
  // One formatter and one namer for the whole list: `useAppFormat` builds about eight `Intl` objects, and a row that made its own would pay for
  // them every time the window brought it in (T-487: the budget is 100ms from the last scroll event).
  format: AppFormat;
  targetName: (target: Target | null | undefined) => string;
  onPress: (rule: Rule) => void;
  onSelect: (rule: Rule, selected: boolean) => void;
  onSwitch: (rule: Rule, enabled: boolean) => void;
  onCopy: (rule: Rule) => void;
  onMove: (rule: Rule) => void;
  onEdit: (rule: Rule) => void;
  onAskDelete: (rule: Rule) => void;
  /** The question of this rule is taken back (Escape, No, or the row leaving the window): the list clears it only if it is still this rule's. */
  onCancelDelete: (rule: Rule) => void;
  onConfirmDelete: (rule: Rule) => void;
};

/** What a rule is about, as words: its domain in `Tech`, or the Geo Rule said in a sentence. */
function useRuleSubject(format: AppFormat) {
  const t = useTranslations("rules");
  return (rule: Rule): {node: ReactNode; text: string} => {
    const geo = parseGeo(rule.pattern);
    if (geo) {
      const country = format.regionName(geo.country);
      const text = t(`row.geo.${geo.side}${geo.negated ? "Not" : ""}`, {country});
      return {text, node: text};
    }
    const asn = parseAsn(rule.pattern);
    if (asn) {
      const text = t(`row.geo.${asn.negated ? "asnNot" : "asn"}`, {number: asn.number});
      return {text, node: text};
    }
    return {text: rule.pattern, node: <Tech>{rule.pattern}</Tech>};
  };
}

/**
 * A button of the row. It is the HeroUI look on a native element: a window of 10,000 rules brings about twenty rows in at once, and a React Aria
 * `Button` (press, hover and focus hooks) on each of the six buttons of a row was the largest part of the 100ms budget of T-487.
 */
function RowButton({label, onClick, children, variant = "ghost", icon = true, buttonRef, className}: {label: string; onClick: () => void; children: ReactNode; variant?: "ghost" | "danger" | "tertiary"; icon?: boolean; buttonRef?: Ref<HTMLButtonElement>; className?: string}) {
  return (
    <button ref={buttonRef} type="button" aria-label={label} className={[buttonVariants({variant, size: "sm", isIconOnly: icon}), "max-sm:bg-default", className ?? ""].filter(Boolean).join(" ")} onClick={onClick}>
      {children}
    </button>
  );
}

function Leading({rule, action}: {rule: Rule; action: Action}) {
  const geo = parseGeo(rule.pattern);
  if (geo) return <SubIcon group="rules" name={geo.side === "dest" ? "geo-destination" : "geo-source"} className="size-5" />;
  if (isGeoKind(rule.match_kind)) return <SubIcon group="rules" name="geo-destination" className="size-5" />;
  const country = action === "redirect" && rule.target?.kind === "location" ? rule.target.location?.country : undefined;
  if (country) return <Flag code={country} />;
  if (action === "block" || action === "bypass" || action === "redirect") return <SubIcon group="rules" name={`action-${action}`} className="size-5" />;
  return <Icon name="rules" className="size-5" />;
}

function RuleRowView(props: RuleRowProps) {
  const {rule, place, compact, readOnly, selecting, selected, confirming, showFolder, folders, now, format, targetName, onPress, onSelect, onSwitch, onCopy, onMove, onEdit, onAskDelete, onCancelDelete, onConfirmDelete} = props;
  const t = useTranslations("rules");
  const subject = useRuleSubject(format);
  const keep = useRef<HTMLButtonElement>(null);

  // The press that asked "delete?" came from a button that goes away, so the focus goes to the safe answer.
  useEffect(() => {
    if (confirming) keep.current?.focus();
  }, [confirming]);

  // A row that leaves the window while it asks (the focus was elsewhere, so it was not kept drawn) takes the question with it: the list would
  // otherwise show it again, pinned, when the row is scrolled back. The latest values are read at that moment.
  const latest = useRef({confirming, rule, onCancelDelete});
  useEffect(() => {
    latest.current = {confirming, rule, onCancelDelete};
  });
  useEffect(
    () => () => {
      const now = latest.current;
      if (now.confirming) now.onCancelDelete(now.rule);
    },
    [],
  );

  const {text: name, node: title} = subject(rule);
  const acting = effectiveRuleAction(rule, folders);
  const state = ruleState(rule, new Date(now));
  const records = recordsOf(rule);
  const folder = rule.folder_id ? folders.find((f) => f.id === rule.folder_id) : undefined;
  const actionLabel = rule.action === "inherit" ? (acting === "inherit" ? t("action.inherit") : t("row.follows", {action: t(`action.${acting}`)})) : t(`action.${rule.action}`);

  const markers: {key: string; text: string}[] = [];
  if (rule.iranian_bypass) markers.push({key: "iranian", text: t("row.actsAsBypass")});
  if (rule.location_unavailable) markers.push({key: "unavailable", text: t("row.unavailable")});
  if (state === "expired") markers.push({key: "expired", text: t("row.expired")});
  else if (rule.expires_at) markers.push({key: "expires", text: t("row.expires", {when: format.dateTime(rule.expires_at)})});

  const detail = [
    acting === "redirect" && rule.target ? targetName(rule.target) : null,
    rule.comment ?? null,
    showFolder && folder ? t("row.inFolder", {folder: folder.name}) : null,
  ].filter((part): part is string => part !== null && part !== "");

  const stateText = state === "on" ? null : state === "expired" ? t("row.expired") : t("row.off");
  const stateChip = stateText === null ? null : <span className="text-muted border-border inline-flex items-center rounded-full border px-2 text-xs">{stateText}</span>;

  return (
    <DenseRow
      compact={compact}
      place={place}
      actionsPinned={confirming}
      // Escape of the row's own question only: one that closes a Select or a dialog is not for it (the focus is not in this row then, or it was handled).
      onKeyDown={confirming ? (event) => {
        if (event.key === "Escape" && !event.defaultPrevented) onCancelDelete(rule);
      } : undefined}
      leading={<Leading rule={rule} action={acting} />}
      title={
        <span className="flex min-w-0 flex-col leading-tight">
          <span className="truncate text-sm">{title}</span>
          {/* The small view has one line from 640px up, where the tags say the action and the state. On a phone the tags are not drawn, so the
              second line stays in the small view too (it fits the 40px row), with the action, the state and the marks in words and no detail. */}
          <span className={["text-muted flex min-w-0 items-center gap-2 overflow-hidden whitespace-nowrap text-xs", compact ? "sm:hidden" : ""].filter(Boolean).join(" ")}>
            <span className="shrink-0 sm:hidden">{[stateText, actionLabel].filter(Boolean).join(" · ")}</span>
            {detail.length > 0 && !compact ? <span className="truncate">{detail.join(" · ")}</span> : null}
            {markers.map((m) => (
              <span key={m.key} className="inline-flex min-w-0 shrink-0 items-center gap-1 text-(--warning-text)" data-marker={m.key}>
                <Icon name={m.key === "expires" ? "calendar" : "warning"} className="size-3" />
                {m.text}
              </span>
            ))}
          </span>
        </span>
      }
      onPress={() => onPress(rule)}
      selection={selecting ? {isSelected: selected, onChange: (value) => onSelect(rule, value), label: t("row.select", {pattern: name})} : undefined}
      tags={
        <>
          {/* The small view from 640px up has no second line, so a marked state is one icon here, its words for a reader; on a phone the second line says them. */}
          {compact && markers.length > 0 ? (
            <span className="hidden items-center gap-1 text-xs text-(--warning-text) sm:inline-flex">
              <Icon name="warning" className="size-3.5" />
              <span className="sr-only">{markers.map((m) => m.text).join(", ")}</span>
            </span>
          ) : null}
          <span className="hidden items-center gap-2 sm:flex">
            {stateChip}
            <span className="text-muted text-xs">{actionLabel}</span>
            {records.a ? <span className="bg-default rounded-full px-2 text-xs">{RECORD_A}</span> : null}
            {records.aaaa ? <span className="bg-default rounded-full px-2 text-xs">{RECORD_AAAA}</span> : null}
          </span>
        </>
      }
      hoverActions={
        confirming && !readOnly ? (
          <span role="group" aria-label={t("row.confirmGroup", {pattern: name})} className="flex items-center gap-1">
            <span className="text-xs">{t("row.confirmDelete")}</span>
            <RowButton icon={false} variant="danger" label={t("row.confirmYesAria", {pattern: name})} onClick={() => onConfirmDelete(rule)}>
              {t("row.confirmYes")}
            </RowButton>
            <RowButton icon={false} variant="tertiary" buttonRef={keep} label={t("row.confirmNoAria", {pattern: name})} onClick={() => onCancelDelete(rule)}>
              {t("row.confirmNo")}
            </RowButton>
          </span>
        ) : (
          <>
            <RowButton className="max-sm:hidden" label={t("row.copy", {pattern: name})} onClick={() => onCopy(rule)}>
              <Icon name="copy" className="size-4" />
            </RowButton>
            {readOnly ? null : (
              <>
                <RowButton className="max-sm:hidden" label={t("row.move", {pattern: name})} onClick={() => onMove(rule)}>
                  <Icon name="move" className="size-4" />
                </RowButton>
                <RowButton label={t("row.edit", {pattern: name})} onClick={() => onEdit(rule)}>
                  <Icon name="edit" className="size-4" />
                </RowButton>
                <RowButton className="max-sm:hidden" label={t("row.delete", {pattern: name})} onClick={() => onAskDelete(rule)}>
                  <Icon name="trash" className="size-4" />
                </RowButton>
              </>
            )}
          </>
        )
      }
      trailing={
        <Switch isSelected={rule.enabled} isDisabled={readOnly} onChange={(enabled) => onSwitch(rule, enabled)} aria-label={t("row.switch", {pattern: name})}>
          <Switch.Content>
            <Switch.Control>
              <Switch.Thumb />
            </Switch.Control>
          </Switch.Content>
        </Switch>
      }
    />
  );
}

// A write replaces the pages, so `rule` is a new object only for the row it changed; the handlers are the same functions for the life of the list.
const same = (a: RuleRowProps, b: RuleRowProps) =>
  a.rule === b.rule &&
  a.place.index === b.place.index &&
  a.place.count === b.place.count &&
  a.place.setSize === b.place.setSize &&
  a.compact === b.compact &&
  a.readOnly === b.readOnly &&
  a.selecting === b.selecting &&
  a.selected === b.selected &&
  a.confirming === b.confirming &&
  a.showFolder === b.showFolder &&
  a.folders === b.folders &&
  a.now === b.now &&
  a.format === b.format &&
  a.targetName === b.targetName &&
  a.onPress === b.onPress &&
  a.onSelect === b.onSelect &&
  a.onSwitch === b.onSwitch &&
  a.onCopy === b.onCopy &&
  a.onMove === b.onMove &&
  a.onEdit === b.onEdit &&
  a.onAskDelete === b.onAskDelete &&
  a.onCancelDelete === b.onCancelDelete &&
  a.onConfirmDelete === b.onConfirmDelete;

export const RuleRow = memo(RuleRowView, same);
