"use client";

import {Button, Input, Label, TextField, ToggleButton, ToggleButtonGroup} from "@heroui/react";
import type {Folder} from "@ctrlz/api-client/hooks/rules.ts";
import {useProfileLocations} from "@ctrlz/api-client/hooks/profiles.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useTranslations} from "next-intl";
import {useState, type ReactNode} from "react";

import {ThreeStateControl} from "../../controls/ThreeStateControl.tsx";
import type {Action} from "../../controls/threeState.ts";
import {DestinationsFields, useDestinationDraft, useTargetName, withLocation} from "../../destinations/DestinationsDialog.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../../feedback/CapacityNotice.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {cleanProse} from "../../forms/invisible.ts";
import {TargetMark} from "../TargetMark.tsx";
import {ExpiryField} from "./ExpiryField.tsx";
import {MiniSelect} from "./MiniSelect.tsx";
import {COMMENT_MAX, editMembers, KEEP_ALL, type Change, type EditDraft, type ExpiryChoice} from "./rulesModel.ts";
import {useFormErrorText} from "./useFormErrorText.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// Spec p2 9.6, WF "Rules" (T-191): group Edit. Each of the action, the expiry, the folder and the comment is left as it is, set to a value, or
// cleared (the action cannot be cleared). Only what was chosen is sent, with the selection (ids, or the selector of the filter).

export type BatchEditDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  profileId: string;
  /** What is edited, in words: "12 rules". */
  subject: string;
  folders: readonly Folder[];
  onSubmit: (members: NonNullable<ReturnType<typeof editMembers>>) => Promise<unknown>;
};

export function BatchEditDialog({isOpen, ...rest}: BatchEditDialogProps) {
  return isOpen ? <BatchEditForm {...rest} /> : null;
}

function Section({title, mode, onMode, canClear, isDisabled, children}: {title: string; mode: Change<unknown>["mode"]; onMode: (mode: "keep" | "set" | "clear") => void; canClear: boolean; isDisabled: boolean; children: ReactNode}) {
  const t = useTranslations("rules");
  return (
    <div className="flex flex-col gap-2" data-section={title}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium">{title}</span>
        <ToggleButtonGroup
          aria-label={t("batchEdit.modeLabel", {field: title})}
          selectionMode="single"
          disallowEmptySelection
          size="sm"
          isDisabled={isDisabled}
          selectedKeys={[mode]}
          onSelectionChange={(keys) => {
            const next = [...keys][0];
            if (next === "keep" || next === "set" || next === "clear") onMode(next);
          }}
        >
          <ToggleButton id="keep">{t("batchEdit.keep")}</ToggleButton>
          <ToggleButton id="set">
            <ToggleButtonGroup.Separator />
            {t("batchEdit.set")}
          </ToggleButton>
          {canClear ? (
            <ToggleButton id="clear">
              <ToggleButtonGroup.Separator />
              {t("batchEdit.clear")}
            </ToggleButton>
          ) : null}
        </ToggleButtonGroup>
      </div>
      {mode === "set" ? children : null}
    </div>
  );
}

function BatchEditForm({onClose, profileId, subject, folders, onSubmit}: Omit<BatchEditDialogProps, "isOpen">) {
  const t = useTranslations("rules");
  const c = useTranslations("common");
  const format = useAppFormat();
  const targetName = useTargetName();
  const errorText = useFormErrorText();
  const locations = useProfileLocations(profileId);
  const [draft, setDraft] = useState<EditDraft>(KEEP_ALL);
  const destination = useDestinationDraft(null, locations.data?.locations ?? []);
  const [step, setStep] = useState<"form" | "destination">("form");
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);

  const action = draft.action.mode === "set" ? draft.action.value : "block";
  const comment = draft.comment.mode === "set" ? draft.comment.value : "";
  const target = destination.target;
  const members = editMembers({...draft, comment: draft.comment.mode === "set" ? {mode: "set", value: cleanProse(draft.comment.value)} : draft.comment, target});
  const needsTarget = draft.action.mode === "set" && draft.action.value === "redirect" && target === null;
  const commentTooLong = [...cleanProse(comment)].length > COMMENT_MAX;
  const hasDestination = locations.data ? locations.data.locations.length > 0 || locations.data.auto_random : true;
  const where = target ? withLocation(target, locations.data?.locations ?? []) : null;
  const inheritable = folders.some((f) => f.kind === "standard" && f.action !== undefined);

  const mode = <K extends keyof EditDraft>(key: K, initial: EditDraft[K] extends Change<infer V> ? V : never) =>
    (next: "keep" | "set" | "clear") => {
      setError(null);
      setDraft((d) => ({...d, [key]: next === "set" ? {mode: "set", value: initial} : {mode: next}}));
      if (key === "action" && next === "set" && initial === "redirect") setStep("destination");
    };

  const send = async () => {
    if (!members) return;
    setError(null);
    setSaving(true);
    try {
      await onSubmit(members);
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  if (step === "destination") {
    return (
      <DialogFrame
        isOpen
        onClose={onClose}
        title={t("dialog.destinationTitle")}
        footer={
          <>
            <Button variant="tertiary" onPress={() => setStep("form")}>
              {c("back")}
            </Button>
            <PrimaryButton isDisabled={target === null} onPress={() => setStep("form")}>
              {t("dialog.destinationDone")}
            </PrimaryButton>
          </>
        }
      >
        <DestinationsFields draft={destination.draft} onChange={destination.setDraft} source={{profileId}} subject={subject} />
      </DialogFrame>
    );
  }

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      isLocked={saving}
      title={t("batchEdit.title", {subject})}
      footer={
        <>
          <Button variant="tertiary" isDisabled={saving} onPress={onClose}>
            {c("cancel")}
          </Button>
          <PrimaryButton isPending={saving} isDisabled={saving || members === null || needsTarget || commentTooLong} onPress={() => void send()}>
            {t("batchEdit.apply")}
          </PrimaryButton>
        </>
      }
    >
      <div className="flex flex-col gap-5">
        <p className="text-muted text-xs">{members === null ? t("batchEdit.nothing") : t("batchEdit.hint")}</p>

        <Section title={t("dialog.action")} mode={draft.action.mode} onMode={mode("action", "block" as Action)} canClear={false} isDisabled={saving}>
          <ThreeStateControl
            value={action}
            onChange={(next) => {
              setDraft((d) => ({...d, action: {mode: "set", value: next}}));
              if (next === "redirect" && target === null) setStep("destination");
            }}
            subject={subject}
            choices={inheritable ? ["block", "bypass", "redirect", "inherit"] : ["block", "bypass", "redirect"]}
            hasDestination={hasDestination}
            destination={action === "redirect" ? <TargetMark target={where} /> : undefined}
            destinationName={action === "redirect" && where ? targetName(where) : undefined}
            onOpenDestination={() => setStep("destination")}
            isDisabled={saving}
          />
          <p className="text-muted text-xs">{t(`actionText.${action}`)}</p>
          {needsTarget ? <p className="text-muted text-xs">{t("dialog.needDestination")}</p> : null}
        </Section>

        <Section title={t("dialog.expiry")} mode={draft.expiry.mode} onMode={mode("expiry", {kind: "shortcut", value: "1d"} as ExpiryChoice)} canClear isDisabled={saving}>
          <ExpiryField
            choice={draft.expiry.mode === "set" ? draft.expiry.value : {kind: "none"}}
            onChange={(value) => setDraft((d) => ({...d, expiry: value.kind === "none" ? {mode: "clear"} : {mode: "set", value}}))}
            subject={subject}
            isDisabled={saving}
          />
        </Section>

        <Section title={t("dialog.folder")} mode={draft.folder.mode} onMode={mode("folder", folders[0]?.id ?? "")} canClear isDisabled={saving}>
          <MiniSelect
            label={t("dialog.folderLabel", {name: subject})}
            value={draft.folder.mode === "set" ? draft.folder.value : ""}
            isDisabled={saving}
            onChange={(id) => setDraft((d) => ({...d, folder: {mode: "set", value: id}}))}
            options={folders.map((f) => ({id: f.id, label: f.name, textValue: f.name}))}
          />
        </Section>

        <Section title={t("dialog.comment")} mode={draft.comment.mode} onMode={mode("comment", "")} canClear isDisabled={saving}>
          <TextField value={comment} onChange={(value) => setDraft((d) => ({...d, comment: {mode: "set", value}}))} isDisabled={saving} isInvalid={commentTooLong} aria-label={t("dialog.comment")}>
            <Label className="sr-only">{t("dialog.comment")}</Label>
            <Input autoComplete="off" placeholder={t("dialog.commentPlaceholder")} />
            <p className={["text-xs", commentTooLong ? "text-(--danger-text)" : "text-muted"].join(" ")} aria-live="polite">
              {t("dialog.commentCount", {count: format.number([...comment].length), max: format.number(COMMENT_MAX)})}
            </p>
          </TextField>
        </Section>

        <CapacityNotice error={error} />
        {error ? <SectionError error={error} text={errorText(error)} /> : null}
      </div>
    </DialogFrame>
  );
}
