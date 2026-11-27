"use client";

import {Button, Description, Input, Label, Radio, RadioGroup, Spinner, TextField} from "@heroui/react";
import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {useFolders} from "@ctrlz/api-client/hooks/rules.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {cleanProse} from "../../forms/invisible.ts";
import {CapacityNotice} from "../../feedback/CapacityNotice.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {MiniSelect} from "./MiniSelect.tsx";
import {FOLDER_NAME_MAX, transferProblem, type TransferDraft, type TransferPlace} from "./rulesModel.ts";
import {useFormErrorText} from "./useFormErrorText.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// Spec p2 9.6, WF "Rules" (T-189, T-193): Copy and Move. The rules to move are in the memory of the page (a hovered row, or a selection), so
// the dialog is state-only and not part of the address. Move offers an existing folder, the top level, another profile, or Create Folder and
// Add Rules; Copy goes to another profile and into the same places there. The destination's lock, limits and locations are checked again by
// the API (T-193), and the refusal is shown here.

export type TransferDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  op: "copy" | "move";
  /** What is moved, in words: the rule's name, or "12 rules". */
  subject: string;
  profileId: string;
  /** Sends the request. A rejection is shown in the dialog. */
  onSubmit: (draft: TransferDraft) => Promise<unknown>;
};

export function TransferDialog({isOpen, ...rest}: TransferDialogProps) {
  // Mounted only while open, so every opening starts from the defaults.
  return isOpen ? <TransferForm {...rest} /> : null;
}

function TransferForm({onClose, op, subject, profileId, onSubmit}: Omit<TransferDialogProps, "isOpen">) {
  const t = useTranslations("rules");
  const c = useTranslations("common");
  const format = useAppFormat();
  const errorText = useFormErrorText();
  const profiles = useProfiles();
  const others = (profiles.data ?? []).filter((p) => p.id !== profileId);
  const [destId, setDestId] = useState(op === "move" ? profileId : "");
  const [place, setPlace] = useState<TransferPlace>({kind: "root"});
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);

  // A Copy needs another profile; until the person picks one the first other profile is the choice.
  const profileValue = destId !== "" ? destId : (others[0]?.id ?? profileId);
  const folders = useFolders(profileValue);
  const dest = profiles.data?.find((p) => p.id === profileValue);
  const draft: TransferDraft = {op, profileId: profileValue, place: place.kind === "new" ? {kind: "new", name: cleanProse(place.name)} : place};
  const problem = transferProblem(draft, profileId);
  const name = place.kind === "new" ? place.name : "";
  const noOther = op === "copy" && profiles.data !== undefined && others.length === 0;

  const profileOptions = [...(op === "move" ? (profiles.data ?? []).filter((p) => p.id === profileId) : []), ...others].map((p) => ({
    id: p.id,
    label: p.id === profileId ? t("transfer.thisProfile", {name: p.name}) : p.name,
    textValue: p.name,
  }));

  const send = async () => {
    setError(null);
    setSaving(true);
    try {
      await onSubmit(draft);
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      isLocked={saving}
      title={t(`transfer.${op}Title`, {subject})}
      footer={
        <>
          <Button variant="tertiary" isDisabled={saving} onPress={onClose}>
            {c("cancel")}
          </Button>
          <PrimaryButton isPending={saving} isDisabled={saving || problem !== null || profiles.data === undefined || noOther} onPress={() => void send()}>
            {t(`transfer.${op}Do`)}
          </PrimaryButton>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {profiles.isError ? (
          <SectionError error={profiles.error} onRetry={() => void profiles.refetch()} />
        ) : profiles.data === undefined ? (
          <p className="text-muted flex items-center gap-2 text-sm" role="status">
            <Spinner size="sm" />
            {t("transfer.loading")}
          </p>
        ) : noOther ? (
          <p className="text-sm" role="status">
            {t("transfer.noOther")}
          </p>
        ) : (
          <>
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium">{t("transfer.profile")}</span>
              <MiniSelect
                label={t("transfer.profileLabel", {subject})}
                value={profileValue}
                isDisabled={saving}
                onChange={(id) => {
                  setDestId(id);
                  // A folder belongs to one profile, so a chosen folder is not carried to another.
                  setPlace((p) => (p.kind === "folder" ? {kind: "root"} : p));
                }}
                options={profileOptions}
              />
              {dest?.locked ? <p className="text-xs text-(--warning-text)">{t("transfer.locked", {name: dest.name})}</p> : null}
            </div>

            <RadioGroup
              aria-label={t("transfer.placeLabel", {subject})}
              value={place.kind}
              isDisabled={saving}
              onChange={(kind) => setPlace(kind === "folder" ? {kind: "folder", folderId: ""} : kind === "new" ? {kind: "new", name: ""} : {kind: "root"})}
              className="flex flex-col gap-1"
            >
              <Radio value="root">
                <Radio.Content className="flex items-center gap-2 py-1">
                  <Radio.Control>
                    <Radio.Indicator />
                  </Radio.Control>
                  <span className="text-sm">{t("transfer.root")}</span>
                </Radio.Content>
              </Radio>
              <Radio value="folder" isDisabled={(folders.data ?? []).length === 0}>
                <Radio.Content className="flex items-center gap-2 py-1">
                  <Radio.Control>
                    <Radio.Indicator />
                  </Radio.Control>
                  <span className="text-sm">{t("transfer.folder")}</span>
                </Radio.Content>
              </Radio>
              <Radio value="new">
                <Radio.Content className="flex items-center gap-2 py-1">
                  <Radio.Control>
                    <Radio.Indicator />
                  </Radio.Control>
                  <span className="text-sm">{t("transfer.createFolder")}</span>
                </Radio.Content>
              </Radio>
            </RadioGroup>

            {place.kind === "folder" ? (
              <MiniSelect
                label={t("transfer.folderLabel", {subject})}
                value={place.folderId}
                isDisabled={saving}
                onChange={(folderId) => setPlace({kind: "folder", folderId})}
                options={(folders.data ?? []).map((f) => ({id: f.id, label: f.name, textValue: f.name}))}
              />
            ) : null}
            {place.kind === "new" ? (
              <TextField value={name} onChange={(value) => setPlace({kind: "new", name: value})} isDisabled={saving} isInvalid={problem === "name_too_long"} aria-label={t("transfer.newName")}>
                <Label>{t("transfer.newName")}</Label>
                <Input autoComplete="off" placeholder={t("folderDialog.namePlaceholder")} />
                <Description>{t("folderDialog.nameCount", {count: format.number([...name.trim()].length), max: format.number(FOLDER_NAME_MAX)})}</Description>
              </TextField>
            ) : null}
          </>
        )}
        <CapacityNotice error={error} />
        {error ? <SectionError error={error} text={errorText(error)} /> : null}
      </div>
    </DialogFrame>
  );
}
