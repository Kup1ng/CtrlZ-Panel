"use client";

import {Button, Description, Input, Label, Radio, RadioGroup, Skeleton, Switch, TextField, toast} from "@heroui/react";
import {useProfileLocations} from "@ctrlz/api-client/hooks/profiles.ts";
import {useCreateFolder, usePatchFolder, type Folder} from "@ctrlz/api-client/hooks/rules.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {ThreeStateControl} from "../../controls/ThreeStateControl.tsx";
import type {Action} from "../../controls/threeState.ts";
import {DestinationsFields, useDestinationDraft, useTargetName, withLocation} from "../../destinations/DestinationsDialog.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../../feedback/CapacityNotice.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {cleanProse} from "../../forms/invisible.ts";
import {TargetMark} from "../TargetMark.tsx";
import {FOLDER_NAME_MAX, sameTarget} from "./rulesModel.ts";
import {useFormErrorText} from "./useFormErrorText.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// Spec p2 9.6, WF "Rules" (T-186, T-189): the folder dialog, `ruleDialog=folder` and `ruleDialog=folder:<folderId>`. Two cards, Standard and
// Magic. A Standard folder has the Folder Rule switch, which shows the action that its rules can follow (`inherit`); a Magic folder only turns
// logging off (Do Not Log), and its Bypass is not offered (D8). The name is under 32 characters. The kind is chosen when the folder is made.

type Kind = Folder["kind"];
/** A folder has no `inherit`: its rules do. */
type FolderAction = Exclude<Action, "inherit">;

export type FolderDialogProps = {
  profileId: string;
  isOpen: boolean;
  onClose: () => void;
  /** `null` for a new folder; the id of the one being edited otherwise. */
  folderId: string | null;
  /** The folders of the profile, `undefined` while they load. */
  folders: readonly Folder[] | undefined;
  /** Called with the folder after a create (the screen may open it). */
  onCreated?: (folder: Folder) => void;
};

export function FolderDialog({isOpen, onClose, folderId, folders, ...rest}: FolderDialogProps) {
  const t = useTranslations("rules");
  const c = useTranslations("common");
  if (!isOpen) return null;
  const folder = folderId === null ? null : folders?.find((f) => f.id === folderId);
  if (folderId !== null && folder === undefined) {
    return (
      <DialogFrame
        isOpen
        onClose={onClose}
        title={t("folderDialog.edit")}
        footer={
          <Button variant="tertiary" onPress={onClose}>
            {c("close")}
          </Button>
        }
      >
        {folders === undefined ? (
          <div role="status" aria-label={t("folderDialog.finding")} className="flex flex-col gap-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : (
          <p className="text-sm" role="status">
            {t("folderDialog.notFound")}
          </p>
        )}
      </DialogFrame>
    );
  }
  return <FolderForm key={folder?.id ?? "new"} folder={folder ?? null} onClose={onClose} {...rest} />;
}

function KindCard({value, title, text, isDisabled}: {value: Kind; title: string; text: string; isDisabled: boolean}) {
  return (
    <Radio value={value} isDisabled={isDisabled} className="bg-default/40 data-[selected=true]:bg-accent/10 w-full p-3" data-kind={value}>
      <Radio.Content className="flex w-full min-w-0 items-start gap-3">
        <Radio.Control>
          <Radio.Indicator />
        </Radio.Control>
        <SubIcon group="rules" name={value === "do_not_log" ? "folder-magic" : "folder"} className="mt-0.5 size-6 shrink-0" />
        <span className="flex min-w-0 flex-1 flex-col">
          <span className="text-sm font-medium">{title}</span>
          <span className="text-muted text-xs">{text}</span>
        </span>
      </Radio.Content>
    </Radio>
  );
}

function FolderForm({profileId, onClose, folder, onCreated}: Omit<FolderDialogProps, "isOpen" | "folderId" | "folders"> & {folder: Folder | null}) {
  const t = useTranslations("rules");
  const c = useTranslations("common");
  const format = useAppFormat();
  const targetName = useTargetName();
  const errorText = useFormErrorText();
  const create = useCreateFolder();
  const patch = usePatchFolder();
  const locations = useProfileLocations(profileId);

  const editing = folder !== null;
  const [kind, setKind] = useState<Kind>(folder?.kind ?? "standard");
  const [name, setName] = useState(folder?.name ?? "");
  const [ruled, setRuled] = useState(folder?.action !== undefined);
  const [action, setAction] = useState<FolderAction>(folder?.action ?? "block");
  const destination = useDestinationDraft(folder?.target ?? null, locations.data?.locations ?? []);
  const [step, setStep] = useState<"form" | "destination">("form");
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);

  const trimmed = cleanProse(name);
  const length = [...trimmed].length;
  const nameProblem = trimmed === "" ? "required" : length > FOLDER_NAME_MAX ? "tooLong" : null;
  const standard = kind === "standard";
  const target = destination.target;
  const hasDestination = locations.data ? locations.data.locations.length > 0 || locations.data.auto_random : true;
  const needsTarget = standard && ruled && action === "redirect" && target === null && !(editing && folder.action === "redirect");
  // The destination counts as changed only when it is another place than the stored one (the dialog seeds it from the folder), so an untouched
  // Redirect folder offers no Save and a rename does not send the target again.
  const targetChanged = editing && ruled && action === "redirect" && target !== null && (action !== folder.action || !sameTarget(target, folder.target));
  const changed = !editing || trimmed !== folder.name || (standard && (ruled !== (folder.action !== undefined) || (ruled && action !== folder.action) || targetChanged));
  const canSend = !saving && nameProblem === null && !needsTarget && changed;
  const where = target ? withLocation(target, locations.data?.locations ?? []) : null;

  const send = async () => {
    setError(null);
    setSaving(true);
    try {
      if (folder) {
        const ruleChanged = standard && (ruled !== (folder.action !== undefined) || action !== folder.action || targetChanged);
        const made = await patch.mutateAsync({
          profileId,
          folderId: folder.id,
          ...(trimmed !== folder.name ? {name: trimmed} : {}),
          ...(standard && ruled && ruleChanged ? {action, ...(action === "redirect" && target ? {target} : {})} : {}),
          ...(standard && !ruled && folder.action !== undefined ? {clear: ["action" as const]} : {}),
        });
        toast.success(t("folderDialog.saved", {name: made.name}));
      } else {
        const made = await create.mutateAsync({profileId, name: trimmed, kind, ...(standard && ruled ? {action, ...(action === "redirect" && target ? {target} : {})} : {})});
        toast.success(t("folderDialog.added", {name: made.name}));
        onCreated?.(made);
      }
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
        <DestinationsFields draft={destination.draft} onChange={destination.setDraft} source={{profileId}} subject={trimmed || t("folderDialog.newFolder")} />
      </DialogFrame>
    );
  }

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      isLocked={saving}
      title={editing ? t("folderDialog.edit") : t("folderDialog.add")}
      footer={
        <>
          <Button variant="tertiary" isDisabled={saving} onPress={onClose}>
            {c("cancel")}
          </Button>
          <PrimaryButton isPending={saving} isDisabled={!canSend} onPress={() => void send()}>
            {editing ? c("save") : c("create")}
          </PrimaryButton>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <RadioGroup aria-label={t("folderDialog.kindLabel")} value={kind} isDisabled={saving} onChange={(value) => setKind(value === "do_not_log" ? "do_not_log" : "standard")} className="flex flex-col gap-2">
          <KindCard value="standard" title={t("folderDialog.standard")} text={t("folderDialog.standardText")} isDisabled={editing} />
          <KindCard value="do_not_log" title={t("folderDialog.magic")} text={t("folderDialog.magicText")} isDisabled={editing} />
        </RadioGroup>
        {editing ? <p className="text-muted text-xs">{t("folderDialog.kindFixed")}</p> : null}

        <TextField value={name} onChange={setName} isDisabled={saving} isInvalid={nameProblem === "tooLong"} aria-label={t("folderDialog.name")}>
          <Label>{t("folderDialog.name")}</Label>
          <Input autoComplete="off" placeholder={t("folderDialog.namePlaceholder")} />
          <Description>{t("folderDialog.nameCount", {count: format.number(length), max: format.number(FOLDER_NAME_MAX)})}</Description>
        </TextField>

        {standard ? (
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-3">
              <span className="text-sm font-medium">{t("folderDialog.ruleSwitch")}</span>
              <Switch isSelected={ruled} isDisabled={saving} onChange={setRuled} aria-label={t("folderDialog.ruleSwitch")}>
                <Switch.Content>
                  <Switch.Control>
                    <Switch.Thumb />
                  </Switch.Control>
                </Switch.Content>
              </Switch>
            </div>
            <p className="text-muted text-xs">{t("folderDialog.ruleText")}</p>
            {ruled ? (
              <>
                <ThreeStateControl
                  value={action}
                  onChange={(next) => {
                    if (next === "inherit") return;
                    setAction(next);
                    setError(null);
                    if (next === "redirect" && target === null) setStep("destination");
                  }}
                  subject={trimmed || t("folderDialog.newFolder")}
                  choices={["block", "bypass", "redirect"]}
                  hasDestination={hasDestination}
                  locationUnavailable={folder?.location_unavailable ?? false}
                  destination={action === "redirect" ? <TargetMark target={where} /> : undefined}
                  destinationName={action === "redirect" && where ? targetName(where) : undefined}
                  onOpenDestination={() => setStep("destination")}
                  isDisabled={saving}
                />
                <p className="text-muted text-xs">{t(`actionText.${action}`)}</p>
                {needsTarget ? <p className="text-muted text-xs">{t("dialog.needDestination")}</p> : null}
              </>
            ) : null}
          </div>
        ) : (
          <p className="text-muted text-xs">{t("folderDialog.magicNote")}</p>
        )}

        <CapacityNotice error={error} />
        {error ? <SectionError error={error} text={errorText(error)} /> : null}
      </div>
    </DialogFrame>
  );
}
