"use client";

import {Alert, Button, Input, Label, Skeleton, TextField, toast} from "@heroui/react";
import {isApiError} from "@ctrlz/api-client/errors.ts";
import {useProfileLocations} from "@ctrlz/api-client/hooks/profiles.ts";
import {useRedirectWarning} from "@ctrlz/api-client/hooks/preferences.ts";
import {useCreateRules, usePatchRule, type Folder, type Rule} from "@ctrlz/api-client/hooks/rules.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useMemo, useRef, useState} from "react";

import {ThreeStateControl} from "../../controls/ThreeStateControl.tsx";
import type {Action} from "../../controls/threeState.ts";
import {DestinationsFields, useDestinationDraft, useTargetName, withLocation} from "../../destinations/DestinationsDialog.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../../feedback/CapacityNotice.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {useScreenFieldText} from "../../feedback/useScreenFieldText.ts";
import {useWriteErrorText} from "../../feedback/useWriteErrorText.ts";
import {cleanProse} from "../../forms/invisible.ts";
import {TargetMark} from "../TargetMark.tsx";
import {DomainTags} from "./DomainTags.tsx";
import {ExpiryField} from "./ExpiryField.tsx";
import {GeoRows, type GeoRow} from "./GeoRows.tsx";
import {MiniSelect} from "./MiniSelect.tsx";
import {
  addTags,
  COMMENT_MAX,
  createExpiry,
  geoPattern,
  isEmptyPatch,
  isGeoKind,
  parseGeo,
  patternIndex,
  rulePatch,
  type ExpiryChoice,
} from "./rulesModel.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// Spec p2 9.6, WF "Rules" (T-180, T-181, T-184, T-197): the rule dialog, `ruleDialog=add-edit-rule` and `ruleDialog=add-edit-rule:<ruleId>`.
//
//   domain tags (one rule each), + Geo Rule rows, the three actions with their description, the clock for the expiry, the folder, the comment
//   with a counter.
//
// Redirect asks for its destination in a second step (the same Destinations body as a service, so the one list of places), and the first time a
// person chooses Redirect a one-time warning comes before it, remembered in `onboarding_state`. An edit changes ONE rule: its one name, and
// only what was changed is sent.

type Step = "form" | "warn" | "destination";

export type RuleDialogProps = {
  profileId: string;
  profileName: string;
  isOpen: boolean;
  onClose: () => void;
  /**
   * `null` for a new rule, else the rule being edited. `undefined` while the rule is being looked for, `false` when it is not found, and
   * `"failed"` when the look-up itself failed (a busy server, a limit): that is not the same as the rule being gone, and it can be tried again.
   */
  rule: Rule | null | undefined | false | "failed";
  /** The look-up again, for `rule === "failed"`. */
  onRetry?: () => void;
  folders: readonly Folder[];
  /** A new rule on a folder page starts in that folder. */
  defaultFolderId?: string;
};

export function RuleDialog({isOpen, onClose, rule, onRetry, ...rest}: RuleDialogProps) {
  const t = useTranslations("rules");
  const c = useTranslations("common");
  if (!isOpen) return null;
  if (rule === undefined || rule === false || rule === "failed") {
    return (
      <DialogFrame
        isOpen
        onClose={onClose}
        title={t("dialog.edit")}
        footer={
          <>
            {rule === "failed" ? (
              <PrimaryButton onPress={onRetry}>
                {c("retry")}
              </PrimaryButton>
            ) : null}
            <Button variant="tertiary" onPress={onClose}>
              {c("close")}
            </Button>
          </>
        }
      >
        {rule === undefined ? (
          <div role="status" aria-label={t("dialog.finding")} className="flex flex-col gap-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : rule === "failed" ? (
          <p className="text-sm" role="alert">
            {t("dialog.lookupFailed")}
          </p>
        ) : (
          <p className="text-sm" role="status">
            {t("dialog.notFound")}
          </p>
        )}
      </DialogFrame>
    );
  }
  // Mounted only while open and for one rule, so each opening starts from the rule as it is.
  return <RuleForm key={rule?.id ?? "new"} rule={rule} onClose={onClose} {...rest} />;
}

const COLOUR: Record<Action, string> = {block: "text-(--danger-text)", bypass: "text-(--success-text)", redirect: "", inherit: "text-muted"};

function RuleForm({profileId, profileName, onClose, rule, folders, defaultFolderId}: Omit<RuleDialogProps, "isOpen" | "rule"> & {rule: Rule | null}) {
  const t = useTranslations("rules");
  const c = useTranslations("common");
  const format = useAppFormat();
  const targetName = useTargetName();
  const writeText = useWriteErrorText();
  const fieldText = useScreenFieldText();
  const create = useCreateRules();
  const patchRule = usePatchRule();
  const warning = useRedirectWarning();
  const locations = useProfileLocations(profileId);

  const editing = rule !== null;
  const geoOfRule = rule ? parseGeo(rule.pattern) : null;
  const asGeo = rule !== null && geoOfRule !== null;

  const [step, setStep] = useState<Step>("form");
  const [tags, setTags] = useState<string[]>(rule && !asGeo ? [rule.pattern] : []);
  const [pending, setPending] = useState("");
  const [geo, setGeo] = useState<GeoRow[]>(geoOfRule ? [{id: 1, ...geoOfRule}] : []);
  const [action, setAction] = useState<Action>(rule?.action ?? "block");
  // The action that was chosen before Redirect, so cancelling the first-Redirect warning gives it back (not the rule's stored one).
  const beforeRedirect = useRef<Action>(action);
  const destination = useDestinationDraft(rule?.target ?? null, locations.data?.locations ?? []);
  const [folderId, setFolderId] = useState(rule ? (rule.folder_id ?? "") : (defaultFolderId ?? ""));
  const [comment, setComment] = useState(rule?.comment ?? "");
  const [expiry, setExpiry] = useState<ExpiryChoice>(rule ? {kind: "keep"} : {kind: "none"});
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);

  const folder = folders.find((f) => f.id === folderId);
  const inheritOk = folder?.kind === "standard" && folder.action !== undefined;
  const choices: readonly Action[] = inheritOk || action === "inherit" ? ["block", "bypass", "redirect", "inherit"] : ["block", "bypass", "redirect"];
  const target = destination.target;
  const hasDestination = locations.data ? locations.data.locations.length > 0 || locations.data.auto_random : true;
  const subject = rule ? rule.pattern : t("dialog.newRule");

  const tagsNow = useMemo(() => (pending.trim() === "" ? tags : addTags(tags, pending).tags), [tags, pending]);
  const geoReady = geo.filter((g) => g.country !== "");
  const patterns = editing ? [] : [...tagsNow, ...geoReady.map(geoPattern)];
  const count = editing ? 1 : patterns.length;

  // What the server said, split into the words under each tag or Geo Rule row and the rest. A pattern field names its index in the request,
  // which is the tags first and the Geo Rule rows after them.
  const patternErrors = useMemo(() => {
    const tagErrors = new Map<number, string>();
    const geoErrors = new Map<number, string>();
    let other = false;
    if (isApiError(error)) {
      for (const f of error.fields ?? []) {
        const index = patternIndex(f.name);
        if (index === null) {
          other = true;
          continue;
        }
        if (index < tagsNow.length) tagErrors.set(index, fieldText(f.code));
        else geoErrors.set(index - tagsNow.length, fieldText(f.code));
      }
      if ((error.fields ?? []).length === 0) other = true;
    } else if (error) {
      other = true;
    }
    return {tagErrors, geoErrors, other};
  }, [error, tagsNow.length, fieldText]);

  const editedPattern = rule ? (asGeo && geo[0] ? geoPattern(geo[0]) : (tags[0] ?? rule.pattern)) : "";
  const cleanComment = cleanProse(comment);
  const patch = rule ? rulePatch(rule, {pattern: editedPattern, action, target, folderId, comment: cleanComment, expiry}) : null;
  const commentTooLong = [...cleanComment].length > COMMENT_MAX;
  const needsTarget = action === "redirect" && target === null && (!editing || rule?.action !== "redirect");
  const geoIncomplete = geo.some((g) => g.country === "");
  const canSend = !saving && !commentTooLong && !needsTarget && !geoIncomplete && (editing ? patch !== null && !isEmptyPatch(patch) && (asGeo ? !geoIncomplete : tags.length === 1) : patterns.length > 0);

  const send = async () => {
    setError(null);
    setSaving(true);
    try {
      if (rule) {
        const body = rulePatch(rule, {pattern: editedPattern, action, target, folderId, comment: cleanComment, expiry});
        await patchRule.mutateAsync({profileId, ruleId: rule.id, patch: body});
        toast.success(t("dialog.saved"));
      } else {
        await create.mutateAsync({
          profileId,
          patterns,
          action,
          ...(action === "redirect" && target ? {target} : {}),
          ...(folderId ? {folder_id: folderId} : {}),
          ...(cleanComment ? {comment: cleanComment} : {}),
          ...createExpiry(expiry),
        });
        toast.success(t("dialog.added", {count: patterns.length}));
      }
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  const chooseAction = (next: Action) => {
    if (next === "redirect" && action !== "redirect") beforeRedirect.current = action;
    setAction(next);
    setError(null);
    if (next === "redirect") {
      if (!warning.seen) setStep("warn");
      else if (target === null) setStep("destination");
    }
  };

  const changeFolder = (id: string) => {
    setFolderId(id);
    // A rule that follows its folder cannot stay so in a folder with no Folder Rule (3.7 `needs_folder_action`).
    const next = folders.find((f) => f.id === id);
    if (action === "inherit" && !(next?.kind === "standard" && next.action)) setAction("block");
  };

  if (step === "warn") {
    return (
      <DialogFrame
        isOpen
        onClose={onClose}
        title={t("redirectWarn.title")}
        footer={
          <>
            <Button
              variant="tertiary"
              onPress={() => {
                setAction(beforeRedirect.current);
                setStep("form");
              }}
            >
              {c("cancel")}
            </Button>
            <PrimaryButton
              onPress={() => {
                void warning.markSeen().catch(() => undefined);
                setStep(target === null ? "destination" : "form");
              }}
            >
              {t("redirectWarn.continue")}
            </PrimaryButton>
          </>
        }
      >
        <div className="flex flex-col gap-3 text-sm">
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t("redirectWarn.heading")}</Alert.Title>
              <Alert.Description>{t("redirectWarn.text")}</Alert.Description>
            </Alert.Content>
          </Alert>
          <p className="text-muted text-xs">{t("redirectWarn.once")}</p>
        </div>
      </DialogFrame>
    );
  }

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
      title={editing ? t("dialog.edit") : t("dialog.add")}
      footer={
        <>
          <Button variant="tertiary" isDisabled={saving} onPress={onClose}>
            {c("cancel")}
          </Button>
          <PrimaryButton isPending={saving} isDisabled={!canSend} onPress={() => void send()}>
            {editing ? c("save") : t("dialog.submitAdd", {count})}
          </PrimaryButton>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <p className="text-muted text-xs">{t("dialog.profile", {name: profileName})}</p>

        {asGeo ? (
          <GeoRows single rows={geo} onChange={setGeo} isDisabled={saving} errors={patternErrors.geoErrors} />
        ) : (
          <>
            <DomainTags
              tags={tags}
              onChange={(next) => {
                setTags(next);
                setError(null);
              }}
              pending={pending}
              onPending={setPending}
              errors={patternErrors.tagErrors}
              isDisabled={saving}
              max={editing ? 1 : undefined}
            />
            {editing && rule && isGeoKind(rule.match_kind) ? <p className="text-muted text-xs">{t("dialog.asnNote")}</p> : null}
            {editing ? null : <GeoRows rows={geo} onChange={setGeo} isDisabled={saving} errors={patternErrors.geoErrors} />}
          </>
        )}

        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium" id="rule-action-label">
            {t("dialog.action")}
          </span>
          <ThreeStateControl
            value={action}
            onChange={chooseAction}
            subject={subject}
            choices={choices}
            hasDestination={hasDestination}
            iranianBypass={rule?.iranian_bypass ?? false}
            locationUnavailable={rule?.location_unavailable ?? false}
            destination={action === "redirect" ? <TargetMark target={target ? withLocation(target, locations.data?.locations ?? []) : null} /> : undefined}
            destinationName={action === "redirect" && target ? targetName(withLocation(target, locations.data?.locations ?? [])) : undefined}
            onOpenDestination={() => setStep("destination")}
            isDisabled={saving}
          />
          <p className={["flex items-start gap-1.5 text-xs", COLOUR[action]].join(" ")} data-action-text={action}>
            <Icon name={action === "block" ? "close" : action === "bypass" ? "check" : action === "redirect" ? "globe" : "info"} className="mt-0.5 size-3.5 shrink-0" />
            <span>{t(`actionText.${action}`)}</span>
          </p>
          {needsTarget ? <p className="text-muted text-xs">{t("dialog.needDestination")}</p> : null}
        </div>

        <div className="flex flex-col gap-1.5">
          <span className="text-sm font-medium">{t("dialog.expiry")}</span>
          <ExpiryField choice={expiry} onChange={setExpiry} current={rule?.expires_at} subject={subject} isDisabled={saving} />
        </div>

        <div className="flex flex-col gap-1.5">
          <span className="text-sm font-medium">{t("dialog.folder")}</span>
          <MiniSelect
            label={t("dialog.folderLabel", {name: subject})}
            value={folderId === "" ? "none" : folderId}
            isDisabled={saving}
            onChange={(id) => changeFolder(id === "none" ? "" : id)}
            options={[
              {id: "none", label: t("dialog.noFolder"), textValue: t("dialog.noFolder")},
              ...folders.map((f) => ({id: f.id, label: f.name, textValue: f.name})),
            ]}
          />
        </div>

        <TextField value={comment} onChange={setComment} isDisabled={saving} isInvalid={commentTooLong} aria-label={t("dialog.comment")}>
          <Label>{t("dialog.comment")}</Label>
          <Input autoComplete="off" placeholder={t("dialog.commentPlaceholder")} />
          <p className={["text-xs", commentTooLong ? "text-(--danger-text)" : "text-muted"].join(" ")} aria-live="polite">
            {t("dialog.commentCount", {count: format.number([...comment].length), max: format.number(COMMENT_MAX)})}
          </p>
        </TextField>

        <CapacityNotice error={error} />
        {error && patternErrors.other ? <SectionError error={error} text={writeText(error)} /> : null}
        {error && !patternErrors.other && (patternErrors.tagErrors.size > 0 || patternErrors.geoErrors.size > 0) ? (
          <p className="text-xs text-(--danger-text)" role="alert">
            {t("dialog.fixTags")}
          </p>
        ) : null}
      </div>
    </DialogFrame>
  );
}
