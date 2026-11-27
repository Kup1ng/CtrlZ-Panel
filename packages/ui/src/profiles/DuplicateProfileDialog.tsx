"use client";

import {Alert} from "@heroui/react";
import {hasCode, isApiError} from "@ctrlz/api-client/errors.ts";
import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {useDuplicateProfile, type Profile} from "@ctrlz/api-client/hooks/profiles.ts";
import {newIdempotencyKey} from "@ctrlz/api-client/hooks/support.ts";
import {sessionGuard} from "@ctrlz/api-client/sessionEnd.ts";
import {Link, useRouter} from "@ctrlz/i18n/navigation.ts";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {Tech} from "../data/Tech.tsx";
import {UrlModal} from "../dialog/UrlModal.tsx";
import {parseProfileDialog} from "../dialog/dialogValues.ts";
import {writePushed, type UrlDialog} from "../dialog/useUrlDialog.ts";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {useScreenFieldText} from "../feedback/useScreenFieldText.ts";
import {AuthForm} from "../forms/AuthForm.tsx";
import {EditorActions} from "../forms/EditorActions.tsx";
import {FormError} from "../forms/FormError.tsx";
import {cleanProse, nameLength} from "../forms/invisible.ts";
import {useApiForm} from "../forms/useApiForm.ts";
import {PROFILE_NAME_MAX} from "./AddProfileDialog.tsx";
import type {JobTarget} from "./jobTarget.ts";
import {JobRunningNotice} from "./JobRunningNotice.tsx";
import {useAnnounceCreated} from "./profileCreated.ts";
import {ProfileNameField} from "./ProfileNameField.tsx";
import {profileHref, profilesHref} from "./profileRoutes.ts";

// Spec p2 9.2, 6.4, WF "Profiles" (T-131). `profileDialog=duplicate` on a profile's page: a name for the copy. The copy is a new, unlocked
// profile with the same content; reading a locked profile is allowed, so a locked one can be copied. On success a toast says so and the
// list opens with the copy first (T-136). A profile of more than 1,000 rules is a job: the dialog gives way to the job dialog.
//
// `iranian_name` (spec p2 3.6): a rule or service that redirects a name on the never-proxied list is kept where it is, but cannot travel
// into a new profile, so the copy is refused and the answer names each one by its JSON pointer. The text says what to do: set them to
// Block or Bypass first, then copy again. The pointers are positions in the export that Duplicate builds, which the Rules screen does not
// number, so the note links to the Rules and Services tabs, where the rows that act as Bypass are marked (spec p2 3.6).
//
// A 409 `job_running` means the tenant has a large job already and this copy was NOT started: the form keeps its name and says so, and the
// running job opens only when asked. A 409 `idempotency_key_reused` drops the key, so the next press is a new request.

export function DuplicateProfileDialog({dialog, profile, onJob}: {dialog: UrlDialog; profile: Profile; onJob: (job: JobTarget) => void}) {
  const t = useTranslations("profiles");
  const open = parseProfileDialog(dialog.value) === "duplicate";
  const [busy, setBusy] = useState(false);
  return (
    <UrlModal dialog={dialog} isOpen={open} isLocked={busy} title={t("dialogs.duplicate.title", {name: profile.name})}>
      {open ? <DuplicateForm profile={profile} onClose={dialog.close} onBusy={setBusy} onJob={onJob} /> : null}
    </UrlModal>
  );
}

/** "Copy of Home", cut to the name limit by code points (the server counts code points). */
function defaultCopyName(text: string): string {
  return Array.from(text).slice(0, PROFILE_NAME_MAX).join("");
}

function DuplicateForm({profile, onClose, onBusy, onJob}: {profile: Profile; onClose: () => void; onBusy: (busy: boolean) => void; onJob: (job: JobTarget) => void}) {
  const t = useTranslations("profiles");
  const router = useRouter();
  const fieldText = useScreenFieldText();
  const duplicate = useDuplicateProfile();
  const announce = useAnnounceCreated();
  const form = useApiForm({focus: "name", fieldNamespace: "profiles"});
  const [name, setName] = useState(() => defaultCopyName(t("dialogs.duplicate.defaultName", {name: profile.name})));
  const [pending, setPending] = useState(false);
  const [capped, setCapped] = useState<unknown>(null);
  const [iranian, setIranian] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const busy = useRef(false);
  const key = useRef<{sig: string; value: string} | null>(null);

  function finish() {
    busy.current = false;
    setPending(false);
    onBusy(false);
  }

  async function submit() {
    if (busy.current || form.blocked) return;
    const clean = cleanProse(name);
    if (clean === "") return form.setFieldError("name", fieldText("required", "name"));
    if (nameLength(clean) > PROFILE_NAME_MAX) return form.setFieldError("name", fieldText("too_long", "name"));
    busy.current = true;
    setPending(true);
    onBusy(true);
    form.clear();
    setCapped(null);
    setIranian([]);
    setRunning(false);
    // The key belongs to this request: the same name is a retry, another name is another request (spec p2 3.5).
    const sig = `${profile.id}:${clean}`;
    if (key.current?.sig !== sig) key.current = {sig, value: newIdempotencyKey()};
    // An answer that arrives after the session ended is not the present person's: no job is followed, nothing is marked, toasted or opened (S1-r3-5).
    const alive = sessionGuard();
    try {
      const result = await duplicate.mutateAsync({id: profile.id, name: clean, key: key.current.value});
      if (!alive()) return;
      finish();
      if (result.kind === "job") {
        onJob({jobId: result.job.id, kind: "duplicate"});
      } else {
        announce(result.data, t("dialogs.duplicate.done", {name: result.data.profile.name}));
        // The list is another page, so the parameter goes with it: closing by Back would undo the navigation.
        writePushed("profileDialog", false);
        router.push(profilesHref);
        return;
      }
      onClose();
    } catch (error) {
      if (!alive()) return;
      finish();
      if (hasCode(error, "job_running")) setRunning(true);
      else if (exceededCap(error)) setCapped(error);
      else if (hasCode(error, "validation_failed") && isApiError(error) && (error.fields ?? []).some((f) => f.code === "iranian_name")) {
        setIranian((error.fields ?? []).filter((f) => f.code === "iranian_name").map((f) => f.name));
      } else {
        if (hasCode(error, "idempotency_key_reused")) key.current = null;
        form.fail(error, {rename: {"/name": "name"}});
      }
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{t("dialogs.duplicate.text", {name: profile.name})}</p>
      <ProfileNameField
        label={t("dialogs.duplicate.name")}
        hint={t("dialogs.nameHint", {max: PROFILE_NAME_MAX})}
        value={name}
        isDisabled={pending}
        {...form.bind("name", setName)}
      />
      {iranian.length > 0 ? (
        <Alert status="warning" data-testid="duplicate-iranian">
          <Alert.Indicator />
          <Alert.Content className="min-w-0">
            <Alert.Title>{t("dialogs.duplicate.iranianTitle")}</Alert.Title>
            <Alert.Description>
              {t("dialogs.duplicate.iranianText")}
              <ul className="mt-1 flex max-h-32 flex-col gap-0.5 overflow-auto">
                {iranian.map((pointer, i) => (
                  <li key={`${pointer}-${i}`}>
                    {pointer === "" ? <span className="text-xs font-medium">{t("dialogs.import.wholeFile")}</span> : <Tech className="text-xs">{pointer}</Tech>}
                  </li>
                ))}
              </ul>
              <span className="mt-2 flex flex-col gap-1">
                <Link href={profileHref(profile.id, "rules")} className="underline underline-offset-2">
                  {t("dialogs.duplicate.iranianRules")}
                </Link>
                <Link href={profileHref(profile.id, "services")} className="underline underline-offset-2">
                  {t("dialogs.duplicate.iranianServices")}
                </Link>
              </span>
            </Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      {running ? (
        <JobRunningNotice
          onShow={() => {
            onJob({resume: true});
            onClose();
          }}
        />
      ) : null}
      <CapacityNotice error={capped} />
      <FormError error={form.formError} form={form} onRetry={() => void submit()} />
      <EditorActions submitLabel={t("dialogs.duplicate.submit")} isPending={pending} retryIn={form.retryIn} onCancel={onClose} />
    </AuthForm>
  );
}
