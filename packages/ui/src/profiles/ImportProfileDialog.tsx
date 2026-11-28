"use client";

import {Alert} from "@heroui/react";
import {DropZone} from "@heroui-pro/react";
import {hasCode, isApiError, type FieldError} from "@ctrlz/api-client/errors.ts";
import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {useImportProfile} from "@ctrlz/api-client/hooks/profiles.ts";
import {newIdempotencyKey} from "@ctrlz/api-client/hooks/support.ts";
import {sessionGuard} from "@ctrlz/api-client/sessionEnd.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {Tech} from "../data/Tech.tsx";
import {UrlModal} from "../dialog/UrlModal.tsx";
import {parseProfileDialog} from "../dialog/dialogValues.ts";
import type {UrlDialog} from "../dialog/useUrlDialog.ts";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {useScreenFieldText} from "../feedback/useScreenFieldText.ts";
import {AuthForm} from "../forms/AuthForm.tsx";
import {EditorActions} from "../forms/EditorActions.tsx";
import {FormError} from "../forms/FormError.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {MAX_IMPORT_BYTES, toBase64} from "./profileList.ts";
import {useAnnounceCreated} from "./profileCreated.ts";
import {FooterPortal, useFooterSlot} from "./footerSlot.tsx";
import type {JobTarget} from "./jobTarget.ts";
import {JobRunningNotice} from "./JobRunningNotice.tsx";

// Spec p2 9.2, 6.2, WF "Profiles" (T-128, T-134). `profileDialog=import`: a file picker (a drop zone), then Import. The file is JSON, at most 4 MiB
// (D31), sent as base64 with an Idempotency-Key that stays the same for a retry of the SAME file and changes with another one. The API
// explains every problem of a file: a 422 carries a `fields` list, each entry a JSON pointer (`/rules/12/pattern`) with a code. The
// pointer is shown in `Tech` and the code as a sentence, so the person knows what to fix in their own file.
//
// A file of more than 1,000 rules is a job (202): the dialog gives way to the job dialog (`onJob`). A 409 `job_running` means the tenant
// has one already and this file was NOT started: the form stays with its file and says so, and the running job opens only when asked.
//
// The key is minted from the whole document, not from a prefix: every export starts with the same 48 bytes, so a file edited in place has the
// same name and size as the one before it. A 409 `idempotency_key_reused` drops the key, so the next press is a new request.

export function ImportProfileDialog({dialog, onJob}: {dialog: UrlDialog; onJob: (job: JobTarget) => void}) {
  const t = useTranslations("profiles");
  const open = parseProfileDialog(dialog.value) === "import";
  const [busy, setBusy] = useState(false);
  const {footer, slot} = useFooterSlot();
  return (
    <UrlModal dialog={dialog} isOpen={open} isLocked={busy} title={t("dialogs.import.title")} footer={footer}>
      {open ? <ImportForm onClose={dialog.close} onBusy={setBusy} onJob={onJob} slot={slot} /> : null}
    </UrlModal>
  );
}

/** The API names at most 100 problems of a file (spec p2 6.2); at that count there may be more. */
const MAX_PROBLEMS = 100;

type Picked = {name: string; size: number; document: string};

function ImportForm({onClose, onBusy, onJob, slot}: {onClose: () => void; onBusy: (busy: boolean) => void; onJob: (job: JobTarget) => void; slot: HTMLElement | null}) {
  const t = useTranslations("profiles");
  const format = useAppFormat();
  const fieldText = useScreenFieldText();
  const importProfile = useImportProfile();
  const announce = useAnnounceCreated();
  const form = useApiForm({fieldNamespace: "profiles"});
  const [file, setFile] = useState<Picked | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [problems, setProblems] = useState<FieldError[]>([]);
  const [capped, setCapped] = useState<unknown>(null);
  const [running, setRunning] = useState(false);
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  // One key for one file: a retry of the same request replays the first answer, and a different file is a different request (spec p2 3.5).
  const key = useRef<{document: string; value: string} | null>(null);

  async function pick(candidate: File | undefined) {
    if (!candidate) return;
    setProblems([]);
    setFileError(null);
    form.clear();
    if (candidate.size > MAX_IMPORT_BYTES) {
      setFile(null);
      setFileError(t("dialogs.import.tooLarge"));
      return;
    }
    try {
      const bytes = new Uint8Array(await candidate.arrayBuffer());
      setFile({name: candidate.name, size: candidate.size, document: toBase64(bytes)});
    } catch {
      setFile(null);
      setFileError(t("dialogs.import.unreadable"));
    }
  }

  function finish() {
    busy.current = false;
    setPending(false);
    onBusy(false);
  }

  async function submit() {
    if (busy.current || form.blocked) return;
    if (!file) return setFileError(t("dialogs.import.nothing"));
    busy.current = true;
    setPending(true);
    onBusy(true);
    form.clear();
    setProblems([]);
    setCapped(null);
    setRunning(false);
    if (key.current?.document !== file.document) key.current = {document: file.document, value: newIdempotencyKey()};
    // An answer that arrives after the session ended is not the present person's: no job is followed, nothing is marked or toasted (S1-r3-5).
    const alive = sessionGuard();
    try {
      const result = await importProfile.mutateAsync({document: file.document, key: key.current.value});
      if (!alive()) return;
      finish();
      if (result.kind === "job") onJob({jobId: result.job.id, kind: "import"});
      else announce(result.data, t("dialogs.import.imported", {name: result.data.profile.name}));
      onClose();
    } catch (error) {
      if (!alive()) return;
      finish();
      if (hasCode(error, "job_running")) setRunning(true);
      else if (exceededCap(error)) setCapped(error);
      else if (hasCode(error, "validation_failed") && isApiError(error) && (error.fields?.length ?? 0) > 0) setProblems(error.fields ?? []);
      else {
        if (hasCode(error, "idempotency_key_reused")) key.current = null;
        form.fail(error);
      }
    }
  }

  return (
    <AuthForm id="import-profile" form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{t("dialogs.import.text")}</p>
      <DropZone>
        <DropZone.Area
          isDisabled={pending}
          onDrop={async (event) => {
            for (const item of event.items) {
              if (item.kind === "file") {
                await pick(await item.getFile());
                break;
              }
            }
          }}
        >
          <DropZone.Icon>
            <Icon name="upload" className="size-6" />
          </DropZone.Icon>
          <DropZone.Label>{t("dialogs.import.drop")}</DropZone.Label>
          <DropZone.Description>{t("dialogs.import.dropHint", {max: 4})}</DropZone.Description>
          <DropZone.Trigger>{t("dialogs.import.choose")}</DropZone.Trigger>
        </DropZone.Area>
        <DropZone.Input aria-label={t("dialogs.import.chooseAria")} accept=".json,application/json" onSelect={(files) => void pick(files[0])} />
        {file ? (
          <DropZone.FileList>
            <DropZone.FileItem status="complete">
              <DropZone.FileInfo>
                <DropZone.FileName>
                  <Tech mono={false}>{file.name}</Tech>
                </DropZone.FileName>
                <DropZone.FileMeta>{t("dialogs.import.size", {kb: format.number(Math.max(1, Math.round(file.size / 1024)))})}</DropZone.FileMeta>
              </DropZone.FileInfo>
              <DropZone.FileRemoveTrigger aria-label={t("dialogs.import.remove", {name: file.name})} isDisabled={pending} onPress={() => setFile(null)}>
                <Icon name="close" className="size-4" />
              </DropZone.FileRemoveTrigger>
            </DropZone.FileItem>
          </DropZone.FileList>
        ) : null}
      </DropZone>
      {fileError ? (
        <p role="alert" className="text-danger-soft-foreground text-sm">
          {fileError}
        </p>
      ) : null}
      {problems.length > 0 ? (
        <Alert status="danger" data-testid="import-problems">
          <Alert.Indicator />
          <Alert.Content className="min-w-0">
            <Alert.Title>{t("dialogs.import.problems")}</Alert.Title>
            <Alert.Description>
              <ul className="mt-1 flex max-h-48 flex-col gap-1 overflow-auto">
                {problems.map((p, i) => (
                  <li key={`${p.name}-${i}`} className="flex flex-col">
                    {p.name === "" ? <span className="text-xs font-medium">{t("dialogs.import.wholeFile")}</span> : <Tech className="text-xs">{p.name}</Tech>}
                    <span>{fieldText(p.code, p.name)}</span>
                  </li>
                ))}
              </ul>
              {problems.length >= MAX_PROBLEMS ? <p className="mt-1 text-xs">{t("dialogs.import.more")}</p> : null}
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
      <FooterPortal slot={slot}>
        <EditorActions form="import-profile" submitLabel={t("dialogs.import.submit")} isPending={pending} isDisabled={file === null} retryIn={form.retryIn} onCancel={onClose} />
      </FooterPortal>
    </AuthForm>
  );
}
