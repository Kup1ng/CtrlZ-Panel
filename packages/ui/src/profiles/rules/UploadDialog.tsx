"use client";

import {Button, Radio, RadioGroup} from "@heroui/react";
import {hasCode, isApiError} from "@ctrlz/api-client/errors.ts";
import {newIdempotencyKey} from "@ctrlz/api-client/hooks/support.ts";
import {useUploadFolderRules, type BatchResult} from "@ctrlz/api-client/hooks/rules.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {Tech} from "../../data/Tech.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../../feedback/CapacityNotice.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {useScreenFieldText} from "../../feedback/useScreenFieldText.ts";
import {JobDialog} from "../../jobs/JobDialog.tsx";
import {resultLines} from "../../jobs/jobModel.ts";
import {toBase64, UPLOAD_MAX_BYTES} from "./rulesModel.ts";
import {useFormErrorText} from "./useFormErrorText.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// Spec p2 9.6, 6.3 (T-188, T-195): Upload Folder, `ruleDialog=upload` on the folder page. The file and the mode (`new_only` by default, which
// adds what is new, or `upsert`, which also updates what is there; neither deletes), then the counts. A file of more than 1,000 rules is a job,
// and the job dialog follows it. A refused file names the places in it that are wrong, by pointer, in `Tech`.
//
// The file is read in the browser and sent as base64 in the request body. It is the person's own file and nothing about it is kept.

export type UploadDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  profileId: string;
  folderId: string;
  folderName: string;
};

export function UploadDialog({isOpen, ...rest}: UploadDialogProps) {
  return isOpen ? <UploadForm {...rest} /> : null;
}

function UploadForm({onClose, profileId, folderId, folderName}: Omit<UploadDialogProps, "isOpen">) {
  const t = useTranslations("rules");
  const j = useTranslations("jobs");
  const c = useTranslations("common");
  const format = useAppFormat();
  const errorText = useFormErrorText();
  const fieldText = useScreenFieldText();
  const upload = useUploadFolderRules();
  const input = useRef<HTMLInputElement>(null);
  // One key for one file and one mode: a retry of the same request replays, and another file or mode is another request.
  const key = useRef<{for: string; value: string} | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<"new_only" | "upsert">("new_only");
  const [result, setResult] = useState<BatchResult | null>(null);
  const [job, setJob] = useState<{id?: string; resume: boolean} | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);

  const tooBig = file !== null && file.size > UPLOAD_MAX_BYTES;
  const empty = file !== null && file.size === 0;

  const send = async () => {
    if (!file) return;
    setError(null);
    setSaving(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const id = `${file.name}:${file.size}:${file.lastModified}:${mode}`;
      if (key.current?.for !== id) key.current = {for: id, value: newIdempotencyKey()};
      const answer = await upload.mutateAsync({profileId, folderId, document: toBase64(bytes), mode, key: key.current.value});
      if (answer.kind === "job") setJob({id: answer.job.id, resume: false});
      else setResult(answer.data);
    } catch (e) {
      if (hasCode(e, "job_running")) setJob({resume: true});
      else setError(e);
    } finally {
      setSaving(false);
    }
  };

  if (job) return <JobDialog isOpen onClose={onClose} jobId={job.id} resume={job.resume} title={t("upload.title", {name: folderName})} />;

  const lines = result ? resultLines(result) : [];
  const fields = isApiError(error) ? (error.fields ?? []).slice(0, 100) : [];

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      isLocked={saving}
      title={t("upload.title", {name: folderName})}
      footer={
        result ? (
          <PrimaryButton onPress={onClose}>
            {c("done")}
          </PrimaryButton>
        ) : (
          <>
            <Button variant="tertiary" isDisabled={saving} onPress={onClose}>
              {c("cancel")}
            </Button>
            <PrimaryButton isPending={saving} isDisabled={saving || file === null || tooBig || empty} onPress={() => void send()}>
              {t("upload.do")}
            </PrimaryButton>
          </>
        )
      }
    >
      {result ? (
        <div className="flex flex-col gap-2" role="status">
          <p className="flex items-center gap-2 text-sm font-medium">
            <Icon name="check" className="size-4" />
            {t("upload.done")}
          </p>
          {lines.length === 0 ? (
            <p className="text-muted text-sm">{j("result.none")}</p>
          ) : (
            <ul className="flex flex-col gap-1 text-sm">
              {lines.map(({key: k, count}) => (
                <li key={k} className="flex items-start gap-2">
                  <Icon name={k === "flagged" || k === "conflict" ? "warning" : "check"} className="mt-0.5 size-4 shrink-0" />
                  <span>{j(`result.${k}`, {count})}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          <p className="text-muted text-xs">{t("upload.help")}</p>
          <div className="flex flex-col gap-2">
            <input
              ref={input}
              type="file"
              accept=".json,application/json"
              className="sr-only"
              tabIndex={-1}
              aria-hidden="true"
              onChange={(event) => {
                setFile(event.target.files?.[0] ?? null);
                setError(null);
              }}
            />
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="secondary" isDisabled={saving} aria-label={t("upload.choose", {name: folderName})} onPress={() => input.current?.click()}>
                <Icon name="upload" className="size-4" />
                {file ? t("upload.change") : t("upload.pick")}
              </Button>
              {file ? (
                <span className="min-w-0 truncate text-sm">
                  <Tech mono={false}>{file.name}</Tech> <span className="text-muted">({t("upload.size", {size: format.number(Math.max(1, Math.round(file.size / 1024)))})})</span>
                </span>
              ) : (
                <span className="text-muted text-sm">{t("upload.none")}</span>
              )}
            </div>
            {tooBig ? <p className="text-xs text-(--danger-text)">{t("upload.tooBig", {max: format.number(UPLOAD_MAX_BYTES / (1024 * 1024))})}</p> : null}
            {empty ? <p className="text-xs text-(--danger-text)">{t("upload.empty")}</p> : null}
          </div>

          <RadioGroup aria-label={t("upload.modeLabel")} value={mode} isDisabled={saving} onChange={(value) => setMode(value === "upsert" ? "upsert" : "new_only")} className="flex flex-col gap-1">
            <Radio value="new_only">
              <Radio.Content className="flex items-start gap-2 py-1">
                <Radio.Control>
                  <Radio.Indicator />
                </Radio.Control>
                <span className="flex flex-col">
                  <span className="text-sm">{t("upload.newOnly")}</span>
                  <span className="text-muted text-xs">{t("upload.newOnlyText")}</span>
                </span>
              </Radio.Content>
            </Radio>
            <Radio value="upsert">
              <Radio.Content className="flex items-start gap-2 py-1">
                <Radio.Control>
                  <Radio.Indicator />
                </Radio.Control>
                <span className="flex flex-col">
                  <span className="text-sm">{t("upload.upsert")}</span>
                  <span className="text-muted text-xs">{t("upload.upsertText")}</span>
                </span>
              </Radio.Content>
            </Radio>
          </RadioGroup>

          <CapacityNotice error={error} />
          {error ? <SectionError error={error} text={errorText(error)} /> : null}
          {fields.length > 0 ? (
            <ul aria-label={t("upload.problems")} className="text-muted flex max-h-40 flex-col gap-0.5 overflow-auto text-xs">
              {fields.map((f, i) => (
                <li key={`${f.name}-${i}`}>
                  <Tech>{f.name || "/"}</Tech> {fieldText(f.code)}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      )}
    </DialogFrame>
  );
}
