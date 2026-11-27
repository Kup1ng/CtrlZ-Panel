"use client";

import {Spinner} from "@heroui/react";
import {isJobFinished, isTerminalJobError, useActiveJob, useJob} from "@ctrlz/api-client/hooks/jobs.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useState, type ReactNode} from "react";

import {Tech} from "../data/Tech.tsx";
import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {followedJobId, isActive, jobErrorText, jobFields, resultLines} from "./jobModel.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec p2 3.5 and 9.6. A request of more than 1,000 items is answered 202 with a Job. This dialog follows it: `GET /jobs/{id}` every two
// seconds until `done` or `failed` (`useJob`), and shows the state in words and a spinner, with no percentage (`progress` moves only at
// commit). It is STATE-ONLY: the job's id is not in the address, and nothing here is a secret, but the dialog belongs to the action that
// made the job, not to a link.
//
// A dialog that is opened after a `409 job_running` has no id: `resume` asks `GET /jobs/active` and follows that job. The tenant has one
// job at a time, and the screens that start one disable their button while `useActiveJob` says there is one.
//
// What a finished job came to is a list of counts: created, updated, skipped, conflict, and flagged (destinations that are not available
// yet and act as Bypass, p2 4.2). A failed one names its error, and for an Import or an Upload the pointers of the file with the code of
// each, in `Tech`, since the file is the person's own and these are what they fix.

export type JobDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  /** The job to follow, from a 202. */
  jobId?: string;
  /** No id: ask for the tenant's active job and follow it (after `job_running`). */
  resume?: boolean;
  /** What the job is for: "Upload rules", "Duplicate profile". */
  title?: ReactNode;
};

export function JobDialog({isOpen, onClose, jobId, resume = false, title}: JobDialogProps) {
  const t = useTranslations("jobs");
  const e = useTranslations("errors");
  // The first job the active query names is kept while the dialog is open (followedJobId), so the end of the job, which turns the query to
  // null, does not take the result away. Once it is kept the query is off. State is set in the render, from what changed, which React
  // allows and which does not paint a frame without the id.
  const [latched, setLatched] = useState<string | undefined>();
  const active = useActiveJob({enabled: isOpen && resume && jobId === undefined && latched === undefined});
  // An answer is taken only when no fetch is under way: after a close the query holds the previous job, and it is asked again as the dialog opens.
  const fresh = active.isFetching ? undefined : active.data?.id;
  const id = followedJobId(latched, jobId, fresh);
  if (isOpen && jobId === undefined && latched === undefined && fresh !== undefined) setLatched(fresh);
  if (!isOpen && latched !== undefined) setLatched(undefined);
  const job = useJob(isOpen ? id : undefined);
  const data = job.data;
  // A job the API no longer knows (404, 403: nothing polls it any more) is not running, whatever its last answer said (S1-r3-3).
  const gone = isTerminalJobError(job.error) && !isJobFinished(data);
  const running = !gone && (isActive(data) || (id === undefined && (active.isPending || active.isFetching)));
  const lines = resultLines(data?.result);
  const error = data?.state === "failed" ? jobErrorText(data.error) : null;
  const fields = jobFields(data?.error);
  const nothingActive = resume && jobId === undefined && id === undefined && !active.isPending && !active.isFetching;

  return (
    <DialogFrame
      isOpen={isOpen}
      onClose={onClose}
      title={title ?? (data ? t(`kind.${data.kind}`) : t("dialog.title"))}
      footer={
        <PrimaryButton onPress={onClose}>
          {running ? t("dialog.background") : t("dialog.close")}
        </PrimaryButton>
      }
    >
      <div className="flex flex-col gap-3" aria-live="polite">
        {resume && data && !gone ? (
          <div>
            <p className="text-sm font-medium">{t("dialog.resumeTitle")}</p>
            <p className="text-muted text-xs">{t("dialog.resumeText")}</p>
          </div>
        ) : null}

        {job.error && (!data || gone) ? (
          <SectionError error={job.error} onRetry={() => void job.refetch()} />
        ) : nothingActive ? (
          <p className="text-muted text-sm" role="status">
            {t("result.none")}
          </p>
        ) : (
          <p className="flex items-center gap-2 text-sm font-medium" role="status" aria-label={t("progressLabel")}>
            {running ? <Spinner size="sm" /> : data?.state === "done" ? <Icon name="check" className="size-4" /> : data?.state === "failed" ? <Icon name="warning" className="size-4" /> : null}
            <span>{data ? t(`state.${data.state}`) : t("state.queued")}</span>
          </p>
        )}

        {running ? <p className="text-muted text-xs">{t("note")}</p> : null}

        {data?.state === "done" ? (
          lines.length === 0 ? (
            <p className="text-muted text-sm">{t("result.none")}</p>
          ) : (
            <ul className="flex flex-col gap-1 text-sm">
              {lines.map(({key, count}) => (
                <li key={key} className="flex items-start gap-2">
                  <Icon name={key === "flagged" || key === "conflict" ? "warning" : "check"} className="mt-0.5 size-4 shrink-0" />
                  <span>{t(`result.${key}`, {count})}</span>
                </li>
              ))}
            </ul>
          )
        ) : null}

        {error ? (
          <div className="flex flex-col gap-2" role="alert">
            <p className="text-sm font-medium">{t("error.title")}</p>
            <p className="text-sm">{error.namespace === "jobs" ? t(error.key) : e(error.key, {retryAfterS: 0})}</p>
            {fields.length > 0 ? (
              <ul className="text-muted flex max-h-48 flex-col gap-0.5 overflow-auto text-xs">
                {fields.map((f, i) => (
                  <li key={`${f.name}-${i}`}>
                    <Tech>{f.name || "/"}</Tech> {e.has(`fields.${f.code}` as never) ? e(`fields.${f.code}` as never) : e("fields.invalid")}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}
      </div>
    </DialogFrame>
  );
}
