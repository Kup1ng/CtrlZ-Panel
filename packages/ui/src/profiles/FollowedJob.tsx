"use client";

import {toast} from "@heroui/react";
import {isJobFinished, isTerminalJobError, useActiveJob, type Job} from "@ctrlz/api-client/hooks/jobs.ts";
import {useTranslations} from "next-intl";
import {useEffect} from "react";

import {JobDialog} from "../jobs/JobDialog.tsx";
import {useJobOutcome} from "../jobs/useJobOutcome.ts";
import {closeJobDialog, resolveFollowedJob, stopFollowingJob, takeJobOutcome, useFollowedJob, type FollowedJobEntry} from "./followedJob.ts";
import {markNewProfile} from "./newProfile.ts";
import {useAnnounceFlagged} from "./profileCreated.ts";

// Spec p2 9.2, 9.6 (T-134, T-136). The follower of the job that Import or Duplicate started. It is mounted by `ProfileDialogs` whenever the
// store has a job, so the job is followed with the dialog open and after it is closed ("keep going in the background"), and it ends with
// the job: when the job is done or failed AND the dialog is closed, the follower stops itself.
//
// What the end of the job does: the toast about destinations that act as Bypass (`flagged`), the mark "New" on the profile the job made
// (`Job.profile_id`, an Import or a Duplicate only), and a toast when the job failed while the dialog was closed. The profile list and the
// counters are read again by `useJob` (`invalidateAfterJob`), which runs for as long as this component is mounted.
//
// The store outlives the screen, so what a later mount finds in it is not taken as it is (S1-r2-1, S1-r2-5):
//   - the job dialog is shown only to the mount that opened it (`owner`); another mount closes it and goes on following;
//   - the end of a job is announced once for the whole session (`takeJobOutcome`), not once per mount;
//   - a job that the API answers with a final 4xx (swept after 24 hours, deleted with its profile) and a resumed job that no answer
//     named are not followed once their dialog is closed: there is nothing left to wait for, and a poll nobody sees must not go on.

export function FollowedJob({owner}: {owner: number}) {
  const entry = useFollowedJob();
  return entry ? <Follower entry={entry} owner={owner} /> : null;
}

const MAKES_A_PROFILE: readonly Job["kind"][] = ["import", "duplicate"];

function Follower({entry, owner}: {entry: FollowedJobEntry; owner: number}) {
  const t = useTranslations("profiles");
  const j = useTranslations("jobs");
  const flagged = useAnnounceFlagged();

  // The dialog is on screen only for the mount that opened it; a stale one is closed here, in the same commit it was found in.
  const shown = entry.open && entry.owner === owner;
  useEffect(() => {
    if (entry.open && !shown) closeJobDialog();
  }, [entry.open, shown]);

  // A resumed job has no id yet: the first answer of `GET /jobs/active` names it, and the store keeps it for the next mount.
  const active = useActiveJob({enabled: entry.jobId === undefined});
  const named = active.isFetching ? undefined : (active.data?.id ?? undefined);
  const nothingActive = entry.jobId === undefined && !active.isPending && !active.isFetching && active.data === null;
  useEffect(() => {
    if (entry.jobId === undefined && named !== undefined) resolveFollowedJob(named);
  }, [entry.jobId, named]);
  // The job ended before the person looked at it, and the dialog is closed: nothing to follow.
  // A failed question is the same: with the dialog closed there is no one to retry it, and a later mount would attach to whatever job is active then.
  const unnamed = entry.jobId === undefined && (nothingActive || active.isError);
  useEffect(() => {
    if (unnamed && !shown) stopFollowingJob();
  }, [unnamed, shown]);

  const query = useJobOutcome(entry.jobId, {
    onDone: (done) => {
      if (!takeJobOutcome(done.id)) return;
      flagged(done.result?.flagged ?? 0);
      if (done.profile_id && MAKES_A_PROFILE.includes(done.kind)) markNewProfile(done.profile_id);
    },
    onFailed: (failed) => {
      if (!takeJobOutcome(failed.id)) return;
      if (!shown) toast.danger(j("error.title"));
    },
  });

  const over = isJobFinished(query.data) || isTerminalJobError(query.error);
  useEffect(() => {
    if (over && !shown) stopFollowingJob();
  }, [over, shown]);

  return (
    <JobDialog
      isOpen={shown}
      onClose={closeJobDialog}
      jobId={entry.jobId}
      resume={entry.jobId === undefined || entry.kind === undefined}
      title={entry.kind ? t(`dialogs.job.${entry.kind}`) : undefined}
    />
  );
}
