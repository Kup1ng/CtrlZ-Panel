"use client";

import {useJob, type Job} from "@ctrlz/api-client/hooks/jobs.ts";
import {useEffect, useRef} from "react";

// For the screen that STARTED a job: it learns when the job ends, once, to open the new profile, show the toast about `flagged`
// destinations, or leave the dialog. It reads the same query as `JobDialog` (`useJob`), so it adds no request. A job that ended
// before the screen mounted (a page reload with the dialog open) calls it once as well, which is what a resumed job needs. It returns the
// query, so the screen can see a job that the API no longer knows (S1-r2-5).

export function useJobOutcome(jobId: string | undefined, handlers: {onDone?: (job: Job) => void; onFailed?: (job: Job) => void}) {
  const query = useJob(jobId);
  const {data} = query;
  const handled = useRef<string | null>(null);
  const latest = useRef(handlers);
  useEffect(() => {
    latest.current = handlers;
  });
  const job = data;
  useEffect(() => {
    if (!job || handled.current === job.id) return;
    if (job.state === "done") {
      handled.current = job.id;
      latest.current.onDone?.(job);
    } else if (job.state === "failed") {
      handled.current = job.id;
      latest.current.onFailed?.(job);
    }
  }, [job]);
  return query;
}
