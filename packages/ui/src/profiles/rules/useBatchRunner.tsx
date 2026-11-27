"use client";

import {toast} from "@heroui/react";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useBatchRules, useTransferRule, type BatchResult, type RulesBatch, type RuleTransfer} from "@ctrlz/api-client/hooks/rules.ts";
import {useTranslations} from "next-intl";
import {useCallback, useState} from "react";

import {JobDialog} from "../../jobs/JobDialog.tsx";
import {resultLines} from "../../jobs/jobModel.ts";

// What a write of the Rules screens does with the answer (spec p2 3.5, 9.6): a batch, or the one-rule transfer, answers its counts at once
// (a toast says them) or, above 1,000 items, a Job that the job dialog follows. A `409 job_running` means the tenant's earlier job is not done,
// so the dialog opens on that job (`resume`) and nothing is sent twice. Any other refusal goes back to the caller, which shows it where the
// person is looking (the dialog that asked).
//
// The `Idempotency-Key` is one for each action of the person, made by the caller and kept for a retry of the same action (`key`).

export function useBatchRunner(profileId: string) {
  const t = useTranslations("jobs");
  const batch = useBatchRules();
  const transfer = useTransferRule();
  const [job, setJob] = useState<{id?: string; resume: boolean; title: string} | null>(null);

  const say = useCallback(
    (result: BatchResult) => {
      const lines = resultLines(result);
      toast.success(lines.length === 0 ? t("result.none") : lines.map(({key, count}) => t(`result.${key}`, {count})).join(" · "));
    },
    [t],
  );

  /** Runs a batch; resolves `true` when it ended (counts or a job), and rejects with the API's refusal. */
  const run = useCallback(
    async (body: RulesBatch, title: string, key?: string): Promise<boolean> => {
      try {
        const result = await batch.mutateAsync({profileId, key, ...body});
        if (result.kind === "job") setJob({id: result.job.id, resume: false, title});
        else say(result.data);
        return true;
      } catch (error) {
        if (hasCode(error, "job_running")) {
          setJob({resume: true, title});
          return true;
        }
        throw error;
      }
    },
    [batch, profileId, say],
  );

  /** Copy or Move of one rule from its hover actions. The route answers at once, so the answer is always counts. */
  const runOne = useCallback(
    async (ruleId: string, body: RuleTransfer): Promise<boolean> => {
      const result = await transfer.mutateAsync({profileId, ruleId, ...body});
      say(result);
      return true;
    },
    [transfer, profileId, say],
  );

  const dialog = job ? <JobDialog isOpen onClose={() => setJob(null)} jobId={job.id} resume={job.resume} title={job.title} /> : null;
  return {run, runOne, isPending: batch.isPending || transfer.isPending, dialog};
}
