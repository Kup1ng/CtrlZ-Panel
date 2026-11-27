// What the job dialog of the profile dialogs follows (state only: a job's id is not in the address). A 202 names the job (`jobId`) and what it
// is for (`kind`, so the dialog has a title); a 409 `job_running` names none, and `resume` asks for the tenant's active one. The title of that
// job comes from its own `Job.kind`, because it may be a rules batch or an upload that the person did not start from this dialog.
export type JobTarget = {jobId: string; kind: "import" | "duplicate"} | {resume: true; jobId?: undefined; kind?: undefined};
