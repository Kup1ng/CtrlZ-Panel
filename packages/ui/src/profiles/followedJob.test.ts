import {runSessionEnd} from "@ctrlz/api-client/sessionEnd.ts";
import {afterEach, describe, expect, it} from "vitest";

import {closeJobDialog, followJob, newFollowOwner, peekFollowedJob, resolveFollowedJob, stopFollowingJob, takeJobOutcome} from "./followedJob.ts";
import {markNewProfile, peekNewProfile} from "./newProfile.ts";

// S1-r2-1 and S1-r2-4: the store of the followed job belongs to one session, its dialog to one mount, and the end of a job is announced
// once. (The mounts themselves are the e2e cases of profiles.jobs.spec.ts.)

afterEach(() => {
  runSessionEnd();
});

describe("the followed job (S1-r2-1)", () => {
  it("every mount has its own owner, and the entry says whose dialog is open", () => {
    const first = newFollowOwner();
    const second = newFollowOwner();
    expect(second).not.toBe(first);
    followJob({jobId: "job-1", kind: "import"}, first);
    expect(peekFollowedJob()).toEqual({open: true, owner: first, jobId: "job-1", kind: "import"});
    // The later mount closes what it finds open; the job is still followed.
    closeJobDialog();
    expect(peekFollowedJob()).toEqual({open: false, owner: first, jobId: "job-1", kind: "import"});
  });

  it("a resumed job is named once", () => {
    followJob({resume: true}, newFollowOwner());
    expect(peekFollowedJob()?.jobId).toBeUndefined();
    resolveFollowedJob("job-1");
    resolveFollowedJob("job-2");
    expect(peekFollowedJob()?.jobId).toBe("job-1");
  });

  it("the end of a job is announced once for the whole session", () => {
    expect(takeJobOutcome("job-1")).toBe(true);
    // A new mount of the screen finds the job done in the cache and asks again: no second toast, no second New mark.
    expect(takeJobOutcome("job-1")).toBe(false);
    expect(takeJobOutcome("job-2")).toBe(true);
    // Stopping the follower does not forget it.
    followJob({jobId: "job-2", kind: "duplicate"}, newFollowOwner());
    stopFollowingJob();
    expect(takeJobOutcome("job-2")).toBe(false);
  });
});

describe("a session that ends (S1-r2-4)", () => {
  it("drops the followed job and the New mark", () => {
    followJob({jobId: "job-1", kind: "import"}, newFollowOwner());
    markNewProfile("profile-1");
    runSessionEnd();
    expect(peekFollowedJob()).toBeNull();
    expect(peekNewProfile()).toBeNull();
  });

  it("forgets which job ends were announced, so the next session announces its own", () => {
    expect(takeJobOutcome("job-1")).toBe(true);
    runSessionEnd();
    expect(takeJobOutcome("job-1")).toBe(true);
  });
});
