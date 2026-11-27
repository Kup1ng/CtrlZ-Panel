import {describe, expect, it} from "vitest";

import {followedJobId, isActive, jobErrorText, jobFields, resultLines} from "./jobModel.ts";

describe("job model", () => {
  it("is active while queued or running", () => {
    expect(isActive({state: "queued"})).toBe(true);
    expect(isActive({state: "running"})).toBe(true);
    expect(isActive({state: "done"})).toBe(false);
    expect(isActive({state: "failed"})).toBe(false);
    expect(isActive(undefined)).toBe(false);
  });

  it("lists the counts above zero, flagged last", () => {
    expect(resultLines({created: 3, updated: 0, skipped: 1, conflict: 0, flagged: 2, items: []})).toEqual([
      {key: "created", count: 3},
      {key: "skipped", count: 1},
      {key: "flagged", count: 2},
    ]);
    expect(resultLines({created: 0, updated: 0, skipped: 0, conflict: 0, flagged: 0, items: []})).toEqual([]);
    expect(resultLines(undefined)).toEqual([]);
  });

  it("gives job_attempts_exhausted its own line and any other code the line of errors", () => {
    expect(jobErrorText({code: "job_attempts_exhausted", message: ""} as never)).toEqual({namespace: "jobs", key: "error.job_attempts_exhausted"});
    expect(jobErrorText({code: "profile_locked"} as never)).toEqual({namespace: "errors", key: "profile_locked"});
    expect(jobErrorText({code: "brand_new"} as never)).toEqual({namespace: "errors", key: "unknown"});
    expect(jobErrorText(undefined)).toEqual({namespace: "errors", key: "unknown"});
  });

  it("reads the pointers of a failed file, drops malformed entries and stops at the bound", () => {
    const fields = [{name: "/rules/1/pattern", code: "pattern_invalid"}, {name: 5, code: "x"}, null, {name: "/a", code: "exceeded"}];
    expect(jobFields({fields} as never)).toEqual([
      {name: "/rules/1/pattern", code: "pattern_invalid"},
      {name: "/a", code: "exceeded"},
    ]);
    expect(jobFields({fields: Array.from({length: 300}, (_, i) => ({name: `/${i}`, code: "invalid"}))} as never)).toHaveLength(100);
    expect(jobFields(undefined)).toEqual([]);
  });
});

describe("followedJobId", () => {
  it("takes the given id first, then the one kept, then a fresh active job", () => {
    expect(followedJobId("kept", "given", "a")).toBe("given");
    expect(followedJobId("kept", undefined, "a")).toBe("kept");
    expect(followedJobId(undefined, undefined, "a")).toBe("a");
  });

  it("keeps the job when the active query turns to null after it ends", () => {
    expect(followedJobId("a", undefined, undefined)).toBe("a");
  });

  it("follows nothing before there is a job", () => {
    expect(followedJobId(undefined, undefined, undefined)).toBeUndefined();
  });
});
