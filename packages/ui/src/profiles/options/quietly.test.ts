import {ApiError} from "@ctrlz/api-client/errors.ts";
import {runSessionEnd} from "@ctrlz/api-client/sessionEnd.ts";
import {describe, expect, it, vi} from "vitest";

import {sendQuietly} from "./quietly.ts";

// S2-r3-5: the toast of a refused switch belongs to the person who pressed it. A refusal that answers after the session ended must not
// reach the next person, and the check is the `alive()` of this function: drop it and the second case fails.

describe("sendQuietly", () => {
  const text = () => "Try again.";

  it("says a refusal in a toast, once", async () => {
    const notify = vi.fn();
    const ok = await sendQuietly(async () => new ApiError(500, "internal"), {}, "Could not save.", text, notify);
    expect(ok).toBe(false);
    expect(notify).toHaveBeenCalledExactlyOnceWith("Could not save. Try again.");
  });

  it("says nothing of a refusal that answers after the session ended", async () => {
    const notify = vi.fn();
    const ok = await sendQuietly(
      async () => {
        runSessionEnd();
        return new ApiError(500, "internal");
      },
      {},
      "Could not save.",
      text,
      notify,
    );
    expect(ok).toBe(false);
    expect(notify).not.toHaveBeenCalled();
  });

  it("says nothing of a 423, which the banner says, and nothing of a write that worked", async () => {
    const notify = vi.fn();
    expect(await sendQuietly(async () => new ApiError(423, "profile_locked"), {}, "x", text, notify)).toBe(false);
    expect(await sendQuietly(async () => null, {}, "x", text, notify)).toBe(true);
    expect(notify).not.toHaveBeenCalled();
  });
});
