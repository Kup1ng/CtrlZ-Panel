import {environmentManager, QueryClient, QueryObserver} from "@tanstack/react-query";
import {afterEach, beforeEach, describe, expect, it, vi} from "vitest";

import {OUTBOX_POLL_MS, outboxPollInterval} from "./sms.ts";

// wp10-r14-3. The test-send lookup polls while the message is pending. A lookup that failed has no answer, and the old rule
// ("pending, or no data yet") went on asking every interval under the visible Retry.

describe("outboxPollInterval", () => {
  it("asks again only while the last answer is pending", () => {
    expect(outboxPollInterval({status: "success", data: {state: "pending"}})).toBe(OUTBOX_POLL_MS);
    expect(outboxPollInterval({status: "success", data: {state: "sent"}})).toBe(false);
    expect(outboxPollInterval({status: "success", data: {state: "failed"}})).toBe(false);
  });

  it("stops when the lookup has failed, with or without an earlier answer", () => {
    expect(outboxPollInterval({status: "error"})).toBe(false);
    expect(outboxPollInterval({status: "error", data: {state: "pending"}})).toBe(false);
  });

  it("does not poll before the first answer, which the ordinary fetch brings", () => {
    expect(outboxPollInterval({status: "pending"})).toBe(false);
  });
});

describe("a lookup that answers 404 is not polled", () => {
  // TanStack sets no interval on a server, and vitest runs in node.
  beforeEach(() => {
    vi.useFakeTimers();
    environmentManager.setIsServer(() => false);
  });
  afterEach(() => {
    environmentManager.setIsServer(() => true);
    vi.useRealTimers();
  });

  function observe(queryFn: () => Promise<{state: string}>) {
    const client = new QueryClient();
    const observer = new QueryObserver(client, {
      queryKey: ["outbox", "x"],
      queryFn,
      retry: false,
      refetchInterval: (query) => outboxPollInterval(query.state),
    });
    return {client, unsubscribe: observer.subscribe(() => undefined)};
  }

  it("sends one request and no more after several intervals", async () => {
    const queryFn = vi.fn(() => Promise.reject(new Error("404")));
    const {client, unsubscribe} = observe(queryFn);
    await vi.advanceTimersByTimeAsync(OUTBOX_POLL_MS * 10);
    expect(queryFn).toHaveBeenCalledTimes(1);
    unsubscribe();
    client.clear();
  });

  it("keeps asking while the answer is pending and stops at the final one", async () => {
    let answers = ["pending", "pending", "sent"];
    const queryFn = vi.fn(async () => ({state: answers.shift() ?? "sent"}));
    const {client, unsubscribe} = observe(queryFn);
    await vi.advanceTimersByTimeAsync(OUTBOX_POLL_MS * 10);
    expect(queryFn).toHaveBeenCalledTimes(3);
    answers = [];
    unsubscribe();
    client.clear();
  });
});
