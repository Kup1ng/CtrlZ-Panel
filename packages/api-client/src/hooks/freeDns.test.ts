import {beforeEach, describe, expect, it, vi} from "vitest";

const GET = vi.hoisted(() => vi.fn());
vi.mock("../client.ts", () => ({api: {GET}}));

import {FREE_DNS_KEEP_MS, forgetFreeDns, readFreeDns} from "./freeDns.ts";

// T-557: the switch is read from the public route; when the route cannot be read the tab keeps its last good answer for five minutes and then
// has none, so a text that depends on the switch is not shown.

const ON = {enabled: true, primary_dns_ip: "203.0.113.53"};
const OFF = {enabled: false};

beforeEach(() => {
  GET.mockReset();
  forgetFreeDns();
});

describe("readFreeDns", () => {
  it("answers with what the route says", async () => {
    GET.mockResolvedValue({data: ON});
    expect(await readFreeDns(undefined, () => 0)).toEqual(ON);
  });

  it("falls back to the last good answer when the route fails with a 429 or a 5xx, up to five minutes", async () => {
    GET.mockResolvedValueOnce({data: ON});
    await readFreeDns(undefined, () => 1_000);
    GET.mockRejectedValue(Object.assign(new Error("busy"), {status: 429}));
    expect(await readFreeDns(undefined, () => 1_000 + FREE_DNS_KEEP_MS - 1)).toEqual(ON);
    GET.mockRejectedValue(Object.assign(new Error("down"), {status: 503}));
    expect(await readFreeDns(undefined, () => 1_000 + FREE_DNS_KEEP_MS - 1)).toEqual(ON);
  });

  it("gives up after five minutes, and with no good answer at all", async () => {
    GET.mockRejectedValue(new Error("offline"));
    await expect(readFreeDns(undefined, () => 0)).rejects.toThrow("offline");
    GET.mockResolvedValueOnce({data: OFF});
    await readFreeDns(undefined, () => 10);
    GET.mockRejectedValue(new Error("offline"));
    await expect(readFreeDns(undefined, () => 10 + FREE_DNS_KEEP_MS)).rejects.toThrow("offline");
  });

  it("keeps the newest good answer: a later switch change replaces the earlier one in the fallback", async () => {
    GET.mockResolvedValueOnce({data: ON});
    await readFreeDns(undefined, () => 0);
    GET.mockResolvedValueOnce({data: OFF});
    await readFreeDns(undefined, () => 100);
    GET.mockRejectedValue(new Error("offline"));
    expect(await readFreeDns(undefined, () => 200)).toEqual(OFF);
  });

  it("does not take a body that is not an answer as good", async () => {
    GET.mockResolvedValue({data: {enabled: "yes"}});
    await expect(readFreeDns(undefined, () => 0)).rejects.toThrow();
  });

  it("lets the page's own abort through instead of answering from memory", async () => {
    GET.mockResolvedValueOnce({data: ON});
    await readFreeDns(undefined, () => 0);
    const controller = new AbortController();
    controller.abort();
    GET.mockRejectedValue(new Error("aborted"));
    await expect(readFreeDns(controller.signal, () => 1)).rejects.toThrow("aborted");
  });
});
