import {describe, expect, it, vi} from "vitest";

const GET = vi.hoisted(() => vi.fn());
vi.mock("../client.ts", () => ({api: {GET}}));

import {probePanel} from "./status.ts";

// S8-r3-6: a connection that never answers must read as "not reachable" after a deadline, not leave the page on "Checking" for as long as
// the browser keeps the socket.

/** A request that answers only by being aborted, like a half-open socket. */
function hang(_path: string, init: {signal?: AbortSignal}) {
  return new Promise((_resolve, reject) => {
    init.signal?.addEventListener("abort", () => reject(init.signal?.reason), {once: true});
  });
}

describe("probePanel", () => {
  it("reads a request that never answers as unreachable once the deadline passes", async () => {
    GET.mockImplementation(hang);
    const probe = await probePanel(new AbortController().signal, 20);
    expect(probe).toMatchObject({reachable: false, degraded: false});
    expect(probe.ms).toBeGreaterThanOrEqual(10);
  });

  it("still lets the page's own abort through, which is no answer", async () => {
    GET.mockImplementation(hang);
    const controller = new AbortController();
    const pending = probePanel(controller.signal, 5_000);
    controller.abort(new Error("left the page"));
    await expect(pending).rejects.toThrow("left the page");
  });

  it("reads an answer as reachable", async () => {
    GET.mockResolvedValue({data: {}});
    expect(await probePanel(undefined, 5_000)).toMatchObject({reachable: true, degraded: false});
  });
});
