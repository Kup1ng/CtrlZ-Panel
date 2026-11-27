import {QueryClient} from "@tanstack/react-query";
import {afterEach, describe, expect, it, vi} from "vitest";

import {createApiClient} from "../core.ts";
import type {paths} from "../generated/admin";
import {adminMeFixture} from "../testing/fixtures.ts";
import {adminClockKeys, CLOCK_SKEW_LIMIT_MS, serverClockOffset, skewIsWarning} from "./clockSkew.ts";
import {adminMeQueryOptions} from "./session.ts";

// Spec 7.10 and 11.9 (T-088): the admin shell compares the `Date` header of GET /me with the browser clock and warns above 30 s.
// The browser clock is faked (vi.setSystemTime), so each case says what the page's clock is and what the server's `Date` is.

afterEach(() => vi.useRealTimers());

const BROWSER_NOW = Date.parse("2026-11-26T10:00:00Z");

/** The admin client over a fake server whose /me answers with the given `Date` header (none when it is undefined). */
function meWithDate(serverDate: string | undefined) {
  const fetch = async () =>
    new Response(JSON.stringify(adminMeFixture()), {
      status: 200,
      headers: {"content-type": "application/json", ...(serverDate ? {Date: serverDate} : {})},
    });
  return createApiClient<paths>({baseUrl: "http://admin.test/api/v1", fetch, refresh: false});
}

/** Log in on a browser whose clock reads BROWSER_NOW and a server whose clock is `serverAheadMs` ahead of it. */
async function skewAfterMe(serverAheadMs: number | "no-date" | "garbage"): Promise<number | null | undefined> {
  vi.useFakeTimers();
  vi.setSystemTime(BROWSER_NOW);
  const header = serverAheadMs === "no-date" ? undefined : serverAheadMs === "garbage" ? "not a date" : new Date(BROWSER_NOW + serverAheadMs).toUTCString();
  const client = new QueryClient();
  await client.fetchQuery(adminMeQueryOptions(meWithDate(header)));
  return client.getQueryData<number | null>(adminClockKeys.skew);
}

describe("the clock offset of /me", () => {
  it("is the server's Date minus the browser clock, at the middle of the request", () => {
    expect(serverClockOffset(new Date(BROWSER_NOW + 40_000).toUTCString(), BROWSER_NOW, BROWSER_NOW)).toBe(40_000);
    // A slow answer (2 s) does not read as a wrong clock: the header was written somewhere in the middle.
    expect(serverClockOffset(new Date(BROWSER_NOW + 1_000).toUTCString(), BROWSER_NOW, BROWSER_NOW + 2_000)).toBe(0);
  });

  it("says nothing for a missing or unreadable Date", () => {
    expect(serverClockOffset(null, 0, 0)).toBeUndefined();
    expect(serverClockOffset("", 0, 0)).toBeUndefined();
    expect(serverClockOffset("tomorrow-ish", 0, 0)).toBeUndefined();
  });

  it("warns above 30 s in either direction and not at or below it", () => {
    expect(CLOCK_SKEW_LIMIT_MS).toBe(30_000);
    expect(skewIsWarning(30_000)).toBe(false);
    expect(skewIsWarning(-30_000)).toBe(false);
    expect(skewIsWarning(30_001)).toBe(true);
    expect(skewIsWarning(-30_001)).toBe(true);
    expect(skewIsWarning(undefined)).toBe(false);
  });
});

describe("GET /me records the offset against the faked browser clock", () => {
  it("a browser 45 s behind the server warns", async () => {
    const offset = await skewAfterMe(45_000);
    expect(offset).toBe(45_000);
    expect(skewIsWarning(offset ?? undefined)).toBe(true);
  });

  it("a browser 45 s ahead of the server warns", async () => {
    const offset = await skewAfterMe(-45_000);
    expect(offset).toBe(-45_000);
    expect(skewIsWarning(offset ?? undefined)).toBe(true);
  });

  it("a browser a few seconds off does not warn", async () => {
    const offset = await skewAfterMe(5_000);
    expect(offset).toBe(5_000);
    expect(skewIsWarning(offset ?? undefined)).toBe(false);
  });

  it("an answer with no usable Date clears an earlier warning instead of keeping it", async () => {
    expect(await skewAfterMe("garbage")).toBeNull();
    expect(await skewAfterMe("no-date")).toBeNull();
  });

  it("the latest /me wins: a clock that was fixed stops warning", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(BROWSER_NOW);
    const client = new QueryClient();
    await client.fetchQuery({...adminMeQueryOptions(meWithDate(new Date(BROWSER_NOW + 90_000).toUTCString())), staleTime: 0});
    expect(skewIsWarning(client.getQueryData<number | null>(adminClockKeys.skew) ?? undefined)).toBe(true);
    await client.fetchQuery({...adminMeQueryOptions(meWithDate(new Date(BROWSER_NOW).toUTCString())), staleTime: 0});
    expect(skewIsWarning(client.getQueryData<number | null>(adminClockKeys.skew) ?? undefined)).toBe(false);
  });
});
