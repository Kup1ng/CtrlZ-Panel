import {MutationObserver, QueryClient, type InfiniteData} from "@tanstack/react-query";
import {describe, expect, it, vi} from "vitest";

import {ApiError} from "../errors.ts";
import {authorizedListQuery, canDeleteAuthorized, isClaimWaiting} from "./clients.ts";
import {defaultMode, filterState, withFilter, type CatalogFilter, type ProfileFilter} from "./filters.ts";
import {isJobFinished, isTerminalJobError, jobRefetchInterval} from "./jobs.ts";
import {exceededCap, capOf} from "./limits.ts";
import {needsLockPasswords, tooManyLockPasswords, withLockPasswords, wrongLockPasswordIndex} from "./lockPasswords.ts";
import {mapRows, noteLockedProfile, optimistic} from "./optimistic.ts";
import {applyOptionsPatch, optionUnitCount, type Options} from "./options.ts";
import {endpointKeys, profileKeys} from "./profileKeys.ts";
import {applySwitch, mapRulePages, ruleListQuery, searchTerm, type RulePage} from "./rules.ts";
import {groupByCategory, selectionAllowsRedirect, withService, writeTarget, type ProfileService} from "./services.ts";
import {filterKey, isUuid, jobOr, newIdempotencyKey, type Job} from "./support.ts";
import {tokenState} from "./apiTokens.ts";
import {isShareLive} from "./setup.ts";
import {createProfileOptions, disableProfileOptions, duplicateProfileOptions, enableProfileOptions, importProfileOptions, putProfile, type Profile} from "./profiles.ts";
import {runSessionEnd} from "../sessionEnd.ts";
import {afterRotateFailure, resetSetupCaches} from "./endpoints.ts";

const ID = "6f1c1b0e-8f35-4d57-9b8f-1d1c2a3b4c5d";
const job = (state: Job["state"]): Job => ({id: ID, kind: "upload", state, progress: 0, total: 5});

describe("support", () => {
  it("tells an id from anything else", () => {
    expect(isUuid(ID)).toBe(true);
    for (const v of [undefined, "", "x", "..", "profile-1", `${ID}x`, ID.toUpperCase().replace(/-/g, "")]) expect(isUuid(v as string | undefined), String(v)).toBe(false);
  });

  it("reads a job from the status and not from the shape", () => {
    expect(jobOr({data: {profile: {}, flagged: 0} as never, response: {status: 201}}).kind).toBe("done");
    expect(jobOr({data: job("queued"), response: {status: 202}}).kind).toBe("job");
    // A result that gained an id and a state is still a result at 200.
    expect(jobOr({data: job("done") as never, response: {status: 200}}).kind).toBe("done");
    expect(() => jobOr({response: {status: 200}})).toThrow();
  });

  it("makes one key per call, inside the schema's bound", () => {
    const a = newIdempotencyKey();
    expect(a).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
    expect(newIdempotencyKey()).not.toBe(a);
  });

  it("builds one canonical key from a filter, leaving out empty values", () => {
    expect(filterKey({q: "a", folder: "root"})).toBe(filterKey({folder: "root", q: "a"}));
    expect(filterKey({q: "", status: undefined, folder: "root", all: false})).toBe("folder=root");
    expect(filterKey({})).toBe("");
  });

  it("keeps every key part a string, so no object rides in a key", () => {
    const key = ruleListQuery(ID, {folder: "root", q: "x"}).queryKey;
    expect(key.every((p) => typeof p === "string")).toBe(true);
    expect(authorizedListQuery(ID, {q: "1.2"}).queryKey.every((p) => typeof p === "string")).toBe(true);
  });
});

describe("jobs", () => {
  it("polls every 2 seconds while a job runs and never once it has ended", () => {
    expect(isJobFinished(job("done"))).toBe(true);
    expect(isJobFinished(job("failed"))).toBe(true);
    expect(isJobFinished(job("running"))).toBe(false);
    expect(jobRefetchInterval(job("done"))).toBe(false);
    expect(jobRefetchInterval(job("failed"))).toBe(false);
    // With no input recorded yet the person counts as present (activity.ts), which is how a fresh page starts.
    expect([2000, false]).toContain(jobRefetchInterval(job("running")));
    expect([2000, false]).toContain(jobRefetchInterval(undefined));
  });

  // S1-r2-5: a job the API no longer knows (swept after 24 hours, or gone with its profile) is asked for once and not every 2 seconds.
  it("stops polling a job that answers 404 or another final 4xx, with or without an earlier answer", () => {
    for (const status of [400, 403, 404, 410]) {
      const error = new ApiError(status, status === 404 ? "not_found" : "validation_failed");
      expect(isTerminalJobError(error), String(status)).toBe(true);
      expect(jobRefetchInterval(undefined, error), String(status)).toBe(false);
      expect(jobRefetchInterval(job("running"), error), String(status)).toBe(false);
    }
  });

  it("keeps polling through an answer that may pass: 408, 429, 5xx and a network error", () => {
    for (const error of [new ApiError(408, "unknown"), new ApiError(429, "rate_limited"), new ApiError(503, "service_unavailable"), new ApiError(500, "unknown"), new TypeError("fetch failed"), null]) {
      expect(isTerminalJobError(error)).toBe(false);
      expect([2000, false]).toContain(jobRefetchInterval(job("running"), error));
    }
  });
});

describe("optimistic", () => {
  const rows = (): ProfileFilter[] => [{filter_id: "malware", enabled: false, mode: "relaxed"}];

  it("shows the change at once and puts the old value back on a refusal", async () => {
    const qc = new QueryClient();
    qc.setQueryData(profileKeys.filters(ID), rows());
    const o = optimistic<{enabled: boolean}>({
      queryClient: qc,
      keys: () => [profileKeys.filters(ID)],
      apply: (current, v) => withFilter(current as ProfileFilter[], "malware", v),
    });
    const context = await o.onMutate({enabled: true});
    expect(qc.getQueryData<ProfileFilter[]>(profileKeys.filters(ID))?.[0]?.enabled).toBe(true);
    o.onError(new ApiError(423, "profile_locked"), {enabled: true}, context);
    expect(qc.getQueryData<ProfileFilter[]>(profileKeys.filters(ID))?.[0]?.enabled).toBe(false);
  });

  it("changes every cached list under the prefix, and not a query that has no data yet", async () => {
    const qc = new QueryClient();
    qc.setQueryData(["x", "a"], [1]);
    qc.setQueryData(["x", "b"], [2]);
    const o = optimistic<number>({queryClient: qc, keys: [["x"]], apply: (cur, n) => (cur as number[]).map((v) => v + n)});
    await o.onMutate(10);
    expect(qc.getQueryData(["x", "a"])).toEqual([11]);
    expect(qc.getQueryData(["x", "b"])).toEqual([12]);
    expect(qc.getQueryData(["y"])).toBeUndefined();
  });

  it("calls onFail with the error after the restore, and invalidates on settle", async () => {
    const qc = new QueryClient();
    qc.setQueryData(["x"], [1]);
    const onFail = vi.fn();
    const spy = vi.spyOn(qc, "invalidateQueries");
    const o = optimistic<number>({queryClient: qc, keys: [["x"]], apply: (cur) => [(cur as number[])[0]! + 1], onFail});
    const context = await o.onMutate(1);
    const error = new ApiError(500, "internal");
    o.onError(error, 1, context);
    expect(onFail).toHaveBeenCalledWith(error, 1);
    expect(qc.getQueryData(["x"])).toEqual([1]);
    o.onSettled(undefined, undefined, 1);
    expect(spy).toHaveBeenCalledWith({queryKey: ["x"]});
  });

  it("S2-r2-7: an answer that comes after the session ended puts nothing back and refetches nothing", async () => {
    const qc = new QueryClient();
    qc.setQueryData(["x"], [1]);
    const spy = vi.spyOn(qc, "invalidateQueries");
    const o = optimistic<number>({queryClient: qc, keys: [["x"]], apply: (cur) => [(cur as number[])[0]! + 1]});
    const context = await o.onMutate(1);
    // The next person's data sits in the same cache by now.
    runSessionEnd();
    qc.setQueryData(["x"], [99]);
    o.onError(new ApiError(500, "internal"), 1, context);
    o.onSettled(undefined, undefined, 1, context);
    expect(qc.getQueryData(["x"])).toEqual([99]);
    expect(spy).not.toHaveBeenCalled();
  });

  it("S2-r2-7: putProfile adds a profile to the list only when it is new", () => {
    const qc = new QueryClient();
    const mine = {id: "a", name: "A"} as unknown as Profile;
    const stranger = {id: "b", name: "B"} as unknown as Profile;
    qc.setQueryData(profileKeys.list, [mine]);
    putProfile(qc, stranger);
    expect(qc.getQueryData<Profile[]>(profileKeys.list)).toEqual([mine]);
    putProfile(qc, stranger, {add: true});
    expect(qc.getQueryData<Profile[]>(profileKeys.list)).toEqual([stranger, mine]);
    putProfile(qc, {...mine, name: "A2"} as Profile);
    expect(qc.getQueryData<Profile[]>(profileKeys.list)?.[1]?.name).toBe("A2");
  });

  it("marks a quiet query stale after a good write without asking for it, and asks for it after a refused one", async () => {
    const qc = new QueryClient();
    qc.setQueryData(["x"], [1]);
    const spy = vi.spyOn(qc, "invalidateQueries");
    const o = optimistic<number>({queryClient: qc, keys: [["x"]], apply: (cur) => cur, settle: [], quiet: [["x"]]});
    o.onSettled(undefined, undefined, 1);
    expect(spy).toHaveBeenCalledWith({queryKey: ["x"], refetchType: "none"});
    spy.mockClear();
    o.onSettled(undefined, new ApiError(500, "internal"), 1);
    expect(spy).toHaveBeenCalledWith({queryKey: ["x"]});
  });

  it("gives apply the key of each query it changes, so a view can depend on its own filter", async () => {
    const qc = new QueryClient();
    qc.setQueryData(["x", "a"], [1]);
    qc.setQueryData(["x", "b"], [2]);
    const seen: unknown[] = [];
    const o = optimistic<number>({queryClient: qc, keys: [["x"]], apply: (cur, _n, key) => (seen.push(key[1]), cur)});
    await o.onMutate(0);
    expect(seen.sort()).toEqual(["a", "b"]);
  });

  it("leaves a value alone when apply returns undefined", async () => {
    const qc = new QueryClient();
    qc.setQueryData(["x"], {id: "a"});
    const o = optimistic<string>({queryClient: qc, keys: [["x"]], apply: () => undefined});
    await o.onMutate("b");
    expect(qc.getQueryData(["x"])).toEqual({id: "a"});
  });

  it("marks the profile for a fresh read when a write is refused with 423", () => {
    const qc = new QueryClient();
    const spy = vi.spyOn(qc, "invalidateQueries");
    noteLockedProfile(qc, ID, new ApiError(500, "internal"));
    expect(spy).not.toHaveBeenCalled();
    noteLockedProfile(qc, ID, new ApiError(423, "profile_locked"));
    expect(spy).toHaveBeenCalledWith({queryKey: profileKeys.detail(ID)});
    expect(spy).toHaveBeenCalledWith({queryKey: profileKeys.list});
  });

  it("maps the rows of a plain list and of an infinite one with the same function", () => {
    const pick = (page: unknown) => (page as {items?: number[]}).items;
    const put = (page: unknown, items: number[]) => ({...(page as object), items});
    expect(mapRows({items: [1, 2]}, pick, put, (n) => n * 2)).toEqual({items: [2, 4]});
    expect(mapRows({pages: [{items: [1]}, {items: [2]}], pageParams: []}, pick, put, (n) => n + 1)).toEqual({pages: [{items: [2]}, {items: [3]}], pageParams: []});
  });
});

describe("filters", () => {
  const modes: CatalogFilter["modes"] = [{mode: "relaxed", default: true}, {mode: "strict", default: false}];
  it("takes the default mode of a multi-mode filter and none for a one-mode filter", () => {
    expect(defaultMode({modes})).toBe("relaxed");
    expect(defaultMode({modes: []})).toBeUndefined();
  });

  it("adds a row, replaces a row, and keeps the remembered mode when a filter is switched off", () => {
    expect(withFilter([], "adult", {enabled: true, mode: "relaxed"})).toEqual([{filter_id: "adult", enabled: true, mode: "relaxed"}]);
    const on = withFilter([], "adult", {enabled: true, mode: "strict"});
    expect(withFilter(on, "adult", {enabled: false})).toEqual([{filter_id: "adult", enabled: false, mode: "strict"}]);
    expect(filterState(undefined, "adult")).toEqual({enabled: false});
    expect(filterState(on, "adult")).toEqual({enabled: true, mode: "strict"});
  });
});

describe("services", () => {
  const row = (slug: string, extra: Partial<ProfileService> = {}): ProfileService => ({slug, enabled: true, action: "block", location_unavailable: false, iranian_bypass: false, ...extra});

  it("replaces a service and keeps the flags that only the server sets", () => {
    const next = withService([row("a", {iranian_bypass: true})], {slug: "a", enabled: false, action: "bypass"});
    expect(next).toEqual([row("a", {iranian_bypass: true, enabled: false, action: "bypass"})]);
    expect(withService([], {slug: "b", enabled: true, action: "redirect", target: {kind: "auto"}})[0]).toMatchObject({slug: "b", target: {kind: "auto"}});
  });

  it("keeps the destination of a Redirect that is switched, and names a location by its id when it is written", () => {
    const target = {kind: "location" as const, location_id: "l1", location: {country: "DE", city: "Frankfurt"}};
    const old = row("a", {action: "redirect", target});
    expect(withService([old], {slug: "a", enabled: false, action: "redirect"})[0]).toMatchObject({enabled: false, action: "redirect", target});
    // A change to another action does not carry the old destination along.
    expect(withService([old], {slug: "a", enabled: true, action: "bypass"})[0]).not.toHaveProperty("target");
    expect(writeTarget(target)).toEqual({kind: "location", location_id: "l1"});
    expect(writeTarget({kind: "ip", ipv4: "203.0.113.7"})).toEqual({kind: "ip", ipv4: "203.0.113.7"});
  });

  it("offers Redirect for a selection only when every service may be redirected (T-521)", () => {
    expect(selectionAllowsRedirect([{redirect_allowed: true}, {redirect_allowed: true}])).toBe(true);
    expect(selectionAllowsRedirect([{redirect_allowed: true}, {redirect_allowed: false}])).toBe(false);
    expect(selectionAllowsRedirect([])).toBe(true);
  });

  it("groups by category in the order of the catalogue and drops a category with none", () => {
    const categories = [{id: "video", name_fa: "v", name_en: "Video"}, {id: "news", name_fa: "n", name_en: "News"}, {id: "empty", name_fa: "e", name_en: "Empty"}];
    const groups = groupByCategory(categories, [{category_id: "news", slug: "n1"}, {category_id: "video", slug: "v1"}, {category_id: "video", slug: "v2"}]);
    expect(groups.map((g) => [g.category.id, g.services.map((s) => s.slug)])).toEqual([["video", ["v1", "v2"]], ["news", ["n1"]]]);
  });
});

describe("options", () => {
  const options: Options = {default_location_unavailable: false, block_ttl: 30, safe_search: true, ecs: {mode: "auto"}};

  it("sets the fields of a patch and unsets the names in clear", () => {
    const next = applyOptionsPatch(options, {block_ttl: 60, clear: ["safe_search"]});
    expect(next).toEqual({default_location_unavailable: false, block_ttl: 60, ecs: {mode: "auto"}});
    expect(options.safe_search).toBe(true);
  });

  it("counts option units as the list does: the flag is not an option", () => {
    expect(optionUnitCount(options)).toBe(3);
    expect(optionUnitCount({default_location_unavailable: true})).toBe(0);
  });
});

describe("rules", () => {
  it("maps the rules of every loaded page without changing the argument", () => {
    const rule = (id: string, enabled: boolean) => ({id, enabled}) as RulePage["items"][number];
    const data: InfiniteData<RulePage, unknown> = {pages: [{items: [rule("1", true)]}, {items: [rule("2", true)]}], pageParams: [undefined, "c"]};
    const next = mapRulePages(data, (r) => (r.id === "2" ? {...r, enabled: false} : r));
    expect(next.pages[1]?.items[0]?.enabled).toBe(false);
    expect(data.pages[1]?.items[0]?.enabled).toBe(true);
  });

  it("takes a switched rule out of a view filtered by the state it left, and out of no other", () => {
    const rule = (id: string, enabled: boolean) => ({id, enabled}) as RulePage["items"][number];
    const data: InfiniteData<RulePage, unknown> = {pages: [{items: [rule("1", true), rule("2", true)], next_cursor: "c"}, {items: [rule("3", true)]}], pageParams: [undefined, "c"]};
    const ids = (d: InfiniteData<RulePage, unknown>) => d.pages.map((p) => p.items.map((r) => r.id).join(","));
    // Off in the view of the enabled: it leaves, and the cursor of the next page stays.
    const off = applySwitch(data, "2", false, "folder=root&status=enabled");
    expect(ids(off)).toEqual(["1", "3"]);
    expect(off.pages[0]?.next_cursor).toBe("c");
    // On in the view of the disabled: it leaves too.
    expect(ids(applySwitch({...data, pages: [{items: [rule("1", false)]}]}, "1", true, "status=disabled"))).toEqual([""]);
    // Off in the view of the disabled, in a view of every state, and in one filtered by action only: it stays, with the new state.
    for (const filter of ["status=disabled", "", "action=block", "folder=x&status=expired"]) {
      const next = applySwitch(data, "2", false, filter);
      expect(ids(next), filter).toEqual(["1,2", "3"]);
      expect(next.pages[0]?.items[1]?.enabled).toBe(false);
    }
  });

  it("trims a search and drops an empty one", () => {
    expect(searchTerm("  Example.COM ")).toBe("Example.COM");
    expect(searchTerm("   ")).toBeUndefined();
    expect(searchTerm("a".repeat(400))?.length).toBe(253);
  });
});

describe("lock passwords (p3 3.3)", () => {
  const missing = new ApiError(423, "profile_locked", undefined, undefined, [{name: "/lock_passwords", code: "required"}]);

  it("reads the three answers that concern a password", () => {
    expect(needsLockPasswords(missing)).toBe(true);
    expect(needsLockPasswords(new ApiError(423, "profile_locked"))).toBe(false);
    expect(wrongLockPasswordIndex(new ApiError(401, "invalid_credentials", undefined, undefined, [{name: "/lock_passwords/2", code: "invalid"}]))).toBe(2);
    expect(wrongLockPasswordIndex(new ApiError(401, "invalid_credentials"))).toBeNull();
    expect(tooManyLockPasswords(new ApiError(422, "validation_failed", undefined, undefined, [{name: "/lock_passwords", code: "exceeded"}]))).toBe(true);
  });

  it("leaves lock_passwords out of the body when there are none", () => {
    expect(withLockPasswords({a: 1}, undefined)).toEqual({a: 1});
    expect(withLockPasswords({a: 1}, [])).toEqual({a: 1});
    expect(withLockPasswords({a: 1}, [{profile_id: ID, password: "x"}])).toEqual({a: 1, lock_passwords: [{profile_id: ID, password: "x"}]});
  });
});

describe("limits", () => {
  it("finds the limit a 422 ran into and reads an unknown one as other", () => {
    const e = (name: string) => new ApiError(422, "validation_failed", undefined, undefined, [{name, code: "exceeded"}]);
    expect(exceededCap(e("max_profiles"))?.name).toBe("max_profiles");
    expect(exceededCap(e("/lock_passwords"))?.name).toBe("lock_passwords");
    expect(exceededCap(e("max_brand_new"))?.name).toBe("other");
    expect(exceededCap(new ApiError(422, "validation_failed", undefined, undefined, [{name: "x", code: "invalid"}]))).toBeNull();
    expect(exceededCap(new ApiError(500, "internal"))).toBeNull();
  });

  it("reads the number from the account's limits when it has it", () => {
    const limits = {max_profiles: 5} as never;
    expect(capOf(limits, "max_profiles")).toBe(5);
    expect(capOf(limits, "max_endpoints")).toBeUndefined();
    expect(capOf(limits, "other")).toBeUndefined();
    expect(capOf(undefined, "max_profiles")).toBeUndefined();
  });
});

describe("endpoint lists", () => {
  it("never lets the current address, or the last one under Require, be deleted", () => {
    expect(canDeleteAuthorized({is_current: true}, false, 5)).toBe(false);
    expect(canDeleteAuthorized({is_current: false}, true, 1)).toBe(false);
    expect(canDeleteAuthorized({is_current: false}, true, 2)).toBe(true);
    expect(canDeleteAuthorized({is_current: false}, false, 1)).toBe(true);
  });

  it("calls a claim waiting while it needs proof or is in its grace", () => {
    expect(isClaimWaiting({state: "pending_proof"})).toBe(true);
    expect(isClaimWaiting({state: "grace"})).toBe(true);
    expect(isClaimWaiting({state: "active"})).toBe(false);
    expect(isClaimWaiting({state: "suspended"})).toBe(false);
  });

  it("tells a live share link from a used, revoked or expired one", () => {
    const now = Date.parse("2026-11-25T00:00:00Z");
    const live = {revoked: false, uses: 0, max_uses: 3, expires_at: "2026-11-26T00:00:00Z"};
    expect(isShareLive(live, now)).toBe(true);
    expect(isShareLive({...live, revoked: true}, now)).toBe(false);
    expect(isShareLive({...live, uses: 3}, now)).toBe(false);
    expect(isShareLive({...live, expires_at: "2026-11-24T00:00:00Z"}, now)).toBe(false);
  });

  it("names an API token's state in one word", () => {
    const now = Date.parse("2026-11-25T00:00:00Z");
    expect(tokenState({ended: false, expires_at: "2027-01-01T00:00:00Z"}, now)).toBe("live");
    expect(tokenState({ended: false, expires_at: "2026-01-01T00:00:00Z"}, now)).toBe("expired");
    expect(tokenState({ended: true, expires_at: "2027-01-01T00:00:00Z"}, now)).toBe("ended");
  });
});

describe("the setup caches of an Endpoint", () => {
  const OTHER = "0a1b2c3d-8f35-4d57-9b8f-1d1c2a3b4c5d";
  const seed = () => {
    const client = new QueryClient();
    client.setQueryData(endpointKeys.resolvers(ID, ""), {doh: "token-1"});
    client.setQueryData(endpointKeys.generator(ID, "windows-doh", ""), {text: "token-1"});
    client.setQueryData(endpointKeys.generator(OTHER, "windows-doh", ""), {text: "other"});
    return client;
  };

  it("empties the Resolver view and the generator text of the Endpoint after a rotation, and leaves another Endpoint's", () => {
    const client = seed();
    resetSetupCaches(client, ID, true);
    expect(client.getQueryData(endpointKeys.resolvers(ID, ""))).toBeUndefined();
    expect(client.getQueryData(endpointKeys.generator(ID, "windows-doh", ""))).toBeUndefined();
    expect(client.getQueryData(endpointKeys.generator(OTHER, "windows-doh", ""))).toEqual({text: "other"});
  });

  it("S5-r2-10: a rotation whose answer is lost empties them, a definite refusal does not", () => {
    const refused = seed();
    expect(afterRotateFailure(refused, ID, new ApiError(423, "profile_locked"))).toBe(false);
    expect(refused.getQueryData(endpointKeys.resolvers(ID, ""))).toEqual({doh: "token-1"});

    for (const error of [new ApiError(503, "service_unavailable"), new ApiError(408, "unknown"), new TypeError("network")]) {
      const lost = seed();
      expect(afterRotateFailure(lost, ID, error)).toBe(true);
      expect(lost.getQueryData(endpointKeys.resolvers(ID, ""))).toBeUndefined();
      expect(lost.getQueryData(endpointKeys.generator(OTHER, "windows-doh", ""))).toEqual({text: "other"});
    }
  });

  it("marks them stale after a patch, so the next read asks again", () => {
    const client = seed();
    resetSetupCaches(client, ID);
    expect(client.getQueryState(endpointKeys.generator(ID, "windows-doh", ""))?.isInvalidated).toBe(true);
    expect(client.getQueryState(endpointKeys.generator(OTHER, "windows-doh", ""))?.isInvalidated).toBe(false);
  });

  it("covers every Endpoint when no id is given, as a batch edit does", () => {
    const client = seed();
    resetSetupCaches(client, undefined);
    expect(client.getQueryState(endpointKeys.generator(OTHER, "windows-doh", ""))?.isInvalidated).toBe(true);
  });
});

// S2-r3-5, S2-r3-6: a write that answers after the session ended. `queryClient.clear()` does not stop a mutation in flight, so its own callbacks
// would put the old person's profile into the next person's cache. Each hook's options run here with the request replaced by one that waits.
describe("S2-r3: a profile write that answers after the session ended", () => {
  const mine = {id: "a", name: "A"} as unknown as Profile;
  const theirs = {id: "b", name: "B"} as unknown as Profile;
  const next = {id: "c", name: "C"} as unknown as Profile;
  const created = {profile: theirs, flagged: 0} as never;
  const done = {kind: "done", data: {profile: theirs, flagged: 0}} as never;

  type After = <T>(value: T) => () => Promise<T>;
  async function answer(endSession: boolean, start: (qc: QueryClient, after: After) => Promise<unknown>) {
    const qc = new QueryClient();
    qc.setQueryData(profileKeys.list, [mine]);
    const invalidate = vi.spyOn(qc, "invalidateQueries");
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let sent!: () => void;
    const started = new Promise<void>((resolve) => (sent = resolve));
    const finished = start(qc, (value) => async () => {
      sent();
      await gate;
      return value;
    });
    // onMutate has run by the time the request goes out, so the guard of the write was taken in the first session.
    await started;
    if (endSession) {
      runSessionEnd();
      qc.setQueryData(profileKeys.list, [next]);
    }
    release();
    await finished;
    return {qc, invalidate};
  }

  const cases: {name: string; adds: boolean; start: (qc: QueryClient, after: After) => Promise<unknown>}[] = [
    {name: "create", adds: true, start: (qc, after) => new MutationObserver(qc, {...createProfileOptions(qc), mutationFn: after(created)}).mutate({name: "B", kind: "custom"})},
    {name: "import", adds: true, start: (qc, after) => new MutationObserver(qc, {...importProfileOptions(qc), mutationFn: after(done)}).mutate({document: "e30="})},
    {name: "duplicate", adds: true, start: (qc, after) => new MutationObserver(qc, {...duplicateProfileOptions(qc), mutationFn: after(done)}).mutate({id: "a", name: "B"})},
    {name: "disable", adds: false, start: (qc, after) => new MutationObserver(qc, {...disableProfileOptions(qc), mutationFn: after(theirs)}).mutate({id: "b", for: "5m"})},
    {name: "enable", adds: false, start: (qc, after) => new MutationObserver(qc, {...enableProfileOptions(qc), mutationFn: after(theirs)}).mutate("b")},
  ];

  for (const c of cases) {
    it(`${c.name}: the answer lands in the cache while the session is the same one`, async () => {
      const {qc} = await answer(false, c.start);
      expect(qc.getQueryData(profileKeys.detail("b"))).toEqual(theirs);
      if (c.adds) expect(qc.getQueryData<Profile[]>(profileKeys.list)).toEqual([theirs, mine]);
    });

    it(`${c.name}: the answer of a finished session puts nothing in the next person's cache and refetches nothing`, async () => {
      const {qc, invalidate} = await answer(true, c.start);
      expect(qc.getQueryData(profileKeys.detail("b"))).toBeUndefined();
      expect(qc.getQueryData<Profile[]>(profileKeys.list)).toEqual([next]);
      expect(invalidate).not.toHaveBeenCalled();
    });
  }
});
