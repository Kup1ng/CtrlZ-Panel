import {describe, expect, it} from "vitest";

import {matches, type MockCall, type MockReply} from "./mock.ts";
import {createScreenState, LOCK_PASSWORD, screenHandlers, VALID_SHARE_LINK} from "./screenMock.ts";
import {catalogServicesFixture, rulesFixture, uid} from "./screenFixtures.ts";

// The mock of the P2 and P3 screens answers as the API does where a screen depends on it. These are the rules a lane builds on.

function makeApi(options?: Parameters<typeof createScreenState>[0]) {
  const state = createScreenState(options);
  const handlers = screenHandlers(state);
  const send = async (method: string, path: string, body?: unknown, query: Record<string, string> = {}): Promise<MockReply> => {
    const [pathname, search] = path.split("?");
    const call: MockCall = {method, path: pathname!, query: new URLSearchParams({...Object.fromEntries(new URLSearchParams(search ?? "")), ...query}), body, headers: {}, pageUrl: "https://panel.localhost/fa"};
    const keys = Object.keys(handlers).filter((k) => matches(k, call));
    const hit = keys.find((k) => !k.includes("{")) ?? keys[0];
    if (!hit) throw new Error(`no handler for ${method} ${path}`);
    return handlers[hit as keyof typeof handlers]!(call, undefined as never);
  };
  return {state, send};
}

const P1 = uid("pr", 1);
const P2 = uid("pr", 2); // locked
const E1 = uid("ep", 1);

describe("fixtures", () => {
  it("holds the volumes the lanes prove their lists on", () => {
    expect(catalogServicesFixture().filter((s) => s.category_id === "video")).toHaveLength(320 + 1); // 320 and Aparat
    expect(rulesFixture()).toHaveLength(10_000);
    expect(new Set(rulesFixture(500).map((r) => r.id)).size).toBe(500);
  });

  it("covers every state a screen draws", () => {
    const services = catalogServicesFixture();
    expect(services.some((s) => s.state === "deprecated")).toBe(true);
    expect(services.some((s) => !s.redirect_allowed)).toBe(true);
    expect(services.some((s) => s.risk_flag)).toBe(true);
    const {state} = makeApi();
    expect(state.profiles.some((p) => p.locked && p.lock_message)).toBe(true);
    expect(state.services.get(P1)!.some((s) => s.location_unavailable)).toBe(true);
    expect(state.services.get(P1)!.some((s) => s.iranian_bypass)).toBe(true);
    expect(state.endpoints.some((e) => e.admin_hold)).toBe(true);
    expect(state.endpoints.some((e) => e.status === "pending")).toBe(true);
    expect(state.claims.get(E1)!.some((c) => c.state === "pending_proof")).toBe(true);
    expect(state.clients.get(E1)).toHaveLength(1000);
  });
});

describe("paging", () => {
  it("pages the rules by cursor, the way the list asks, until the last page has none", async () => {
    const {send} = makeApi();
    let cursor: string | undefined;
    let seen = 0;
    for (let i = 0; i < 200; i++) {
      const r = await send("GET", `/profiles/${P1}/rules`, undefined, {limit: "100", ...(cursor ? {cursor} : {})});
      const body = r.body as {items: unknown[]; next_cursor?: string};
      seen += body.items.length;
      cursor = body.next_cursor;
      if (!cursor) break;
    }
    expect(seen).toBe(10_000);
  });

  it("filters the rules by folder, search, status and action on the server", async () => {
    const {send} = makeApi({rules: 500});
    const inFolder = (await send("GET", `/profiles/${P1}/rules`, undefined, {folder: uid("fo", 1), limit: "1000"})).body as {items: unknown[]};
    expect(inFolder.items).toHaveLength(120);
    const root = (await send("GET", `/profiles/${P1}/rules`, undefined, {folder: "root", limit: "1000"})).body as {items: unknown[]};
    expect(root.items).toHaveLength(500 - 120);
    const found = (await send("GET", `/profiles/${P1}/rules`, undefined, {q: "example10.com", limit: "1000"})).body as {items: {key: string}[]};
    expect(found.items.every((r) => r.key.includes("example10.com"))).toBe(true);
    const disabled = (await send("GET", `/profiles/${P1}/rules`, undefined, {status: "disabled", limit: "1000"})).body as {items: {enabled: boolean}[]};
    expect(disabled.items.length).toBeGreaterThan(0);
    expect(disabled.items.every((r) => !r.enabled)).toBe(true);
  });

  it("pages the clients and says how many match", async () => {
    const {send} = makeApi();
    const first = (await send("GET", `/endpoints/${E1}/clients`, undefined, {limit: "100"})).body as {items: unknown[]; count: number; next_cursor?: string};
    expect(first.items).toHaveLength(100);
    expect(first.count).toBe(1000);
    expect(first.next_cursor).toBeDefined();
    const inactive = (await send("GET", `/endpoints/${E1}/clients`, undefined, {inactive_days: "30", limit: "10"})).body as {count: number};
    expect(inactive.count).toBeGreaterThan(0);
    expect(inactive.count).toBeLessThan(1000);
  });
});

describe("the lock", () => {
  it("refuses every guarded write on a locked profile with 423, and a read is open", async () => {
    const {send} = makeApi();
    expect((await send("GET", `/profiles/${P2}/options`)).status).toBe(200);
    expect((await send("PUT", `/profiles/${P2}/filters/malware`, {enabled: true})).status).toBe(423);
    expect((await send("POST", `/profiles/${P2}/rules`, {patterns: ["a.com"], action: "block"})).status).toBe(423);
    expect((await send("PATCH", `/profiles/${P2}/options`, {safe_search: true})).status).toBe(423);
    expect((await send("DELETE", `/profiles/${P2}`)).status).toBe(423);
  });

  it("unlocks with the password only, and locks again with a bounded one", async () => {
    const {send, state} = makeApi();
    expect((await send("POST", `/profiles/${P2}/unlock`, {password: "wrong"})).status).toBe(401);
    expect((await send("POST", `/profiles/${P2}/unlock`, {password: LOCK_PASSWORD})).status).toBe(204);
    expect(state.profiles.find((p) => p.id === P2)!.locked).toBe(false);
    expect((await send("PUT", `/profiles/${P2}/filters/malware`, {enabled: true})).status).toBe(200);
    expect((await send("POST", `/profiles/${P2}/lock`, {password: "abc"})).body).toMatchObject({fields: [{name: "/password", code: "too_short"}]});
    expect((await send("POST", `/profiles/${P2}/lock`, {password: "a long enough one", message: "hold"})).status).toBe(204);
    expect(state.profiles.find((p) => p.id === P2)).toMatchObject({locked: true, lock_message: "hold"});
    expect((await send("POST", `/profiles/${P2}/lock`, {password: "again again"})).status).toBe(409);
  });

  it("asks for the lock password when an Endpoint change takes a locked profile away, and 401 for a wrong one", async () => {
    const {send} = makeApi();
    const office = uid("ep", 3); // on the locked profile
    const move = {profile_id: P1};
    expect((await send("PATCH", `/endpoints/${office}`, move)).body).toMatchObject({fields: [{name: "/lock_passwords", code: "required"}]});
    const wrong = await send("PATCH", `/endpoints/${office}`, {...move, lock_passwords: [{profile_id: P2, password: "nope"}]});
    expect(wrong.status).toBe(401);
    expect(wrong.body).toMatchObject({fields: [{name: "/lock_passwords/0", code: "invalid"}]});
    expect((await send("PATCH", `/endpoints/${office}`, {...move, lock_passwords: [{profile_id: P2, password: LOCK_PASSWORD}]})).status).toBe(200);
  });
});

describe("what the API refuses", () => {
  it("refuses a Redirect on a service that is never proxied and on an .ir name, and accepts a Block", async () => {
    const {send} = makeApi();
    expect((await send("PUT", `/profiles/${P1}/services/aparat`, {enabled: true, action: "redirect", target: {kind: "random"}})).body).toMatchObject({fields: [{code: "iranian_name"}]});
    expect((await send("PUT", `/profiles/${P1}/services/aparat`, {enabled: true, action: "block"})).status).toBe(200);
    expect((await send("POST", `/profiles/${P1}/rules`, {patterns: ["news.ir"], action: "redirect", target: {kind: "auto"}})).body).toMatchObject({fields: [{name: "/patterns/0", code: "iranian_name"}]});
    expect((await send("POST", `/profiles/${P1}/services:batch`, {op: "set", slugs: ["telegram", "aparat"], action: "redirect", target: {kind: "auto"}})).status).toBe(422);
  });

  it("refuses a limit with 422 exceeded on the limit's name, and a duplicate rule", async () => {
    const {send} = makeApi({limits: {max_profiles: 5}});
    expect((await send("POST", "/profiles", {name: "One more", kind: "custom"})).body).toMatchObject({fields: [{name: "max_profiles", code: "exceeded"}]});
    expect((await send("POST", `/profiles/${P1}/rules`, {patterns: ["example1.com"], action: "block"})).body).toMatchObject({fields: [{code: "exists"}]});
  });

  it("refuses a mode of another filter, a one-mode filter with a mode, and the unknown filter", async () => {
    const {send} = makeApi();
    expect((await send("PUT", `/profiles/${P1}/filters/malware`, {enabled: true, mode: "last_week"})).status).toBe(422);
    expect((await send("PUT", `/profiles/${P1}/filters/phishing`, {enabled: true, mode: "strict"})).status).toBe(422);
    expect((await send("PUT", `/profiles/${P1}/filters/nope`, {enabled: true})).status).toBe(422);
  });

  it("keeps a filter's mode when it is switched off, and gives the default mode on first enable", async () => {
    const {send} = makeApi();
    const on = (await send("PUT", `/profiles/${P1}/filters/ads-trackers`, {enabled: false})).body as {mode?: string};
    expect(on.mode).toBe("relaxed");
    const first = (await send("PUT", `/profiles/${uid("pr", 3)}/filters/malware`, {enabled: true})).body as {mode?: string};
    expect(first.mode).toBe("relaxed");
  });

  it("keeps the profile's Endpoints and counter in step with the Endpoint writes", async () => {
    const {state, send} = makeApi();
    const gaming = uid("pr", 3); // starts with no Endpoint
    const attached = () => state.profiles.find((x) => x.id === gaming)!;
    expect(attached().endpoints).toHaveLength(0);
    const made = ((await send("POST", "/endpoints", {type: "windows", names: ["Walk"], profile_id: gaming})).body as {endpoints: {id: string}[]}).endpoints[0]!;
    expect(attached().endpoints).toEqual([{id: made.id, name: "Walk"}]);
    expect(attached().counts.endpoints).toBe(1);
    expect((await send("GET", "/profiles")).body).toMatchObject({items: expect.arrayContaining([expect.objectContaining({id: gaming, counts: expect.objectContaining({endpoints: 1})})])});
    // The profile is in use now, so its delete is refused.
    expect((await send("DELETE", `/profiles/${gaming}`)).body).toMatchObject({code: "profile_in_use"});
    // A rename follows, a move takes it to the other profile, a delete empties the list again.
    await send("PATCH", `/endpoints/${made.id}`, {name: "Walked"});
    expect(attached().endpoints).toEqual([{id: made.id, name: "Walked"}]);
    await send("PATCH", `/endpoints/${made.id}`, {profile_id: P1});
    expect(attached().endpoints).toHaveLength(0);
    expect(attached().counts.endpoints).toBe(0);
    expect(state.profiles.find((x) => x.id === P1)!.endpoints.some((e) => e.id === made.id)).toBe(true);
    await send("POST", `/endpoints/${made.id}:delete`, {});
    expect(state.profiles.find((x) => x.id === P1)!.endpoints.some((e) => e.id === made.id)).toBe(false);
    expect((await send("DELETE", `/profiles/${gaming}`)).status).toBe(204);
  });

  it("refuses to delete a profile an Endpoint uses, and an Endpoint that is held", async () => {
    const {send} = makeApi();
    expect((await send("DELETE", `/profiles/${P1}`)).body).toMatchObject({code: "profile_in_use"});
    expect((await send("POST", `/endpoints/${uid("ep", 5)}:delete`, {})).body).toMatchObject({code: "endpoint_held"});
    expect((await send("POST", `/endpoints/${uid("ep", 6)}:delete`, {})).status).toBe(204);
  });

  it("refuses the current address and the last one under Require", async () => {
    const {send} = makeApi();
    expect((await send("POST", `/endpoints/${E1}/authorized-ips:delete`, {ids: [uid("au", 1)]})).body).toMatchObject({fields: [{code: "current_address"}]});
    expect((await send("POST", `/endpoints/${E1}/authorized-ips:delete`, {ids: [uid("au", 2)]})).status).toBe(204);
  });

  it("answers 404 for an id that is not the tenant's, the same for every kind", async () => {
    const {send} = makeApi();
    for (const path of ["/profiles/x", `/profiles/${uid("pr", 99)}`, `/endpoints/${uid("ep", 99)}`, `/profiles/${uid("pr", 99)}/rules`]) {
      expect((await send("GET", path)).status, path).toBe(404);
    }
  });
});

describe("the rules routes of the Rules screens (spec p2 8.3)", () => {
  const body = (reply: MockReply) => reply.body as Record<string, unknown>;

  it("reads a Geo Rule token as its kind, uppercases the country, and refuses the same key twice or a name that exists", async () => {
    const {send} = makeApi({rules: 200});
    const made = body(await send("POST", `/profiles/${P1}/rules`, {patterns: ["!#de", "new.test"], action: "block"}));
    expect((made.rules as {pattern: string; match_kind: string; negated: boolean}[]).map((r) => [r.pattern, r.match_kind, r.negated])).toEqual([["!#DE", "src_cc", true], ["new.test", "domain", false]]);
    expect((await send("POST", `/profiles/${P1}/rules`, {patterns: ["a.test", "A.test"], action: "block"})).status).toBe(422);
    const exists = await send("POST", `/profiles/${P1}/rules`, {patterns: ["example130.com"], action: "block"});
    expect(body(exists).fields).toEqual([{name: "/patterns/0", code: "exists"}]);
  });

  it("refuses inherit in a folder with no action, and a Folder Rule that goes while a rule follows it", async () => {
    const {send} = makeApi({rules: 200});
    const noAction = await send("POST", `/profiles/${P1}/rules`, {patterns: ["f.test"], action: "inherit", folder_id: uid("fo", 3)});
    expect(body(noAction).fields).toEqual([{name: "/action", code: "needs_folder_action"}]);
    await send("POST", `/profiles/${P1}/rules`, {patterns: ["follow.test"], action: "inherit", folder_id: uid("fo", 1)});
    const cleared = await send("PATCH", `/profiles/${P1}/folders/${uid("fo", 1)}`, {clear: ["action"]});
    expect(body(cleared).fields).toEqual([{name: "/clear/0", code: "has_inheriting_rules"}]);
  });

  it("counts the rules of a folder from the rules, and a selector batch acts on every match, not on a page", async () => {
    const {send, state} = makeApi({rules: 500});
    const folders = body(await send("GET", `/profiles/${P1}/folders`)).folders as {id: string; rule_count: number}[];
    expect(folders.find((f) => f.id === uid("fo", 1))?.rule_count).toBe(120);
    const result = body(await send("POST", `/profiles/${P1}/rules:batch`, {op: "disable", selector: {q: "example1"}}));
    expect(result.updated).toBe(state.rules.get(P1)!.filter((r) => r.key.includes("example1")).length);
    expect(state.rules.get(P1)!.filter((r) => r.key.includes("example1") && r.enabled)).toHaveLength(0);
  });

  it("copies to another profile with the conflict counted, moves into a new folder, and refuses a locked destination and a Copy inside the profile", async () => {
    const {send, state} = makeApi({rules: 200});
    const id = uid("ru", 130);
    const copied = body(await send("POST", `/profiles/${P1}/rules/${id}:transfer`, {op: "copy", dest_profile_id: uid("pr", 4), dest_root: true}));
    expect(copied.created).toBe(1);
    const again = body(await send("POST", `/profiles/${P1}/rules/${id}:transfer`, {op: "copy", dest_profile_id: uid("pr", 4), dest_root: true}));
    expect([again.created, again.conflict]).toEqual([0, 1]);
    expect((await send("POST", `/profiles/${P1}/rules/${id}:transfer`, {op: "copy", dest_profile_id: P2, dest_root: true})).status).toBe(423);
    expect((await send("POST", `/profiles/${P1}/rules/${id}:transfer`, {op: "copy", dest_root: true})).status).toBe(422);
    await send("POST", `/profiles/${P1}/rules/${id}:transfer`, {op: "move", new_folder: {name: "Fresh", kind: "standard"}});
    const fresh = state.folders.get(P1)!.find((f) => f.name === "Fresh")!;
    expect(state.rules.get(P1)!.find((r) => r.id === id)?.folder_id).toBe(fresh.id);
  });

  it("merges an uploaded file by mode, and refuses a file that is not a rules file with its pointer", async () => {
    const {send, state} = makeApi({rules: 200});
    const file = (rules: unknown[]) => btoa(JSON.stringify({format: "ctrlz-rules", version: 1, rules}));
    const folder = uid("fo", 2);
    const first = body(await send("POST", `/profiles/${P1}/folders/${folder}:upload`, {document: file([{pattern: "up.test", action: "block"}, {pattern: "example150.com", action: "block"}])}));
    expect([first.created, first.conflict]).toEqual([1, 1]);
    const second = body(await send("POST", `/profiles/${P1}/folders/${folder}:upload`, {document: file([{pattern: "up.test", action: "bypass"}]), mode: "upsert"}));
    expect(second.updated).toBe(1);
    expect(state.rules.get(P1)!.find((r) => r.key === "up.test")?.action).toBe("bypass");
    const bad = await send("POST", `/profiles/${P1}/folders/${folder}:upload`, {document: file([{pattern: "not a name", action: "block"}])});
    expect(body(bad).fields).toEqual([{name: "/rules/0/pattern", code: "pattern_invalid"}]);
  });
});

describe("jobs", () => {
  it("makes a job of a batch over 1,000 items, runs it on the next reads, and refuses a second one while it runs", async () => {
    const {send} = makeApi();
    const started = await send("POST", `/profiles/${P1}/rules:batch`, {op: "disable", selector: {}});
    expect(started.status).toBe(202);
    const job = started.body as {id: string; state: string};
    expect((await send("GET", "/jobs/active")).body).toMatchObject({job: {id: job.id}});
    expect((await send("POST", `/profiles/${P1}/rules:batch`, {op: "disable", selector: {}})).body).toMatchObject({code: "job_running"});
    expect(((await send("GET", `/jobs/${job.id}`)).body as {state: string}).state).toBe("running");
    expect(((await send("GET", `/jobs/${job.id}`)).body as {state: string}).state).toBe("done");
    expect((await send("GET", "/jobs/active")).body).toEqual({});
    expect((await send("GET", `/jobs/${uid("jb", 1)}`)).status).toBe(404);
  });

  it("runs a small batch inline", async () => {
    const {send} = makeApi({rules: 50});
    const r = await send("POST", `/profiles/${P1}/rules:batch`, {op: "delete", ids: [uid("ru", 1), uid("ru", 2)]});
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({updated: 2});
  });
});

describe("setup", () => {
  it("says a deployment with no zone is not ready and refuses to generate", async () => {
    const {send} = makeApi({resolverNotReady: true});
    expect((await send("GET", `/endpoints/${E1}/resolvers`)).body).toMatchObject({ready: false, reason: "zone_missing"});
    expect((await send("GET", `/endpoints/${E1}/generators`, undefined, {generator: "windows-doh"})).body).toMatchObject({code: "setup_unavailable"});
    expect((await send("POST", `/endpoints/${E1}/share-links`, {})).status).toBe(409);
  });

  it("opens a share link only for the value it made, and says nothing different for any other", async () => {
    const {send} = makeApi();
    expect((await send("POST", "/public/share", {link: VALID_SHARE_LINK})).status).toBe(200);
    const bad = await send("POST", "/public/share", {link: "x".repeat(64)});
    expect(bad.status).toBe(404);
    expect(bad.body).toMatchObject({code: "not_found"});
    expect((await send("GET", `/endpoints/${E1}/generators`, undefined, {generator: "nope"})).status).toBe(404);
  });
});
