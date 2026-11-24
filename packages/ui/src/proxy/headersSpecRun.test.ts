import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

import {defineE2eConfig} from "../testing/config.ts";

// gate-r13-1. The Caddy-only cases of headersSpec.ts run when E2E_BASE_URL is https over the mock projects (ci-web.sh step 10d, spec 15.5).
// E2E_MODE=stack builds one project that matches only *.stack.spec.ts, so headers.spec.ts is not selected at all there: a run in that mode
// shows no failure and no skip for these cases, and looks like a proof that never ran. These tests keep the file from sending a reader there.
const source = readFileSync(fileURLToPath(new URL("./headersSpec.ts", import.meta.url)), "utf8");

describe("how the Caddy-only cases of headersSpec.ts are run (gate-r13-1)", () => {
  it("headers.spec.ts is not part of the stack mode run, so no condition or skip reason may rely on it", () => {
    const stack = defineE2eConfig("panel", {E2E_MODE: "stack"});
    const match = (stack.projects ?? []).map((p) => p.testMatch);
    expect(match).toHaveLength(1);
    const pattern = match[0] as RegExp;
    expect(pattern.test("headers.spec.ts")).toBe(false);
    expect(pattern.test("headers.stack.spec.ts")).toBe(true);
    expect(source, "a condition on E2E_MODE would be a branch that never runs").not.toContain("process.env.E2E_MODE");
  });

  it("every skip reason of a Caddy-only case names the https base URL as the way to run it", () => {
    const reasons = [...source.matchAll(/test\.skip\(!throughCaddy, "([^"]*)"\)/g)].map((m) => m[1]!);
    expect(reasons.length, "the Caddy-only cases are there").toBeGreaterThanOrEqual(5);
    for (const reason of reasons) {
      expect(reason).toMatch(/E2E_BASE_URL set to an https address/);
      expect(reason, "never 'run it with E2E_MODE=stack'").not.toMatch(/\(E2E_MODE=stack\)/);
    }
  });

  // gate-r14-5. Only Caddy can put COOP, CORP, Permissions-Policy and a CSP on a /api/* answer, and the case that checks the four cannot run
  // before the merge, so what it asks for is pinned here: a bump or a tidy-up that drops the API paths from it would keep the Caddy run green
  // for a Caddyfile that put the lines inside the web handle.
  it("the Caddy case for the four headers asks for the API answers too: JSON with no session, the mux's 404 and its 301", () => {
    const start = source.indexOf("Caddy gives COOP, CORP, Permissions-Policy and the default CSP");
    const end = source.indexOf("// The ones that the proxy answered keep their own policy");
    expect(start, "the case is there").toBeGreaterThan(0);
    expect(end, "its second half is there").toBeGreaterThan(start);
    const body = source.slice(start, end);
    for (const path of ["/api/v1/nothing-here", "/api/v1/me", "/api/v1//me"]) expect(body, path).toContain(path);
    expect(body, "the 301 is asked for raw, since the request context would clean the path").toContain("rawGet(origin, API_ODD");
    for (const header of ["cross-origin-opener-policy", "cross-origin-resource-policy", "permissions-policy", "content-security-policy"]) {
      expect(body, header).toContain(header);
    }
  });
});

// gate-r19-2. The answers that Node and Caddy make with no Next code in the path (431, an absolute-form or asterisk target, Caddy's own 502) can only
// be seen in the Caddy run, so what they ask for is pinned here: a tidy-up that dropped one of them would leave that run green for a Caddyfile that
// misses it.
describe("the Caddy-only cases for answers made without Next (gate-r19-2)", () => {
  it("asks for the 431, both absolute-form spellings, the asterisk target and Caddy's own 502 or 504", () => {
    expect(source).toContain('"x".repeat(20_000)');
    expect(source).toContain("toBe(431)");
    expect(source).toContain('absolute("http")');
    expect(source).toContain('absolute("https")');
    expect(source).toContain('["the asterisk target", "*", "OPTIONS"]');
    expect(source).toContain("E2E_UPSTREAM_STOPPED");
    expect(source).toMatch(/\[502, 503, 504\]/);
  });
  it("skips the 502 case for a reason that names how to run it, and never lets it run without the stopped upstream", () => {
    expect(source).toMatch(/E2E_UPSTREAM_STOPPED=1 after `docker compose stop web-panel web-admin`/);
  });
});

// merge-r4-1, merge-r4-7, merge-r4-6. The stalled POST makes Next log an aborted body by design, which step 10d1 of ci-web.sh rejects in the main run, so the case
// runs only when asked for (after that step), and it asserts the status the edge gives, not only that something ended the request.
describe("the stalled POST case", () => {
  const start = source.indexOf("a POST body that is announced and never finished");
  const body = source.slice(start, source.indexOf("// gate-r2-8.", start));

  it("is skipped unless E2E_STALLED_POST=1, with a reason that names the step that runs it", () => {
    expect(start).toBeGreaterThan(-1);
    expect(body).toMatch(/test\.skip\(process\.env\.E2E_STALLED_POST !== "1"/);
    expect(body).toContain("step 10d1");
  });

  it("asserts the status and the headers of an answer, and that the request does not stay open", () => {
    expect(body).toContain('not.toBe("open")');
    expect(body).toContain("[408, 502, 504]");
    expect(body).toContain('one("content-security-policy")');
  });
});
