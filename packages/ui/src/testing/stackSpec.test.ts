import {readFileSync} from "node:fs";
import {describe, expect, it} from "vitest";

// A static check of the stack-mode specs, which cannot run before the merge (they need the Compose stack). The
// failure it guards is the one of wp8-r4-4: a test that waits for TOTP windows (up to 30.5 s each) ran into
// the 60 s timeout of stack mode inside its cleanup, which left the seeded user with TOTP on and broke every
// later test with an error that did not point back to it. Three rules close the class for every test in the file:
//
//  1. A test that waits for a window (`nextStep`) sets its own timeout.
//  2. A cleanup (`finally`, or a helper called from one) never waits for a window.
//  3. A test that adds something to the shared seeded user (a passkey, TOTP) removes it in a `finally` block
//     (wp8-r5-8): a cleanup after the last step runs only when every step before it passed.
//
// The same rules guard account.stack.spec.ts (wp9-r5-1): it enables TOTP and adds a passkey on the same shared
// user, so its cleanup is a finally block too, and a test that enables TOTP gets at least 120 s whether or not
// it waits, because a first real run is slow. A window wait (`nextStep`, or a sleep to the next 30 s boundary)
// is not allowed in account.stack.spec.ts at all: its cleanup works with recovery codes.
//
// This file sits in the testing folder that WP12 owns, although WP8 wrote it (wp8-r5-6): it guards the stack
// specs and should move next to them, or stay with WP12, when the stack is first run.

const windowWait = /nextStep|30_000 - \(Date\.now/;

const specs = [
  {
    file: "auth.stack.spec.ts",
    // What marks a test as adding something to the shared user.
    adds: /passkeys\/finish|totp\/confirm|enableTotp\(/,
    // A test that waits for a window must set its own timeout.
    waits: /nextStep\(\)/,
  },
  {
    file: "account.stack.spec.ts",
    adds: /totp\/confirm|passkeys\.create|totp\.enable/,
    // The account spec never waits for a window, so every test that enables TOTP is held to the roomy timeout.
    waits: /totp\/confirm|totp\.enable/,
  },
];

/** The text of a top-level `async function name` up to its closing brace at column 0. */
function functionBody(source: string, name: string): string {
  const start = source.indexOf(`async function ${name}(`);
  expect(start, `${name} exists`).toBeGreaterThan(-1);
  return source.slice(start, source.indexOf("\n}\n", start));
}

/** Each `test("...", async (...) => { ... });` block, split on the two-space indent that Prettier gives it. */
function testBlocks(source: string): string[] {
  return source.split(/\n(?=  test\()/).slice(1);
}

for (const spec of specs) {
  const source = readFileSync(new URL(`../../../../apps/panel/e2e/${spec.file}`, import.meta.url), "utf8");

  describe(`${spec.file} timing and cleanup`, () => {
    it("never waits for a TOTP window inside a helper that a finally block calls", () => {
      expect(functionBody(source, "removeTotp")).not.toMatch(windowWait);
    });

    it("never waits for a TOTP window in a finally block", () => {
      const finals = [...source.matchAll(/finally \{([\s\S]*?)\n\s{4}\}/g)];
      expect(finals.length).toBeGreaterThan(0);
      for (const block of finals) expect(block[1]).not.toMatch(windowWait);
    });

    it("gives every test that waits for a window, or enables TOTP, a timeout of its own", () => {
      const waiting = testBlocks(source).filter((block) => spec.waits.test(block));
      expect(waiting.length).toBeGreaterThan(0);
      for (const block of waiting) {
        const title = block.split("\n")[0];
        const found = /test\.setTimeout\((\d[\d_]*)\)/.exec(block);
        expect(found, title).not.toBeNull();
        // Two windows and the page flows around them, with room.
        expect(Number(found![1]!.replace(/_/g, "")), title).toBeGreaterThanOrEqual(120_000);
      }
    });

    it("removes what a test added to the shared user inside a finally block", () => {
      const adding = testBlocks(source).filter((block) => spec.adds.test(block));
      expect(adding.length).toBeGreaterThan(0);
      for (const block of adding) {
        expect(block, block.split("\n")[0]).toMatch(/finally \{[\s\S]*?(removePasskeys|removeTotp)\(/);
      }
    });

    it("checks every delete and the empty list in the passkey cleanup", () => {
      const body = functionBody(source, "removePasskeys");
      expect(body).toContain("toBe(204)");
      expect(body).toContain("toEqual([])");
    });
  });
}

describe("account.stack.spec.ts has no window wait at all", () => {
  it("disables TOTP by recovery codes, never by a clock", () => {
    const source = readFileSync(new URL("../../../../apps/panel/e2e/account.stack.spec.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(windowWait);
    expect(functionBody(source, "removeTotp")).toContain("recovery_code");
  });
});
