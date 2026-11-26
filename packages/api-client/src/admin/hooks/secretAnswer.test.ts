import {readFileSync} from "node:fs";
import {join} from "node:path";

import {describe, expect, it} from "vitest";

// A class test for wp10-r6-2. TanStack awaits what `onSuccess` returns before `mutateAsync` resolves, and an invalidation resolves
// only when every loaded page of every matching query has been fetched again, retries included. A mutation whose answer holds a
// value that exists once and cannot be shown again (the console one-time password, the invite link) must therefore not return
// that promise: the value would wait behind an unrelated list refresh, and be lost if the dialog closed or the tab went meanwhile.
// The browser cases (admin-pages.spec.ts, "shown when the POST answers") drive a slow list; this one names the rule for the next hook.
const SECRET_ANSWERS: Record<string, string[]> = {
  "users.ts": ["useCreateUser"],
  "invites.ts": ["useCreateInvite"],
};

/** The source of one exported function, up to the next top-level export. */
function bodyOf(source: string, name: string): string {
  const start = source.indexOf(`export function ${name}(`);
  if (start < 0) throw new Error(`${name} is not exported`);
  const next = source.indexOf("\nexport ", start + 1);
  return source.slice(start, next < 0 ? undefined : next);
}

describe("a mutation that answers with a one-time secret", () => {
  for (const [file, hooks] of Object.entries(SECRET_ANSWERS)) {
    for (const hook of hooks) {
      it(`${hook} does not return the invalidation from onSuccess`, () => {
        const body = bodyOf(readFileSync(join(__dirname, file), "utf8"), hook);
        expect(body).toMatch(/onSuccess/);
        expect(body, "an arrow that returns the promise").not.toMatch(/onSuccess:\s*\([^)]*\)\s*=>(?!\s*\{)/);
        expect(body, "a return of the promise").not.toMatch(/return\s+queryClient\.invalidateQueries/);
        expect(body).toMatch(/void queryClient\.invalidateQueries/);
      });
    }
  }
});
