import {readdirSync} from "node:fs";
import {join} from "node:path";
import {describe, expect, it} from "vitest";

import {isSignedInAuthPath} from "./signedInAuthPaths.ts";

describe("the pages of the auth layout a signed-in user lands on (wp4-r14-1)", () => {
  it("change-password and suspended keep their /me; the sign-in pages do not", () => {
    expect(isSignedInAuthPath("/change-password")).toBe(true);
    expect(isSignedInAuthPath("/suspended")).toBe(true);
    for (const p of ["/login", "/register", "/invite", "/forgot-password", "/change-passwords"]) {
      expect(isSignedInAuthPath(p)).toBe(false);
    }
  });

  it("every page folder of the (auth) layout is either listed here or a sign-in page", () => {
    // A page added to the layout must be placed on purpose: the reset drops the cached /me on every
    // page that is not listed.
    const dir = join(__dirname, "../../../../apps/panel/src/app/[locale]/(auth)");
    const folders = readdirSync(dir, {withFileTypes: true}).filter((d) => d.isDirectory()).map((d) => d.name);
    const signIn = ["forgot-password", "invite", "login", "register"];
    const signedIn = ["change-password", "suspended"];
    expect(folders.sort()).toEqual([...signIn, ...signedIn].sort());
    for (const f of signedIn) expect(isSignedInAuthPath(`/${f}`)).toBe(true);
    for (const f of signIn) expect(isSignedInAuthPath(`/${f}`)).toBe(false);
  });
});
