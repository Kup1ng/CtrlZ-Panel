import {describe, expect, it} from "vitest";

import {getPathname} from "./navigation.ts";

describe("navigation", () => {
  it("always prefixes the locale", () => {
    expect(getPathname({locale: "fa", href: "/login"})).toBe("/fa/login");
    expect(getPathname({locale: "en", href: "/profiles/abc"})).toBe("/en/profiles/abc");
  });
});
