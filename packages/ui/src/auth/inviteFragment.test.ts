import {describe, expect, it} from "vitest";

import {hashOfHashChange} from "./inviteFragment.ts";

describe("hashOfHashChange", () => {
  it("reads the fragment from newURL, whatever the current address says", () => {
    expect(hashOfHashChange("https://panel.example/fa/invite#ABCD-EFGH", "")).toBe("#ABCD-EFGH");
    expect(hashOfHashChange("http://localhost:3420/en/invite?x=1#---", "#other")).toBe("#---");
  });

  it("is empty for an address with no fragment, even when the current one has one", () => {
    expect(hashOfHashChange("http://localhost:3420/fa/invite", "#late")).toBe("");
  });

  it("falls back to the current fragment when there is no usable newURL", () => {
    expect(hashOfHashChange(undefined, "#here")).toBe("#here");
    expect(hashOfHashChange("not a url", "#here")).toBe("#here");
  });
});
