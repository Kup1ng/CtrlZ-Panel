import {describe, expect, it} from "vitest";

import {
  DOMAIN_MAX_LENGTH,
  EMPTY_APPLE_DRAFT,
  MAX_DOMAINS,
  MAX_SSIDS,
  domainProblem,
  normalizeDomain,
  requestOf,
  shareParamsOf,
  ssidProblem,
  utf8Length,
} from "./appleModel.ts";

// T-246, T-250: the builder's bounds and the request it makes.

describe("ssidProblem", () => {
  it("accepts a name of 1 to 32 bytes", () => {
    expect(ssidProblem("Home", [])).toBeNull();
    expect(ssidProblem("a".repeat(32), [])).toBeNull();
  });
  it("counts bytes, not characters: 17 Persian letters are 34 bytes", () => {
    const name = "ا".repeat(17);
    expect(utf8Length(name)).toBe(34);
    expect(ssidProblem(name, [])).toBe("too_long");
    expect(ssidProblem("ا".repeat(16), [])).toBeNull();
  });
  it("refuses an empty name, controls and format characters, and keeps the half-space", () => {
    expect(ssidProblem("   ", [])).toBe("empty");
    expect(ssidProblem("a\nb", [])).toBe("invalid");
    expect(ssidProblem("a‎b", [])).toBe("invalid");
    expect(ssidProblem("می‌خواهم", [])).toBeNull();
  });
  it("refuses a repeat and the 51st", () => {
    expect(ssidProblem("Home", ["Home"])).toBe("duplicate");
    expect(ssidProblem("new", Array.from({length: MAX_SSIDS}, (_, i) => `n${i}`))).toBe("full");
  });
});

describe("domains", () => {
  it("normalises what a person pastes", () => {
    expect(normalizeDomain(" HTTPS://Example.COM/path?x=1 ")).toBe("example.com");
    expect(normalizeDomain("*.example.com.")).toBe("example.com");
    expect(normalizeDomain("example.com:8443")).toBe("example.com");
  });
  it("accepts a host and refuses what is not one", () => {
    expect(domainProblem("example.com", [])).toBeNull();
    expect(domainProblem("", [])).toBe("empty");
    expect(domainProblem("a b.com", [])).toBe("invalid");
    expect(domainProblem("user@example.com", [])).toBe("invalid");
    expect(domainProblem("a".repeat(DOMAIN_MAX_LENGTH + 1), [])).toBe("too_long");
    expect(domainProblem("example.com", ["example.com"])).toBe("duplicate");
    expect(domainProblem("x.com", Array.from({length: MAX_DOMAINS}, (_, i) => `d${i}.com`))).toBe("full");
  });
});

describe("requestOf", () => {
  it("leaves out what is empty or off", () => {
    expect(requestOf(EMPTY_APPLE_DRAFT)).toEqual({protocol: "doh"});
  });
  it("carries every Advanced setting, Prevent Disablement included (T-250)", () => {
    expect(
      requestOf({client: "kids", protocol: "dot", ssids: ["Home"], domains: ["example.com"], folderId: "f", excludeCommon: true, prohibitDisablement: true}),
    ).toEqual({
      protocol: "dot",
      client: "kids",
      excluded_ssids: ["Home"],
      excluded_domains: ["example.com"],
      from_folder_id: "f",
      exclude_common: true,
      prohibit_disablement: true,
    });
  });
});

describe("shareParamsOf", () => {
  it("never carries a folder and takes the link's client", () => {
    const params = shareParamsOf({...EMPTY_APPLE_DRAFT, folderId: "f", client: "other", domains: ["a.com"]}, "kids");
    expect(params).toEqual({protocol: "doh", client: "kids", excluded_domains: ["a.com"]});
    expect("from_folder_id" in params).toBe(false);
  });
});
