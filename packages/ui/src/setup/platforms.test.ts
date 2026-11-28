import {describe, expect, it} from "vitest";

import {parseSetupOs} from "../dialog/dialogValues.ts";
import {PLATFORMS, parseSetupNav, setupOsValue} from "./platforms.ts";

// S7-r1-4: the version rides in `setupOs`, so a reload or a link opens the steps that were on screen.

describe("the version in setupOs", () => {
  it("reads a platform alone as its default version", () => {
    expect(parseSetupNav("windows")).toMatchObject({platform: {id: "windows"}, version: null});
    expect(parseSetupNav("apple-tv")).toMatchObject({platform: {id: "apple-tv"}, version: null});
  });
  it("reads the other versions, including those of a platform whose id has a hyphen", () => {
    expect(parseSetupNav("windows-10")).toMatchObject({platform: {id: "windows"}, version: "10"});
    expect(parseSetupNav("mac-12")).toMatchObject({platform: {id: "mac"}, version: "12"});
    expect(parseSetupNav("apple-tv-13")).toMatchObject({platform: {id: "apple-tv"}, version: "13"});
  });
  it("refuses a version the platform does not have, and the default spelled out", () => {
    expect(parseSetupNav("windows-98")).toBeNull();
    expect(parseSetupNav("windows-11")).toBeNull();
    expect(parseSetupNav("router-x")).toBeNull();
    expect(parseSetupNav(null)).toBeNull();
  });
  it("writes the default version as the bare id and any other as id-version, and reads both back", () => {
    for (const platform of PLATFORMS) {
      for (const version of platform.versions) {
        const value = setupOsValue(platform.id, version)!;
        expect(parseSetupOs(value)).toBe(value);
        const back = parseSetupNav(value)!;
        expect(back.platform.id).toBe(platform.id);
        expect(back.version ?? platform.versions[0]).toBe(version);
      }
    }
    expect(setupOsValue("windows", "11")).toBe("windows");
    expect(setupOsValue("windows", "10")).toBe("windows-10");
    expect(setupOsValue("windows", null)).toBe("windows");
    expect(setupOsValue(null, "10")).toBeNull();
  });
});
