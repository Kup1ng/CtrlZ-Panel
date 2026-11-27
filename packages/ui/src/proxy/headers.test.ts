import {describe, expect, it} from "vitest";

import {COOP, CORP, permissionsPolicy, securityHeaders} from "./headers.ts";

const features = (value: string) => Object.fromEntries(value.split(", ").map((p) => p.split("=")));

describe("securityHeaders (spec 15.1)", () => {
  it("sets COOP and CORP to same-origin", () => {
    expect(COOP).toBe("same-origin");
    expect(CORP).toBe("same-origin");
  });
  it("turns off camera, microphone and location, and allows passkeys and clipboard writes to the panel for this origin only", () => {
    expect(features(permissionsPolicy("panel"))).toEqual({
      camera: "()",
      microphone: "()",
      geolocation: "()",
      "publickey-credentials-get": "(self)",
      "publickey-credentials-create": "(self)",
      "clipboard-write": "(self)",
    });
  });
  // gate-r2-18: the admin has no passkey screen, and its host shares the passkey RP ID with the panel's.
  it("refuses passkey ceremonies to the admin and keeps its copy buttons", () => {
    expect(features(permissionsPolicy("admin"))).toEqual({
      camera: "()",
      microphone: "()",
      geolocation: "()",
      "publickey-credentials-get": "()",
      "publickey-credentials-create": "()",
      "clipboard-write": "(self)",
    });
  });
  it("drops interest-cohort, which is obsolete", () => {
    for (const app of ["panel", "admin"] as const) expect(permissionsPolicy(app)).not.toContain("interest-cohort");
  });
  it("allows no feature to another origin", () => {
    for (const app of ["panel", "admin"] as const) expect(permissionsPolicy(app)).not.toMatch(/https?:|\*/);
  });
  it("returns the three header names, with the policy of the app", () => {
    for (const app of ["panel", "admin"] as const) {
      expect(Object.keys(securityHeaders(app)).sort()).toEqual(["Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Permissions-Policy"]);
      expect(securityHeaders(app)["Permissions-Policy"]).toBe(permissionsPolicy(app));
    }
  });
});
