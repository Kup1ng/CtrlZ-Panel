import {readFileSync, readdirSync} from "node:fs";
import path from "node:path";

import {resolverViewFixture} from "@ctrlz/api-client/testing/screenFixtures.ts";
import {describe, expect, it} from "vitest";

import {GUIDE_LOADERS} from "./content/index.ts";
import {VALUE_KEYS, valueOf, type Guide} from "./guide.ts";
import {PLATFORMS, PLATFORM_IDS, automaticOf, versionOf} from "./platforms.ts";

// T-243: the platforms are exactly the fourteen of the Plan, each with steps in both languages. T-242: a version picker where a platform has
// two. T-544: a step never holds a typed address, host or URL, and never a mode that falls back to plaintext or checks no certificate.

const dir = path.join(import.meta.dirname, "content");
const read = (lang: string, id: string): Guide => JSON.parse(readFileSync(path.join(dir, lang, `${id}.json`), "utf8")) as Guide;

const PLAN_PLATFORMS = ["windows", "mac", "linux", "ios", "android", "chrome", "firefox", "edge", "brave", "apple-tv", "android-tv", "fire-tv", "samsung-tv", "router"];

describe("the platform list (T-243)", () => {
  it("is the fourteen of the Plan, once each, in order", () => expect(PLATFORM_IDS).toEqual(PLAN_PLATFORMS));

  it("has a content file in each language for each platform, and a loader for each", () => {
    for (const lang of ["fa", "en"] as const) {
      expect(readdirSync(path.join(dir, lang)).map((f) => f.slice(0, -5)).sort()).toEqual([...PLAN_PLATFORMS].sort());
      expect(Object.keys(GUIDE_LOADERS[lang]).sort()).toEqual([...PLAN_PLATFORMS].sort());
    }
  });

  it("names every id in the setupOs grammar of the address", () => {
    for (const id of PLATFORM_IDS) expect(id).toMatch(/^[a-z0-9][a-z0-9-]{0,31}$/);
  });
});

describe.each(PLATFORMS)("$id", (platform) => {
  const fa = read("fa", platform.id);
  const en = read("en", platform.id);

  it("has the versions the picker offers, in the same order in both languages (T-242)", () => {
    expect(fa.versions.map((v) => v.id)).toEqual([...platform.versions]);
    expect(en.versions.map((v) => v.id)).toEqual([...platform.versions]);
  });

  it("has the same steps in both languages: same count, same values shown, same link and verify marks", () => {
    for (const [index, version] of fa.versions.entries()) {
      const other = en.versions[index]!;
      expect(version.steps.length, version.id).toBeGreaterThanOrEqual(3);
      expect(other.steps.map((s) => [s.show ?? [], s.link ?? null, s.verify ?? false])).toEqual(version.steps.map((s) => [s.show ?? [], s.link ?? null, s.verify ?? false]));
      expect(version.name.trim()).not.toBe("");
      expect(other.name.trim()).not.toBe("");
    }
  });

  // The probe is a fetch from the page's own browser, so it tells about the device the page is open on. A TV is never that device (S7-r2-3): its
  // last step says so in text and carries no check, and a router's check is for a device behind it.
  it(platform.group === "tv" ? "ends a TV with a step of text and no verification (S7-r2-3)" : "ends every version with the verification, and has it once", () => {
    for (const lang of [fa, en]) {
      for (const version of lang.versions) {
        const marks = version.steps.map((s) => s.verify === true);
        if (platform.group === "tv") {
          expect(marks.filter(Boolean)).toHaveLength(0);
          continue;
        }
        expect(marks.filter(Boolean)).toHaveLength(1);
        expect(marks.at(-1)).toBe(true);
      }
    }
  });

  it("shows only values the Resolver view has, and holds no address, host or URL of its own (T-544)", () => {
    for (const lang of [fa, en]) {
      for (const version of lang.versions) {
        for (const step of version.steps) {
          for (const key of step.show ?? []) expect(VALUE_KEYS).toContain(key);
          const text = `${step.title} ${step.text}`;
          expect(text, text).not.toMatch(/https?:\/\//i);
          expect(text, text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
          expect(text, text).not.toMatch(/\bsdns:/i);
          // No setting that checks no certificate or falls back to plain DNS.
          expect(text, text).not.toMatch(/opportunistic|AllowFallbackToUdp\s*\$?True|trr\.mode\s*[12]\b|insecure/i);
        }
      }
    }
  });

  it("marks the claim of a network for the platforms set by address", () => {
    const byAddress = ["windows", "mac", "apple-tv", "android-tv", "fire-tv", "samsung-tv", "router"];
    for (const version of fa.versions) {
      const links = version.steps.filter((s) => s.link === "ips").length;
      if (byAddress.includes(platform.id)) {
        // Windows 11 is encrypted and needs no claim: only the address versions do.
        const encrypted = platform.id === "windows" && version.id === "11";
        expect(links > 0 || encrypted, `${platform.id} ${version.id}`).toBe(true);
      } else {
        expect(links, `${platform.id} ${version.id}`).toBe(0);
      }
    }
  });

  it("has a version for every automatic setup it names", () => {
    for (const id of Object.keys(platform.automatic)) expect(platform.versions).toContain(id);
    expect(versionOf(platform, "nonsense")).toBe(platform.versions[0]);
    expect(automaticOf(platform, platform.versions[0]!)).toBe(platform.automatic[platform.versions[0]!]);
  });
});

describe("what the guides promise (S7-r1-10)", () => {
  it("says what Windows 11 does with IPv6 DNS, in both languages, since Encrypted only covers the servers entered", () => {
    for (const lang of ["fa", "en"] as const) {
      const windows11 = read(lang, "windows").versions.find((v) => v.id === "11")!;
      const save = windows11.steps.at(-2)!;
      expect(save.text, lang).toMatch(/IPv6/);
      expect(save.text, lang).toMatch(/IPv4/);
    }
  });
  it("does not say that Linux DNS is always encrypted, in either language", () => {
    for (const lang of ["fa", "en"] as const) {
      const steps = read(lang, "linux").versions[0]!.steps;
      expect(steps[1]!.text, lang).toContain("Domains=~.");
      expect(steps[1]!.text, lang).not.toMatch(/always|همیشه/);
    }
  });
});

describe("valueOf", () => {
  const view = resolverViewFixture();
  it("gives the values of the view, the primary first", () => {
    expect(valueOf(view, "dns1")).toBe("203.0.113.53");
    expect(valueOf(view, "dns2")).toBe("203.0.113.54");
    expect(valueOf(view, "host")).toBe(view.host);
    expect(valueOf(view, "doh_url")).toBe(view.doh_url);
  });

  it("writes the resolved drop-in strict, with both hosts and DNSOverTLS=yes, never opportunistic", () => {
    const text = valueOf(view, "resolved_conf")!;
    expect(text).toContain(`DNS=203.0.113.53#${view.host} 203.0.113.54#${view.host}`);
    expect(text).toContain("DNSOverTLS=yes");
    expect(text).not.toMatch(/opportunistic/);
  });

  it("makes the drop-in the route for every name, so the network's own resolver is not asked (S7-r1-10)", () => {
    const text = valueOf(view, "resolved_conf")!;
    expect(text.split("\n")).toContain("Domains=~.");
    // It sits in the [Resolve] section, after the servers.
    expect(text.indexOf("Domains=~.")).toBeGreaterThan(text.indexOf("DNS="));
    expect(text.startsWith("[Resolve]\n")).toBe(true);
  });

  it("gives nothing for a view that is not ready", () => {
    const notReady = {ready: false, resolver_id: "r1", protocols: ["plain"]} as Parameters<typeof valueOf>[0];
    for (const key of VALUE_KEYS) expect(valueOf(notReady, key)).toBeUndefined();
  });
});
