import {readdirSync, readFileSync} from "node:fs";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import {describe, expect, it} from "vitest";

import enRules from "../../../../i18n/messages/en/rules.json";
import faRules from "../../../../i18n/messages/fa/rules.json";
import {
  addressProblem,
  blockCustomProblems,
  customBody,
  defaultActionOf,
  disableBody,
  freshUntil,
  ecsCustomProblems,
  isDisabledNow,
  isNoop,
  parseTtl,
  OPTION_ROWS,
  ROW_ICON,
  sameTarget,
  subnetProblem,
  SWITCH_OPTIONS,
  withLocation,
  switchPatch,
  TTL_OPTIONS,
  ttlProblem,
} from "./optionModel.ts";

// The rules of the Profile Options screen without a DOM (spec p2 9.7, 3.7). The API checks the same bounds last.

describe("rows", () => {
  it("are the fifteen of Plan, without AI Malware (D5) and Compatibility Mode (D9), and every one is a switch, a TTL or has its own row", () => {
    expect(OPTION_ROWS).toHaveLength(15);
    expect(OPTION_ROWS).not.toContain("ai_malware" as never);
    expect(OPTION_ROWS).not.toContain("compatibility_mode" as never);
    const own = ["default_rule", "block_response", "ecs", "disable", "lock"];
    for (const row of OPTION_ROWS) {
      const kinds = [(SWITCH_OPTIONS as readonly string[]).includes(row), (TTL_OPTIONS as readonly string[]).includes(row), own.includes(row)];
      expect(kinds.filter(Boolean), row).toHaveLength(1);
    }
  });

  it("have a name, a description and an explanation in both languages", () => {
    for (const messages of [enRules, faRules]) {
      for (const row of OPTION_ROWS) {
        const rows = messages.options.rows as Record<string, {name: string; description: string}>;
        const help = messages.options.help as Record<string, {title: string; body: string}>;
        expect(rows[row]?.name, row).toBeTruthy();
        expect(rows[row]?.description, row).toBeTruthy();
        expect(help[row]?.title, row).toBeTruthy();
        expect(help[row]?.body, row).toBeTruthy();
      }
    }
  });

  it("use an icon that exists in svg/options, and every file of that group is used", () => {
    const dir = join(fileURLToPath(new URL("../../../../icons/svg/options", import.meta.url)));
    const files = readdirSync(dir).map((f) => f.slice(0, -4));
    const slugs = OPTION_ROWS.filter((r) => r !== "lock").map((r) => ROW_ICON[r]);
    for (const slug of slugs) expect(files, slug).toContain(slug);
    expect([...new Set(slugs)].sort()).toEqual([...files].sort());
    expect(readFileSync(join(dir, "ttl.svg"), "utf8")).toContain("<svg");
  });
});

describe("TTL (T-204)", () => {
  it("takes whole seconds from 1 to 86,400", () => {
    expect(ttlProblem(1)).toBeNull();
    expect(ttlProblem(86_400)).toBeNull();
    expect(ttlProblem(0)).toBe("out_of_range");
    expect(ttlProblem(86_401)).toBe("out_of_range");
    expect(ttlProblem(1.5)).toBe("out_of_range");
    expect(ttlProblem(Number.NaN)).toBe("required");
    expect(ttlProblem(null)).toBe("required");
  });
});

describe("parseTtl", () => {
  it("reads Latin, Persian and Arabic-Indic digits, and nothing else", () => {
    expect(parseTtl("120")).toBe(120);
    expect(parseTtl("۱۲۰")).toBe(120);
    expect(parseTtl("١٢٠")).toBe(120);
    expect(parseTtl(" 60 ")).toBe(60);
    for (const bad of ["", "  ", "-5", "1.5", "1e3", "12a", "۱۲a", "1,00", "12,34,56", ",100", "1,0000", "1,,000"]) expect(parseTtl(bad), bad).toBeNaN();
  });

  // S2-r3-2: the hint prints the maximum with the separator of the language, and a reader may type it back as written.
  it("reads a value grouped in threes, as the hint prints it", () => {
    expect(parseTtl("1,000")).toBe(1000);
    expect(parseTtl("86,400")).toBe(86400);
    expect(parseTtl("۸۶٬۴۰۰")).toBe(86400);
    expect(parseTtl("٨٦٬٤٠٠")).toBe(86400);
    expect(parseTtl("86 400")).toBe(86400);
    expect(parseTtl("86 400")).toBe(86400);
    for (const locale of ["en", "fa-IR", "ar"]) expect(parseTtl(new Intl.NumberFormat(locale).format(86400)), locale).toBe(86400);
  });
});

describe("Block Response custom (T-205)", () => {
  it("needs one address of its own family, and either alone is enough", () => {
    expect(blockCustomProblems({v4: "203.0.113.7", v6: ""})).toEqual({});
    expect(blockCustomProblems({v4: "", v6: "2001:db8::1"})).toEqual({});
    expect(blockCustomProblems({v4: "", v6: ""})).toEqual({needOne: true});
    expect(blockCustomProblems({v4: "2001:db8::1", v6: ""})).toEqual({v4: "invalid"});
    expect(blockCustomProblems({v4: "", v6: "203.0.113.7"})).toEqual({v6: "invalid"});
    expect(blockCustomProblems({v4: "999.1.1.1", v6: "zzz"})).toEqual({v4: "invalid", v6: "invalid"});
  });

  it("sends only the fields that are filled", () => {
    expect(customBody({v4: "203.0.113.7", v6: ""})).toEqual({v4: "203.0.113.7"});
    expect(customBody({v4: "", v6: "::1"})).toEqual({v6: "::1"});
    expect(customBody({v4: "203.0.113.7", v6: "::1"})).toEqual({v4: "203.0.113.7", v6: "::1"});
  });

  it("addressProblem leaves an empty field to the 'at least one' rule", () => {
    expect(addressProblem("", 4)).toBeNull();
    expect(addressProblem("10.0.0.1", 4)).toBeNull();
    expect(addressProblem("10.0.0", 4)).toBe("invalid");
  });
});

describe("ECS subnets (T-210, spec p2 3.7)", () => {
  it("takes address/prefix of the field's family", () => {
    expect(subnetProblem("203.0.113.0/24", 4)).toBeNull();
    expect(subnetProblem("203.0.113.0", 4)).toBe("invalid");
    expect(subnetProblem("203.0.113.0/33", 4)).toBe("invalid");
    expect(subnetProblem("203.0.113.0/0", 4)).toBe("invalid");
    expect(subnetProblem("203.0.113.0/x", 4)).toBe("invalid");
    expect(subnetProblem("2001:db8::/48", 6)).toBeNull();
    expect(subnetProblem("2001:db8::/129", 6)).toBe("invalid");
    expect(subnetProblem("203.0.113.0/24", 6)).toBe("invalid");
    expect(subnetProblem("2001:db8::/48", 4)).toBe("invalid");
    expect(subnetProblem("", 4)).toBeNull();
  });

  it("refuses an IPv4 prefix with host bits, and takes the network address itself", () => {
    expect(subnetProblem("203.0.113.7/24", 4)).toBe("host_bits");
    expect(subnetProblem("203.0.113.0/24", 4)).toBeNull();
    expect(subnetProblem("203.0.113.128/25", 4)).toBeNull();
    expect(subnetProblem("203.0.113.129/25", 4)).toBe("host_bits");
    expect(subnetProblem("10.0.0.0/8", 4)).toBeNull();
    expect(subnetProblem("10.1.0.0/8", 4)).toBe("host_bits");
    expect(subnetProblem("203.0.113.1/32", 4)).toBeNull();
  });

  it("refuses an IPv6 prefix with host bits, in the written and the compressed form", () => {
    expect(subnetProblem("2001:db8::/32", 6)).toBeNull();
    expect(subnetProblem("2001:db8:1::/32", 6)).toBe("host_bits");
    expect(subnetProblem("2001:db8:0:0:0:0:0:0/32", 6)).toBeNull();
    expect(subnetProblem("2001:db8::1/48", 6)).toBe("host_bits");
    expect(subnetProblem("2001:db8:ffff::/33", 6)).toBe("host_bits");
    expect(subnetProblem("2001:db8:8000::/33", 6)).toBeNull();
    expect(subnetProblem("::/1", 6)).toBeNull();
    expect(subnetProblem("::1/128", 6)).toBeNull();
  });

  it("asks for at least one subnet", () => {
    expect(ecsCustomProblems({v4: "", v6: ""})).toEqual({needOne: true});
    expect(ecsCustomProblems({v4: "203.0.113.0/24", v6: ""})).toEqual({});
    expect(ecsCustomProblems({v4: "203.0.113.9/24", v6: "2001:db8::/48"})).toEqual({v4: "host_bits"});
  });
});

describe("Disable (T-138)", () => {
  const now = Date.parse("2026-11-26T10:00:00Z");
  it("reads a pause that has not ended as on", () => {
    expect(isDisabledNow("2026-11-26T10:05:00Z", now)).toBe(true);
    expect(isDisabledNow("2026-11-26T09:59:59Z", now)).toBe(false);
    expect(isDisabledNow(undefined, now)).toBe(false);
    expect(isDisabledNow("not a date", now)).toBe(false);
  });

  it("sends `for` for the three durations and `until` for a date, and nothing for Custom with no date", () => {
    expect(disableBody("5m", null)).toEqual({for: "5m"});
    expect(disableBody("1h", null)).toEqual({for: "1h"});
    expect(disableBody("1d", new Date("2026-12-01T00:00:00Z"))).toEqual({for: "1d"});
    expect(disableBody("custom", null)).toBeNull();
    expect(disableBody("custom", new Date("2026-12-01T00:00:00Z"))).toEqual({until: "2026-12-01T00:00:00.000Z"});
  });
});

describe("freshUntil", () => {
  const now = Date.parse("2026-12-01T12:00:00Z");
  it("keeps a date that is ahead and drops one that has passed, is now, or is not there", () => {
    const ahead = new Date("2026-12-01T12:00:01Z");
    expect(freshUntil(ahead, now)).toBe(ahead);
    expect(freshUntil(new Date("2026-12-01T11:59:59Z"), now)).toBeNull();
    expect(freshUntil(new Date(now), now)).toBeNull();
    expect(freshUntil(null, now)).toBeNull();
  });
});

describe("withLocation", () => {
  const set = [{id: "a", country: "DE", city: "Frankfurt"}, {id: "b", label: "Home lab"}];
  it("names the place of a target that carries only its id", () => {
    expect(withLocation({kind: "location", location_id: "a"}, set)?.location).toEqual({country: "DE", city: "Frankfurt"});
    expect(withLocation({kind: "location", location_id: "b"}, set)?.location).toEqual({label: "Home lab"});
  });
  it("leaves a target that has its place, an unknown id, and any other kind as they are", () => {
    const named = {kind: "location" as const, location_id: "a", location: {country: "NL"}};
    expect(withLocation(named, set)).toBe(named);
    const unknown = {kind: "location" as const, location_id: "zzz"};
    expect(withLocation(unknown, set)).toBe(unknown);
    const auto = {kind: "auto" as const};
    expect(withLocation(auto, set)).toBe(auto);
    expect(withLocation(undefined, set)).toBeUndefined();
    expect(withLocation(unknown, undefined)).toBe(unknown);
  });
});

describe("sameTarget", () => {
  it("compares the place a target names, not the words it carries", () => {
    expect(sameTarget({kind: "location", location_id: "a", location: {country: "NL"}}, {kind: "location", location_id: "a"})).toBe(true);
    expect(sameTarget({kind: "location", location_id: "a"}, {kind: "location", location_id: "b"})).toBe(false);
    expect(sameTarget({kind: "auto"}, {kind: "auto"})).toBe(true);
    expect(sameTarget({kind: "auto"}, {kind: "random"})).toBe(false);
    expect(sameTarget({kind: "ip", ipv4: "1.1.1.1"}, {kind: "ip", ipv4: "1.1.1.1"})).toBe(true);
    expect(sameTarget({kind: "ip", ipv4: "1.1.1.1"}, {kind: "ip", ipv4: "1.1.1.2"})).toBe(false);
    expect(sameTarget({kind: "host", host: "A.example.com"}, {kind: "host", host: "a.example.com"})).toBe(true);
    expect(sameTarget(undefined, null)).toBe(true);
    expect(sameTarget(undefined, {kind: "auto"})).toBe(false);
  });
});

describe("patches", () => {
  it("turns a switch on by setting it and off by clearing it (open question 3)", () => {
    expect(switchPatch("dns64", true)).toEqual({dns64: true});
    expect(switchPatch("dns64", false)).toEqual({clear: ["dns64"]});
  });

  it("treats an unset Default Rule as Bypass (SC 6)", () => {
    expect(defaultActionOf({default_location_unavailable: false})).toBe("bypass");
    expect(defaultActionOf({default_location_unavailable: false, default_rule: {action: "block"}})).toBe("block");
  });

  it("sees a patch that changes nothing", () => {
    const options = {default_location_unavailable: false, safe_search: true, block_ttl: 10};
    expect(isNoop(options, {safe_search: true})).toBe(true);
    expect(isNoop(options, {safe_search: false})).toBe(false);
    expect(isNoop(options, {clear: ["dns64"]})).toBe(true);
    expect(isNoop(options, {clear: ["block_ttl"]})).toBe(false);
  });
});
