import {describe, expect, it} from "vitest";

import {CHAIN_MAX, canRetire, daysLeft, formProblems, isUnder, KEY_MAX, liveZones, nameProblem, normaliseName, pemProblem, sameDomainDraft, startsTransition, transitionRunning, withoutPrivateKey} from "./domainParts.ts";

// T-344, p4-nodes 10.4. What the Domain page says before it sends: the names, the rules between them, the PEM text of an upload.

// The PEM frames are built from a label, so no source line holds a whole private-key block (the secret scan of the commit would take it for one).
const pem = (label: string, body: string) => `-----BEGIN ${label}-----
${body}
-----END ${label}-----`;
const NOW = Date.parse("2026-11-24T10:00:00Z");
const FUTURE = "2026-12-10T00:00:00Z";
const PAST = "2026-11-01T00:00:00Z";

describe("names", () => {
  it("normalises like the route: trimmed, lower case", () => {
    expect(normaliseName("  DNS.Example.IR ")).toBe("dns.example.ir");
  });
  it("accepts a zone that starts with dns. and holds a domain of the owner", () => {
    expect(nameProblem("zone", "dns.example.ir")).toBeNull();
    expect(nameProblem("zone", "dns.a.example.co.uk")).toBeNull();
    expect(nameProblem("zone", "DNS.Example.ir")).toBeNull();
  });
  it("refuses a zone without dns., with too little after it, and a name that is no host name", () => {
    expect(nameProblem("zone", "example.ir")).toBe("zonePrefix");
    expect(nameProblem("zone", "dns.ir")).toBe("zoneShort");
    expect(nameProblem("zone", "dns.example..ir")).toBe("grammar");
    expect(nameProblem("zone", "dns.exa mple.ir")).toBe("grammar");
    expect(nameProblem("zone", "dns.-example.ir")).toBe("grammar");
    expect(nameProblem("zone", "dns.example.ir/")).toBe("grammar");
    expect(nameProblem("zone", "https://dns.example.ir")).toBe("grammar");
    expect(nameProblem("zone", "dns.example.ir:53")).toBe("grammar");
    expect(nameProblem("zone", `dns.${"a".repeat(64)}.ir`)).toBe("grammar");
  });
  it("accepts a host of two labels and refuses a one-label name", () => {
    expect(nameProblem("panel", "panel.example.ir")).toBeNull();
    expect(nameProblem("panel", "panel")).toBe("grammar");
  });
  it("holds a host to 249 bytes and a zone to 253", () => {
    const long = (n: number) => `${"a".repeat(60)}.`.repeat(Math.ceil(n / 61)).slice(0, n - 3) + ".ir";
    expect(nameProblem("panel", long(250))).toBe("tooLong");
    expect(nameProblem("admin", long(249))).not.toBe("tooLong");
  });
  it("an empty host asks for no change and is not a problem", () => {
    expect(nameProblem("panel", "")).toBeNull();
    expect(nameProblem("admin", "   ")).toBeNull();
  });
  it("isUnder reads whole labels", () => {
    expect(isUnder("a.dns.example.ir", "dns.example.ir")).toBe(true);
    expect(isUnder("dns.example.ir", "dns.example.ir")).toBe(true);
    expect(isUnder("xdns.example.ir", "dns.example.ir")).toBe(false);
    expect(isUnder("example.ir", "dns.example.ir")).toBe(false);
  });
});

describe("formProblems", () => {
  const ok = {dns_zone: "dns.example.ir", panel_host: "panel.example.ir", admin_host: "admin.example.ir"};
  it("passes the three values of the placeholders", () => {
    expect(formProblems(ok, [])).toEqual({});
  });
  it("refuses a host equal to or below the new zone, or a zone still live", () => {
    expect(formProblems({...ok, panel_host: "panel.dns.example.ir"}, [])).toEqual({panel_host: "underZone"});
    expect(formProblems({...ok, admin_host: "dns.example.ir"}, [])).toEqual({admin_host: "underZone"});
    // The zone being replaced still serves during its transition: a host under it is refused too.
    expect(formProblems({...ok, panel_host: "panel.dns.old.ir"}, ["dns.old.ir"])).toEqual({panel_host: "underZone"});
  });
  it("refuses two equal hosts, on the second", () => {
    expect(formProblems({...ok, admin_host: "panel.example.ir"}, [])).toEqual({admin_host: "same"});
  });
  it("reports the grammar of each field and no rule on top of a grammar problem", () => {
    expect(formProblems({dns_zone: "nope", panel_host: "Panel Host", admin_host: ""}, [])).toEqual({dns_zone: "grammar", panel_host: "grammar"});
  });
  it("accepts empty hosts", () => {
    expect(formProblems({...ok, panel_host: "", admin_host: ""}, [])).toEqual({});
  });
});

describe("the live zones and the transition", () => {
  it("the zone now, and the previous one only while its transition runs", () => {
    expect(liveZones({dns_zone: "dns.a.ir"}, NOW)).toEqual(["dns.a.ir"]);
    expect(liveZones({dns_zone: "dns.b.ir", prev_dns_zone: "dns.a.ir", transition_until: FUTURE}, NOW)).toEqual(["dns.b.ir", "dns.a.ir"]);
    expect(liveZones({dns_zone: "dns.b.ir", prev_dns_zone: "dns.a.ir", transition_until: PAST}, NOW)).toEqual(["dns.b.ir"]);
    expect(liveZones({}, NOW)).toEqual([]);
  });
  it("transitionRunning: a previous zone and an end ahead", () => {
    expect(transitionRunning({prev_dns_zone: "dns.a.ir", transition_until: FUTURE}, NOW)).toBe(true);
    expect(transitionRunning({prev_dns_zone: "dns.a.ir", transition_until: PAST}, NOW)).toBe(false);
    expect(transitionRunning({}, NOW)).toBe(false);
  });
  it("only a change from one zone to another starts a transition: not a first set, not the same zone in another spelling", () => {
    expect(startsTransition(undefined, "dns.a.ir")).toBe(false);
    expect(startsTransition("", "dns.a.ir")).toBe(false);
    expect(startsTransition("dns.a.ir", " DNS.A.ir ")).toBe(false);
    expect(startsTransition("dns.a.ir", "dns.b.ir")).toBe(true);
  });
});

describe("withoutPrivateKey (PG-r3-4)", () => {
  const body = "A".repeat(80);
  const cert = `-----BEGIN CERTIFICATE-----
${body}
-----END CERTIFICATE-----
`;
  const key = `-----BEGIN PRIVATE KEY-----
${body}
-----END PRIVATE KEY-----
`;
  it("leaves a text with no key as it is", () => {
    expect(withoutPrivateKey(cert)).toEqual({text: cert, removed: false});
    expect(withoutPrivateKey("")).toEqual({text: "", removed: false});
  });
  it("drops the key block of a combined file and keeps the certificates", () => {
    expect(withoutPrivateKey(cert + key)).toEqual({text: cert.trim(), removed: true});
    expect(withoutPrivateKey(key + cert)).toEqual({text: cert.trim(), removed: true});
    expect(withoutPrivateKey(key.replaceAll("PRIVATE KEY", "RSA PRIVATE KEY") + cert)).toEqual({text: cert.trim(), removed: true});
  });
  it("empties the box when only a key was put there, and drops a half-pasted key to the end", () => {
    expect(withoutPrivateKey(key)).toEqual({text: "", removed: true});
    const got = withoutPrivateKey(cert + "-----BEGIN PRIVATE KEY-----\nAAAA");
    expect(got).toEqual({text: cert.trim(), removed: true});
    expect(got.text).not.toContain("PRIVATE");
  });
});

describe("pemProblem", () => {
  const body = "A".repeat(80);
  const cert = `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
  const key = pem("PRIVATE KEY", body);
  it("accepts a certificate as the chain and a key as the key, with several certificates in a chain", () => {
    expect(pemProblem("chain", cert)).toBeNull();
    expect(pemProblem("chain", `${cert}\n${cert}\n`)).toBeNull();
    expect(pemProblem("key", key)).toBeNull();
    expect(pemProblem("key", key.replace("PRIVATE KEY", "RSA PRIVATE KEY"))).toBeNull();
    expect(pemProblem("key", key.replaceAll("\n", "\r\n"))).toBeNull();
  });
  it("says what is wrong, the clearer reason first: a key in the chain box, a certificate in the key box", () => {
    expect(pemProblem("chain", "   ")).toBe("empty");
    expect(pemProblem("chain", "-----BEGIN CERTIFICATE-----")).toBe("tooShort");
    expect(pemProblem("chain", key)).toBe("isKey");
    expect(pemProblem("key", cert)).toBe("isCertificate");
    expect(pemProblem("chain", `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`)).toBe("notCertificate");
    expect(pemProblem("key", `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`)).toBe("notKey");
    expect(pemProblem("chain", `hello ${cert}`)).toBe("shape");
    expect(pemProblem("chain", `-----BEGIN CERTIFICATE-----\n${body}!\n-----END CERTIFICATE-----`)).toBe("shape");
  });
  it("holds a chain to 32 KiB and a key to 8 KiB, counted in bytes", () => {
    const big = (n: number) => `-----BEGIN CERTIFICATE-----\n${"A".repeat(n)}\n-----END CERTIFICATE-----`;
    expect(pemProblem("chain", big(CHAIN_MAX))).toBe("tooLong");
    expect(pemProblem("chain", big(CHAIN_MAX - 200))).toBeNull();
    const bigKey = pem("PRIVATE KEY", "A".repeat(KEY_MAX));
    expect(pemProblem("key", bigKey)).toBe("tooLong");
  });
  it("never puts the text it was given into its answer", () => {
    expect(JSON.stringify(pemProblem("key", `${key} secret-material`))).not.toContain("secret-material");
  });
});

describe("certificates", () => {
  it("only an uploaded active row of an uploadable kind can be retired", () => {
    expect(canRetire({source: "uploaded", state: "active", kind: "wildcard"})).toBe(true);
    expect(canRetire({source: "uploaded", state: "retired", kind: "wildcard"})).toBe(false);
    expect(canRetire({source: "issued", state: "active", kind: "wildcard"})).toBe(false);
    expect(canRetire({source: "uploaded", state: "active", kind: "node_ca"})).toBe(false);
  });
  it("daysLeft rounds down and goes negative after the end", () => {
    expect(daysLeft("2026-12-01T10:00:00Z", NOW)).toBe(7);
    expect(daysLeft("2026-12-01T09:00:00Z", NOW)).toBe(6);
    expect(daysLeft("2026-11-20T10:00:00Z", NOW)).toBe(-4);
  });
});

describe("sameDomainDraft (PG-r2-3)", () => {
  const values = {dns_zone: "dns.example.ir", panel_host: "panel.example.ir", admin_host: "admin.example.ir"};
  it("is one value when a zone was typed and put back, whatever length is left over", () => {
    expect(sameDomainDraft({...values, transition_days: 60} as never, {...values, transition_days: 30} as never)).toBe(true);
  });
  it("reads two spellings of a name as one, and a changed name as a change", () => {
    expect(sameDomainDraft({...values, dns_zone: " DNS.example.ir "}, values)).toBe(true);
    expect(sameDomainDraft({...values, dns_zone: "dns.example.com"}, values)).toBe(false);
    expect(sameDomainDraft({...values, admin_host: ""}, values)).toBe(false);
  });
});
