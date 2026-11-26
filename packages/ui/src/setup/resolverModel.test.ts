import {resolverViewFixture} from "@ctrlz/api-client/testing/screenFixtures.ts";
import {RESOLVER_PROTOCOLS} from "@ctrlz/api-client/hooks/setup.ts";
import {describe, expect, it} from "vitest";

import {bootstrapList, listedProtocols, stampGroups} from "./resolverModel.ts";

// T-239, T-240, T-544: the order of what a person is given.

const two = resolverViewFixture({
  legacy: {dns1: "203.0.113.53", dns2: "203.0.113.54"},
  bootstrap: ["203.0.113.54", "203.0.113.53"],
  stamps: {
    // Address stamps come from the API in the wrong order on purpose: the page puts the primary's first.
    doh: {hostname_stamp: "sdns://h1", address_stamps: [{ip: "203.0.113.54", stamp: "sdns://b"}, {ip: "203.0.113.53", stamp: "sdns://a"}]},
    dot: {hostname_stamp: "sdns://h2", address_stamps: [{ip: "203.0.113.53", stamp: "sdns://c"}, {ip: "203.0.113.54", stamp: "sdns://d"}]},
    doq: {hostname_stamp: "sdns://h3", address_stamps: []},
  },
});

describe("stampGroups", () => {
  it("gives DoH, DoT and DoQ, each with the host name stamp apart from the address stamps", () => {
    const groups = stampGroups(two);
    expect(groups.map((g) => g.protocol)).toEqual(["doh", "dot", "doq"]);
    expect(groups.map((g) => g.hostname)).toEqual(["sdns://h1", "sdns://h2", "sdns://h3"]);
  });

  it("lists the primary's address stamp first, whatever order the API used", () => {
    const [doh, dot] = stampGroups(two);
    expect(doh!.addresses.map((a) => a.ip)).toEqual(["203.0.113.53", "203.0.113.54"]);
    expect(dot!.addresses.map((a) => a.ip)).toEqual(["203.0.113.53", "203.0.113.54"]);
  });

  it("has no DoH3 stamp: DoH3 is the DoH address with its own label (D51)", () => {
    expect(stampGroups(two).map((g) => g.protocol)).not.toContain("doh3");
  });
});

describe("bootstrapList", () => {
  it("puts the primary first", () => expect(bootstrapList(two)).toEqual(["203.0.113.53", "203.0.113.54"]));
});

describe("listedProtocols", () => {
  it("is exactly the five protocols of D24 and D51, in order", () => {
    expect(listedProtocols(two)).toEqual(["plain", "doh", "doh3", "dot", "doq"]);
    expect(listedProtocols(two)).toEqual([...RESOLVER_PROTOCOLS]);
  });

  it("never invents a protocol the view does not carry", () => {
    expect(listedProtocols(resolverViewFixture({protocols: ["plain", "doh"]}))).toEqual(["plain", "doh"]);
  });
});
