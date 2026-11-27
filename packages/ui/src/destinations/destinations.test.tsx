import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {NextIntlClientProvider} from "next-intl";
import type {ReactNode} from "react";
import {renderToString} from "react-dom/server";
import {describe, expect, it} from "vitest";

import commonEn from "../../../i18n/messages/en/common.json";
import errorsEn from "../../../i18n/messages/en/errors.json";
import feedbackEn from "../../../i18n/messages/en/feedback.json";
import servicesEn from "../../../i18n/messages/en/services.json";
import servicesFa from "../../../i18n/messages/fa/services.json";
import {DestinationsFields} from "./DestinationsDialog.tsx";
import {
  bucketSlugs,
  chunkSlugs,
  draftOf,
  draftProblems,
  EMPTY_DRAFT,
  filterGroups,
  groupLocations,
  intersectLocations,
  targetFits,
  isHostName,
  isIPv4,
  isIPv6,
  targetOf,
  type DestinationDraft,
} from "./destinations.ts";

const L = (id: string, rest: {country?: string; city?: string; label?: string}) => ({id, ...rest});
const SET = [
  L("1", {country: "DE"}),
  L("2", {country: "DE", city: "Frankfurt"}),
  L("3", {country: "DE", city: "Berlin"}),
  L("4", {country: "NL"}),
  L("5", {label: "Home lab"}),
  L("6", {country: "FR", city: "Paris"}),
];
const names: Record<string, string> = {DE: "Germany", NL: "Netherlands", FR: "France"};
const collator = new Intl.Collator("en");
const fold = (s: string) => s.toLowerCase();

describe("grouping and search", () => {
  const groups = groupLocations(SET, (c) => names[c] ?? c, collator);

  it("groups by country, sorted by the country's name, with the label-only location last", () => {
    expect(groups.map((g) => g.name)).toEqual(["France", "Germany", "Netherlands", "Home lab"]);
    const de = groups.find((g) => g.country === "DE")!;
    expect(de.whole?.id).toBe("1");
    expect(de.cities.map((c) => c.city)).toEqual(["Berlin", "Frankfurt"]);
    expect(groups.find((g) => g.country === "FR")!.whole).toBeUndefined();
    expect(groups.at(-1)!.label?.id).toBe("5");
  });

  it("finds a country by its name or code, and a city by its name, keeping only that city", () => {
    expect(filterGroups(groups, "germ", fold).map((g) => g.name)).toEqual(["Germany"]);
    expect(filterGroups(groups, "nl", fold).map((g) => g.name)).toEqual(["Netherlands"]);
    const city = filterGroups(groups, "frank", fold);
    expect(city).toHaveLength(1);
    expect(city[0]!.cities.map((c) => c.city)).toEqual(["Frankfurt"]);
    expect(city[0]!.whole).toBeUndefined();
    expect(filterGroups(groups, "nowhere", fold)).toEqual([]);
    expect(filterGroups(groups, "  ", fold)).toHaveLength(groups.length);
  });
});

describe("addresses", () => {
  it("reads IPv4 as four octets with no leading zero", () => {
    for (const ok of ["0.0.0.0", "203.0.113.7", "255.255.255.255"]) expect(isIPv4(ok), ok).toBe(true);
    for (const bad of ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.-4", "1.2.3.a", " 1.2.3.4", "1..2.3"]) expect(isIPv4(bad), bad).toBe(false);
  });

  it("reads IPv6 in the forms people write", () => {
    for (const ok of ["::", "::1", "2001:db8::7", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::ffff:1.2.3.4", "fe80::1", "1:2:3:4:5:6:1.2.3.4"]) expect(isIPv6(ok), ok).toBe(true);
    for (const bad of ["", ":", ":::", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "g::1", "12345::1", "1.2.3.4", "::1.2.3", "[::1]", "fe80::1%eth0", ":1:2:3:4:5:6:7"]) expect(isIPv6(bad), bad).toBe(false);
  });

  it("reads a host name for a CNAME", () => {
    for (const ok of ["proxy.example.org", "a.b", "xn--mgba3a4f16a.ir", "proxy.example.org.", "a-b.c-d.e"]) expect(isHostName(ok), ok).toBe(true);
    for (const bad of ["", "localhost", "-a.b", "a-.b", "a..b", "a b.c", `${"a".repeat(64)}.com`, `${"a.".repeat(130)}com`, "a_b.c", "http://a.b"]) expect(isHostName(bad), bad).toBe(false);
  });
});

describe("the draft and the Target it makes", () => {
  const ip: DestinationDraft = {...EMPTY_DRAFT, tab: "ip"};

  it("makes a location by its id, and Auto and Random by their kind", () => {
    expect(targetOf({...EMPTY_DRAFT, proxy: {kind: "location", id: "2"}})).toEqual({kind: "location", location_id: "2"});
    expect(targetOf({...EMPTY_DRAFT, proxy: {kind: "auto"}})).toEqual({kind: "auto"});
    expect(targetOf({...EMPTY_DRAFT, proxy: {kind: "random"}})).toEqual({kind: "random"});
    expect(targetOf(EMPTY_DRAFT)).toBeNull();
  });

  it("makes an IP target from one or both addresses, and refuses none or a wrong one", () => {
    expect(targetOf({...ip, v4: " 203.0.113.7 "})).toEqual({kind: "ip", ipv4: "203.0.113.7"});
    expect(targetOf({...ip, v6: "2001:db8::7"})).toEqual({kind: "ip", ipv6: "2001:db8::7"});
    expect(targetOf({...ip, v4: "203.0.113.7", v6: "2001:db8::7"})).toEqual({kind: "ip", ipv4: "203.0.113.7", ipv6: "2001:db8::7"});
    expect(targetOf(ip)).toBeNull();
    expect(targetOf({...ip, v4: "999.1.1.1"})).toBeNull();
    expect(draftProblems({...ip, v4: "999.1.1.1", v6: "zz"})).toEqual({v4: "invalidV4", v6: "invalidV6"});
    // A family that is empty is not an error: the Save button stays off instead.
    expect(draftProblems(ip)).toEqual({});
  });

  it("makes a host target from a CNAME", () => {
    expect(targetOf({...ip, record: "cname", host: "proxy.example.org"})).toEqual({kind: "host", host: "proxy.example.org"});
    expect(targetOf({...ip, record: "cname", host: "nope"})).toBeNull();
    expect(draftProblems({...ip, record: "cname", host: "nope"})).toEqual({host: "invalidHost"});
  });

  it("opens on what the row has: a location by id or by key, Auto, an IP, a host", () => {
    expect(draftOf({kind: "location", location_id: "2"}, SET).proxy).toEqual({kind: "location", id: "2"});
    expect(draftOf({kind: "location", location: {country: "DE", city: "Berlin"}}, SET).proxy).toEqual({kind: "location", id: "3"});
    expect(draftOf({kind: "location", location: {label: "Home lab"}}, SET).proxy).toEqual({kind: "location", id: "5"});
    expect(draftOf({kind: "location", location: {country: "JP"}}, SET).proxy).toBeNull();
    expect(draftOf({kind: "auto"}, SET).proxy).toEqual({kind: "auto"});
    expect(draftOf({kind: "ip", ipv4: "203.0.113.7"}, SET)).toMatchObject({tab: "ip", record: "a", v4: "203.0.113.7"});
    expect(draftOf({kind: "host", host: "a.b"}, SET)).toMatchObject({tab: "ip", record: "cname", host: "a.b"});
    expect(draftOf(null, SET)).toEqual(EMPTY_DRAFT);
  });

  it("says whether a destination is still one the set offers", () => {
    const one = {locations: [SET[0]!], autoRandom: false};
    expect(targetFits({kind: "location", location_id: SET[0]!.id}, one)).toBe(true);
    expect(targetFits({kind: "location", location_id: SET[3]!.id}, one)).toBe(false);
    expect(targetFits({kind: "auto"}, one)).toBe(false);
    expect(targetFits({kind: "random"}, {...one, autoRandom: true})).toBe(true);
    // The person's own address or host name is not a member of any set.
    expect(targetFits({kind: "ip", ipv4: "203.0.113.7"}, {locations: [], autoRandom: false})).toBe(true);
    expect(targetFits({kind: "host", host: "a.b"}, {locations: [], autoRandom: false})).toBe(true);
  });

  it("intersects the sets of several calls and cuts a long selection into calls of 100", () => {
    expect(intersectLocations([SET, [SET[0]!, SET[3]!], [SET[3]!]]).map((l) => l.id)).toEqual(["4"]);
    expect(intersectLocations([])).toEqual([]);
    const slugs = Array.from({length: 250}, (_, i) => `s${i}`);
    expect(chunkSlugs(slugs).map((c) => c.length)).toEqual([100, 100, 50]);
    expect(chunkSlugs([])).toEqual([]);
  });

  it("keeps a slug in its part of the catalogue, so one tick changes one part (S3-r3-2)", () => {
    const order = new Map(Array.from({length: 250}, (_, i) => [`s${String(i).padStart(3, "0")}`, i] as const));
    const all = [...order.keys()];
    const before = bucketSlugs(all, order);
    expect(before.map((c) => c.length)).toEqual([100, 100, 50]);
    // Taking one service out of the first part leaves the other parts as they were: chunkSlugs would have moved every part after it.
    const after = bucketSlugs(all.filter((s) => s !== "s003"), order);
    expect(after[0]).toHaveLength(99);
    expect(after.slice(1)).toEqual(before.slice(1));
    // A part with nothing selected is not asked for, and slugs the catalogue does not know stay within the limit of a call.
    expect(bucketSlugs(["s150", "s151"], order)).toEqual([["s150", "s151"]]);
    expect(bucketSlugs([], order)).toEqual([]);
    expect(bucketSlugs(Array.from({length: 120}, (_, i) => `x${i}`), order).map((c) => c.length)).toEqual([100, 20]);
  });
});

const render = (node: ReactNode, locale: "en" | "fa" = "en") =>
  renderToString(
    <QueryClientProvider client={new QueryClient()}>
      <NextIntlClientProvider locale={locale} messages={{common: commonEn, errors: errorsEn, feedback: feedbackEn, services: locale === "en" ? servicesEn : servicesFa}}>
        {node}
      </NextIntlClientProvider>
    </QueryClientProvider>,
  );

describe("DestinationsFields", () => {
  const noop = () => undefined;

  it("shows the two pill tabs, Auto and Random when the set allows them, and the countries", () => {
    const html = render(<DestinationsFields draft={EMPTY_DRAFT} onChange={noop} source={{locations: SET, autoRandom: true}} subject="Netflix" />);
    expect(html).toContain("Proxies");
    expect(html).toContain("IP or Hostname");
    expect(html).toContain("Auto");
    expect(html).toContain("Random");
    expect(html).toContain("Germany");
    expect(html).toContain("Show the cities of Germany");
    expect(html).toContain("Home lab");
  });

  it("leaves Auto and Random out when the API says the set is too small for them (SC 10.2)", () => {
    const html = render(<DestinationsFields draft={EMPTY_DRAFT} onChange={noop} source={{locations: [SET[0]!], autoRandom: false}} subject="Netflix" />);
    expect(html).not.toContain("The nearest destination is picked");
    expect(html).toContain("Germany");
  });

  it("says plainly that no location is available", () => {
    const html = render(<DestinationsFields draft={EMPTY_DRAFT} onChange={noop} source={{locations: [], autoRandom: false}} subject="Netflix" />);
    expect(html).toContain("No location is available");
  });

  it("shows the IPv4 and IPv6 fields on the A tab and says what is wrong with a bad address", () => {
    const html = render(<DestinationsFields draft={{...EMPTY_DRAFT, tab: "ip", v4: "999.0.0.1"}} onChange={noop} source={{locations: [], autoRandom: false}} subject="Netflix" />);
    expect(html).toContain("IPv4 address");
    expect(html).toContain("IPv6 address");
    expect(html).toContain("The IPv4 address is not valid.");
  });

  it("shows the host field on the CNAME tab, in Persian too", () => {
    const html = render(<DestinationsFields draft={{...EMPTY_DRAFT, tab: "ip", record: "cname"}} onChange={noop} source={{locations: [], autoRandom: false}} subject="Netflix" />, "fa");
    expect(html).toContain("نام میزبان");
  });
});
