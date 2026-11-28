import {createHmac, randomBytes} from "node:crypto";

import type {Page} from "@playwright/test";
import jsQR from "jsqr";
import type {ResolverView} from "@ctrlz/api-client/hooks/setup.ts";
import {resolverViewFixture} from "@ctrlz/api-client/testing/screenFixtures.ts";

import enCommon from "../../../packages/i18n/messages/en/common.json";
import faCommon from "../../../packages/i18n/messages/fa/common.json";
import enErrors from "../../../packages/i18n/messages/en/errors.json";
import faErrors from "../../../packages/i18n/messages/fa/errors.json";

import {ENDPOINT, endpointPath} from "./endpoints-support.ts";
import type {Lang} from "./profiles-support.ts";
import {setupText} from "./setup-support.ts";

// What the specs of Resolvers, Help Me Configure and the verification share (S7), on top of the foundation's support files: the paths of
// the dialogs, a Resolver view with two address stamps (the fixture of the foundation has one), and the stub of the verify zone.

// Through the frame of the Endpoint (`/endpoints/<id>/clients`), which mounts EndpointDialogs with the Endpoint it has already read. The
// list page mounts the same component, but it is the lane P3a's, so a case of S7 does not stand on it. The Endpoint frame shows the
// id of the unknown Endpoint as a 404 and no dialog, so a case about an unknown id uses the list path below.
const framed = (lang: Lang, id: string, query: string) => `${endpointPath(lang, id, "clients")}?${query}`;
export const resolversPath = (lang: Lang, id: string = ENDPOINT.home) => framed(lang, id, `deviceDialog=resolvers&deviceId=${id}`);
export const configurePath = (lang: Lang, id: string = ENDPOINT.home, os?: string, step?: number) =>
  framed(lang, id, `deviceDialog=configure&deviceId=${id}${os ? `&setupOs=${os}` : ""}${step ? `&step=${step}` : ""}`);

/** The view of a deployment with both nodes: the second address stamp of each protocol is listed after the first, and in the wrong order here. */
export function twoNodeView(over: Partial<ResolverView> = {}): ResolverView {
  const base = resolverViewFixture();
  const stamp = (protocol: string, ip: string, n: number) => ({ip, stamp: `sdns://${protocol}${n}`});
  return {
    ...base,
    stamps: {
      doh: {hostname_stamp: "sdns://dohhost", address_stamps: [stamp("doh", "203.0.113.54", 2), stamp("doh", "203.0.113.53", 1)]},
      dot: {hostname_stamp: "sdns://dothost", address_stamps: [stamp("dot", "203.0.113.54", 2), stamp("dot", "203.0.113.53", 1)]},
      doq: {hostname_stamp: "sdns://doqhost", address_stamps: [stamp("doq", "203.0.113.54", 2), stamp("doq", "203.0.113.53", 1)]},
    },
    ...over,
  };
}

/** The English or Persian line of a platform name, for a button. */
export const platformName = (lang: Lang, id: string) => setupText(lang, `platforms.names.${id}`);

// ---- The verify zone ----

/** The origin the server of verify.spec.ts is started with (`CTRLZ_VERIFY_ORIGIN`): the host of the fixture's view is `r00000001.dns.example.test`. */
export const VERIFY_ORIGIN = ["https", "://*.verify.dns.example.test"].join("");
export const VERIFY_PORT = Number(process.env.E2E_VERIFY_PORT) || 5867;
export const VERIFY_HOST_RE = /^[a-z2-7]{26}\.verify\.dns\.example\.test$/;

const hex = (bytes: Buffer) => bytes.subarray(0, 16).toString("hex");
const tag = (label: string, n: Buffer, message: Buffer) => hex(createHmac("sha256", Buffer.concat([Buffer.from(label), n])).update(message).digest());

export type VerifyScenario =
  /** The probe does not get through: the name is not resolved by this service. */
  | "unseen"
  /** `seen` is true, but through another Endpoint. */
  | "other"
  /** The expected Endpoint and client, over DoH. */
  | "match"
  /** Not an answer at all: a captive portal's HTML. */
  | "junk";

/**
 * The protocol byte of the `proto_tag` message, written out from spec p4-nodes 7.6 (the number of `common.v1.Protocol`) and not imported from the
 * page, so a drift in the page's own table fails a case.
 */
const PROTOCOL_BYTE: Record<string, number> = {udp: 1, tcp: 2, doh: 3, dot: 4, doq: 5, doh3: 6};

/**
 * The body the node would give for `label`, built the way spec p4 7.6 says and from its literal bytes (`rid || 0x00 || client`, `rid || 0x01 ||
 * protocol byte`), not through the page's `messagesOf`. The client of an unnamed client is empty in the `client_tag`.
 */
export function verifyBody(label: string, scenario: VerifyScenario, expected = {resolverId: "r00000001", client: "", protocol: "doh"}) {
  const n = randomBytes(16);
  const rid = Buffer.from(scenario === "other" ? "r00000002" : expected.resolverId);
  if (scenario === "unseen") {
    return {seen: false, n: n.toString("hex"), rid_tag: hex(randomBytes(16)), client_tag: hex(randomBytes(16)), proto_tag: hex(randomBytes(16))};
  }
  return {
    seen: true,
    n: n.toString("hex"),
    rid_tag: tag(label, n, rid),
    client_tag: tag(label, n, Buffer.concat([rid, Buffer.from([0]), Buffer.from(expected.client)])),
    proto_tag: tag(label, n, Buffer.concat([rid, Buffer.from([1, PROTOCOL_BYTE[expected.protocol]!])])),
  };
}

/**
 * Answers `GET https://<label>.verify.dns.example.test/v` on one page. `script` gives the scenario of each probe in turn (the last one repeats).
 * Returns the labels asked, so a case can assert that each probe used a fresh 26-character label. The request is to another origin by design,
 * so the guard of 17.2 records it: the case ends with `guard.consume("external")`.
 */
export async function stubVerify(page: Page, script: VerifyScenario[]) {
  const labels: string[] = [];
  await page.route(/^https:\/\/[a-z2-7]{26}\.verify\.dns\.example\.test\/v(\?.*)?$/, async (route) => {
    const url = new URL(route.request().url());
    const label = url.hostname.split(".")[0]!;
    labels.push(label);
    const scenario = script[Math.min(labels.length - 1, script.length - 1)]!;
    const cors = {
      "access-control-allow-origin": route.request().headers().origin ?? "*",
      "cache-control": "no-store",
    };
    if (scenario === "junk") return route.fulfill({status: 200, headers: cors, contentType: "text/html", body: "<html>portal</html>"});
    return route.fulfill({status: 200, headers: cors, contentType: "application/json", body: JSON.stringify(verifyBody(label, scenario))});
  });
  return labels;
}

// ---- Words ----

const COMMON = {fa: faCommon, en: enCommon} as const;
const ERRORS = {fa: faErrors, en: enErrors} as const;

/** The text of `errors.<code>` in one language (codes with no argument). */
export const errorText = (lang: Lang, code: keyof typeof faErrors & string): string => String(ERRORS[lang][code]);

/** `common.copyNamed` filled in: the accessible name of a Copy button for the value called `name`. */
export function copyName(lang: Lang, name: string): string {
  return COMMON[lang].copyNamed.replace("{name}", name);
}
export const commonText = (lang: Lang, key: "copy" | "close" | "done" | "copied") => COMMON[lang][key];

// ---- QR ----

/**
 * Reads the QR code the page drew (`data-testid="setup-qr"`) the way a phone would, without a request or an image: the SVG's modules are
 * written back into a bitmap here, in Node, and decoded by jsQR. The page's policy has no `img-src`, so a canvas of the page could not do it.
 */
export async function decodeQr(page: Page, testId = "setup-qr"): Promise<string | null> {
  const svg = await page.getByTestId(testId).locator("svg").evaluate((el) => el.outerHTML);
  const size = Number(/viewBox="0 0 (\d+) \d+"/.exec(svg)?.[1]);
  const dark = /fill="#000000" d="([^"]+)"/.exec(svg)?.[1];
  if (!size || !dark) throw new Error("the QR code has no modules to read");
  const scale = 6;
  const side = size * scale;
  const rgba = new Uint8ClampedArray(side * side * 4).fill(255);
  for (const [, x0, y0, w] of dark.matchAll(/M(\d+)[ ,](\d+)\s?h(\d+)v1/g)) {
    for (let dx = 0; dx < Number(w); dx++) {
      for (let px = 0; px < scale; px++) {
        for (let py = 0; py < scale; py++) {
          const at = ((Number(y0) * scale + py) * side + (Number(x0) + dx) * scale + px) * 4;
          rgba[at] = rgba[at + 1] = rgba[at + 2] = 0;
        }
      }
    }
  }
  return jsQR(rgba, side, side)?.data ?? null;
}
