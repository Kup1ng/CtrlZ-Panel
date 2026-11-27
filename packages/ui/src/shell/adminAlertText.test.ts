import {readFileSync} from "node:fs";
import {describe, expect, it} from "vitest";

import {alertText, isSmsAlert, PROVIDER_NAMES} from "./adminAlertText.ts";

// Spec 13.6. What an alert says is chosen by its kind and its closed params; a kind or a class this client does not know falls
// back to the generic words, so a newer API never breaks an older page. The last case proves every key that can be chosen is
// in both languages' catalogues.

type Tree = {[key: string]: string | Tree};
const catalogue = (lang: string) => (JSON.parse(readFileSync(new URL(`../../../i18n/messages/${lang}/admin.json`, import.meta.url), "utf8")) as {alerts: Tree}).alerts;

const has = (tree: Tree) => (key: string) => {
  let node: string | Tree | undefined = tree;
  for (const part of key.split(".")) node = typeof node === "object" ? node[part] : undefined;
  return typeof node === "string";
};

describe("alertText", () => {
  const known = has(catalogue("en"));

  it("names the gateway by its product name and the failure by its class, whether the class is a word or a number", () => {
    const named = alertText({kind: "sms_gateway", params: {provider: "sms_ir", class: "credit", code: "no_credit"}}, known);
    expect(named).toMatchObject({titleKey: "sms_gateway.title", textKey: "sms_gateway.credit", values: {provider: "sms.ir"}, code: "no_credit"});
    expect(alertText({kind: "sms_gateway", params: {provider: "melipayamak", class: 2}}, known)).toMatchObject({textKey: "sms_gateway.auth", values: {provider: "Melipayamak"}});
  });

  it("uses the other line for a class it does not know, and keeps an unknown provider as it came", () => {
    expect(alertText({kind: "sms_gateway", params: {provider: "newco", class: 99}}, known)).toMatchObject({textKey: "sms_gateway.other", values: {provider: "newco"}});
  });

  it("has a line for each SMS kind", () => {
    for (const kind of ["sms_down", "sms_outbox_cap", "sms_payload"]) expect(alertText({kind, params: {}}, known)).toMatchObject({titleKey: `${kind}.title`, textKey: `${kind}.text`});
  });

  it("falls back to the generic words for a kind of a later phase", () => {
    expect(alertText({kind: "other", params: {}}, known)).toMatchObject({titleKey: "generic.title", textKey: "generic.text"});
    expect(alertText({kind: "tls_expiring", params: {}}, known).titleKey).toBe("generic.title");
  });

  it("carries the worker reason as the code when there is no code", () => {
    expect(alertText({kind: "sms_payload", params: {reason: "bad_payload"}}, known).code).toBe("bad_payload");
  });

  it("every key it can choose is in the English and the Persian catalogue", () => {
    const kinds = ["sms_down", "sms_outbox_cap", "sms_payload", "other"];
    const classes = ["transient", "auth", "credit", "config", "recipient", "blacklisted", "nonsense"];
    for (const lang of ["en", "fa"]) {
      const there = has(catalogue(lang));
      const chosen = [
        ...kinds.map((kind) => alertText({kind, params: {}}, there)),
        ...classes.map((cls) => alertText({kind: "sms_gateway", params: {provider: "sms_ir", class: cls}}, there)),
      ];
      for (const words of chosen) {
        expect(there(words.titleKey), `${lang} ${words.titleKey}`).toBe(true);
        if (words.textKey) expect(there(words.textKey), `${lang} ${words.textKey}`).toBe(true);
      }
    }
  });
});

describe("isSmsAlert and the provider names", () => {
  it("knows the four SMS kinds and no other", () => {
    for (const kind of ["sms_gateway", "sms_down", "sms_outbox_cap", "sms_payload"]) expect(isSmsAlert({kind})).toBe(true);
    for (const kind of ["other", "smsx", ""]) expect(isSmsAlert({kind})).toBe(false);
  });
  it("names the three gateways", () => {
    expect(PROVIDER_NAMES).toMatchObject({sms_ir: "sms.ir", melipayamak: "Melipayamak", noop: "noop"});
  });
});
