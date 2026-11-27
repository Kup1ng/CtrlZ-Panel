import {resolverViewFixture} from "@ctrlz/api-client/testing/screenFixtures.ts";
import {NextIntlClientProvider} from "next-intl";
import {renderToString} from "react-dom/server";
import {readFileSync} from "node:fs";
import path from "node:path";
import {describe, expect, it} from "vitest";

import common from "../../../i18n/messages/en/common.json";
import enSetup from "../../../i18n/messages/en/setup.json";
import faCommon from "../../../i18n/messages/fa/common.json";
import faSetup from "../../../i18n/messages/fa/setup.json";
import type {Guide} from "./guide.ts";
import {Wizard} from "./Wizard.tsx";

// S7-r2-4: the first step of a Plain DNS platform tells the owner to claim the network. A visitor of a setup link has no session and no Addresses
// page, so the same step says whose job it is. The share page is not mounted anywhere yet, so this is the case that holds the text until it is.

const dir = path.join(import.meta.dirname, "content");
/** The version of a platform that sends to the Addresses page: Windows 11 sets DoH and has no such step, Windows 10 does. */
const guide = (lang: "en" | "fa", id: string) => {
  const versions = (JSON.parse(readFileSync(path.join(dir, lang, `${id}.json`), "utf8")) as Guide).versions;
  return versions.find((v) => v.steps.some((step) => step.link === "ips"))!;
};

const render = (lang: "en" | "fa", platform: string, endpointId?: string) =>
  renderToString(
    <NextIntlClientProvider locale={lang} messages={lang === "en" ? {common, setup: enSetup} : {common: faCommon, setup: faSetup}}>
      <Wizard version={guide(lang, platform)} step={guide(lang, platform).steps.findIndex((step) => step.link === "ips") + 1} onStep={() => undefined} view={resolverViewFixture()} endpointId={endpointId} onDone={() => undefined} />
    </NextIntlClientProvider>,
  );

describe.each(["en", "fa"] as const)("the first step of a Plain DNS platform (%s)", (lang) => {
  const own = (platform: string) => guide(lang, platform).steps.find((step) => step.link === "ips")!.text;
  const shared = lang === "en" ? enSetup.wizard.shareClaim : faSetup.wizard.shareClaim;

  it.each(["router", "samsung-tv", "windows", "mac", "apple-tv"])("%s: the owner's wizard keeps the claim text and the visitor's gives the owner's part (S7-r2-4)", (platform) => {
    const visitor = render(lang, platform);
    expect(visitor).toContain(shared);
    expect(visitor).not.toContain(own(platform));
    expect(visitor).not.toContain("/ips");
  });
});
