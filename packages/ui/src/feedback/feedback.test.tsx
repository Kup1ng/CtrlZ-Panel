import {ApiError} from "@ctrlz/api-client/errors.ts";
import {NextIntlClientProvider} from "next-intl";
import type {ReactNode} from "react";
import {renderToString} from "react-dom/server";
import {readFileSync} from "node:fs";
import {describe, expect, it} from "vitest";

import common from "../../../i18n/messages/en/common.json";
import errors from "../../../i18n/messages/en/errors.json";
import feedback from "../../../i18n/messages/en/feedback.json";
import faCommon from "../../../i18n/messages/fa/common.json";
import faErrors from "../../../i18n/messages/fa/errors.json";
import faFeedback from "../../../i18n/messages/fa/feedback.json";
import {SectionEmpty} from "./SectionEmpty.tsx";
import {SectionError} from "./SectionError.tsx";

const en = (node: ReactNode) =>
  renderToString(
    <NextIntlClientProvider locale="en" messages={{common, errors, feedback}}>
      {node}
    </NextIntlClientProvider>,
  );
const fa = (node: ReactNode) =>
  renderToString(
    <NextIntlClientProvider locale="fa" messages={{common: faCommon, errors: faErrors, feedback: faFeedback}}>
      {node}
    </NextIntlClientProvider>,
  );

describe("SectionError (spec 8.7)", () => {
  it("shows the title, the catalogue text, Retry and the request id in <Tech>, and announces itself", () => {
    const html = en(<SectionError error={new ApiError(503, "service_unavailable", "req-abc123")} onRetry={() => undefined} />);
    expect(html).toContain('role="alert"');
    expect(html).toContain("Something went wrong");
    expect(html).toContain(errors.service_unavailable);
    expect(html).toContain("Try again");
    expect(html).toMatch(/<bdi dir="ltr"[^>]*>req-abc123<\/bdi>/);
    expect(html).toContain("Reference code");
    // The reference alone does not say what to do with it (wp7-r1-7).
    expect(html).toContain(feedback.error.referenceHint);
  });

  it("never shows a thrown message, a stack or a URL", () => {
    const boom = new Error("connect ECONNREFUSED 10.0.0.1:5432 at /srv/api/handler.go:12");
    const html = en(<SectionError error={boom} onRetry={() => undefined} />);
    expect(html).not.toContain("ECONNREFUSED");
    expect(html).not.toContain("handler.go");
    expect(html).toContain(errors.unknown);
  });

  it("uses a Next digest as the reference when there is no request id, and ignores one that is not a plain token", () => {
    const withDigest = Object.assign(new Error("x"), {digest: "1234567890"});
    expect(en(<SectionError error={withDigest} />)).toMatch(/<bdi dir="ltr"[^>]*>1234567890<\/bdi>/);
    const hostile = Object.assign(new Error("x"), {digest: "<script>alert(1)</script>"});
    const html = en(<SectionError error={hostile} />);
    expect(html).not.toContain("<script>alert");
    expect(html).not.toContain("Reference code");
  });

  it("has no Retry without a handler, and none for not_found, whose text never says whose row it was", () => {
    expect(en(<SectionError error={new ApiError(500, "internal")} />)).not.toContain("<button");
    const html = en(<SectionError error={new ApiError(404, "not_found")} onRetry={() => undefined} />);
    expect(html).not.toContain("<button");
    expect(html).toContain("Not found");
  });

  it("is in Persian when the locale is", () => {
    const html = fa(<SectionError error={new ApiError(503, "service_unavailable", "r1")} onRetry={() => undefined} />);
    expect(html).toContain(faFeedback.error.title);
    expect(html).toContain(faCommon.retry);
  });
});

describe("feedback messages", () => {
  // A key that no component reads is a sentence nobody sees (wp7-r1-7). The showcase keys belong to the lab sample.
  it("are all read by the feedback components, in both languages", () => {
    const source = ["SectionError.tsx", "SectionEmpty.tsx"].map((f) => readFileSync(new URL(`./${f}`, import.meta.url), "utf8")).join("\n");
    for (const messages of [feedback, faFeedback]) {
      for (const [group, entries] of Object.entries(messages)) {
        if (group === "showcase") continue;
        for (const key of Object.keys(entries)) expect(source, `${group}.${key}`).toContain(`"${group}.${key}"`);
      }
    }
  });
});

describe("SectionEmpty (spec 8.7)", () => {
  it("has a generic title and line when it is given none", () => {
    const html = en(<SectionEmpty />);
    expect(html).toContain(feedback.empty.title);
    expect(html).toContain(feedback.empty.text);
  });

  it("does not add the generic line under a title of the caller", () => {
    const html = en(<SectionEmpty title="No rules" />);
    expect(html).toContain("No rules");
    expect(html).not.toContain(feedback.empty.text);
  });

  it("renders the action in the content area, and none when there is none", () => {
    expect(en(<SectionEmpty title="t" action={<a href="/x">Add</a>} />)).toContain("empty-state__content");
    expect(en(<SectionEmpty title="t" />)).not.toContain("empty-state__content");
  });
});
