import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {NextIntlClientProvider} from "next-intl";
import type {ReactNode} from "react";
import {renderToString} from "react-dom/server";
import {I18nProvider} from "react-aria-components";
import {describe, expect, it} from "vitest";

import {ApiError} from "@ctrlz/api-client/errors.ts";
import {accountKeys} from "@ctrlz/api-client/hooks/profileKeys.ts";

import commonEn from "../../../i18n/messages/en/common.json";
import commonFa from "../../../i18n/messages/fa/common.json";
import errorsEn from "../../../i18n/messages/en/errors.json";
import errorsFa from "../../../i18n/messages/fa/errors.json";
import rulesEn from "../../../i18n/messages/en/rules.json";
import rulesFa from "../../../i18n/messages/fa/rules.json";
import {DateTimePicker} from "../calendar/DateTimePicker.tsx";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {CardGrid, ItemTile} from "./CardGrid.tsx";
import {TechCopyRow} from "./TechCopyRow.tsx";

const messagesOf = (locale: "en" | "fa") => (locale === "en" ? {common: commonEn, errors: errorsEn, rules: rulesEn} : {common: commonFa, errors: errorsFa, rules: rulesFa});

const render = (node: ReactNode, locale: "en" | "fa" = "en", client = new QueryClient()) =>
  renderToString(
    <QueryClientProvider client={client}>
      <NextIntlClientProvider locale={locale} messages={messagesOf(locale)}>
        {node}
      </NextIntlClientProvider>
    </QueryClientProvider>,
  );

describe("CardGrid and ItemTile", () => {
  it("is a list of list items, with as many columns of 14rem as fit", () => {
    const html = render(
      <CardGrid label="Filters">
        <ItemTile title="Malware" status="Blocked" toggle={<span>sw</span>} footer={<span>info</span>} />
        <ItemTile title="Ads" state="off" />
      </CardGrid>,
    );
    expect(html).toContain('role="list"');
    expect(html).toContain('aria-label="Filters"');
    expect(html).toContain("minmax(14rem,1fr)");
    expect(html.match(/role="listitem"/g)).toHaveLength(2);
    expect(html).toContain('data-state="off"');
  });

  it("says the status in words and keeps the switch outside the card's own action", () => {
    const html = render(<ItemTile title="Malware" status="Blocked" toggle={<button type="button">Malware</button>} />);
    expect(html).toContain("Blocked");
    expect(html).toContain("<h3");
    expect(html).not.toMatch(/<a /);
  });
});

describe("TechCopyRow", () => {
  it("shows the value left to right and names its button with the label", () => {
    const html = render(<TechCopyRow label="DNS 1" value="203.0.113.7" />);
    expect(html).toContain('dir="ltr"');
    expect(html).toContain("203.0.113.7");
    expect(html).toContain('aria-label="Copy DNS 1"');
  });

  it("names the button in Persian too, and keeps the value unbroken by the surrounding direction", () => {
    const html = render(<TechCopyRow label="نشانی ۱" value="2001:db8::7" hint="راهنما" />, "fa");
    expect(html).toContain('aria-label="کپی نشانی ۱"');
    expect(html).toContain('translate="no"');
    expect(html).toContain("راهنما");
  });
});

describe("CapacityNotice", () => {
  const over = (name: string) => new ApiError(422, "validation_failed", undefined, undefined, [{name, code: "exceeded"}]);

  it("renders nothing for an error that is not a limit", () => {
    expect(render(<CapacityNotice error={new ApiError(500, "internal")} />)).toBe("");
    expect(render(<CapacityNotice error={null} />)).toBe("");
  });

  it("names the limit that was reached", () => {
    expect(render(<CapacityNotice error={over("max_profiles")} />)).toContain("You have reached the limit of profiles.");
    expect(render(<CapacityNotice error={over("max_brand_new")} />)).toContain("this section");
  });

  it("adds the number when the account's limits are known, in the person's digits", () => {
    const client = new QueryClient();
    client.setQueryData(accountKeys.limits, {max_profiles: 5});
    expect(render(<CapacityNotice error={over("max_profiles")} />, "en", client)).toContain("limit of profiles: 5.");
    expect(render(<CapacityNotice error={over("max_profiles")} />, "fa", client)).toContain("۵");
  });
});

describe("DateTimePicker (calendar with a clock)", () => {
  const value = new Date("2026-11-25T08:30:00Z");
  const withLocale = (tag: string, locale: "en" | "fa") =>
    render(
      <I18nProvider locale={tag}>
        <DateTimePicker value={value} onApply={() => undefined} label="example.com" now={() => new Date("2026-11-20T00:00:00Z")} />
      </I18nProvider>,
      locale,
    );

  it("draws a Jalali month in Persian, with Persian digits", () => {
    const html = withLocale("fa-IR-u-ca-persian-nu-arabext", "fa");
    // The month of 25 November 2026 is Azar 1405, the week starts on Saturday, and no Gregorian month name is on the grid. The year 2026 is
    // only in the data attribute of the year picker's cell, which is not shown.
    expect(html.includes("۱۴۰۵ آذر")).toBe(true);
    expect(html.includes("شنبه")).toBe(true);
    expect(html.includes("November")).toBe(false);
  });

  it("draws a Gregorian month in English", () => {
    const html = withLocale("en-US-u-ca-gregory-nu-latn", "en");
    expect(html.includes("November 2026")).toBe(true);
    expect(html.includes("۱۴۰۵")).toBe(false);
  });

  it("names the grid and the clock for the thing they belong to, and offers Apply and Clear", () => {
    const html = withLocale("en-US-u-ca-gregory-nu-latn", "en");
    expect(html).toContain("Date: example.com");
    expect(html).toContain("Time: example.com");
    expect(html).toContain("Apply");
    expect(html).toContain("Clear");
  });
});
