import {NextIntlClientProvider} from "next-intl";
import type {ReactNode} from "react";
import {renderToString} from "react-dom/server";
import {describe, expect, it, vi} from "vitest";

import common from "../../../i18n/messages/en/common.json";
import faCommon from "../../../i18n/messages/fa/common.json";

vi.mock("next/navigation", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/profiles",
  useRouter: () => ({push: () => undefined, replace: () => undefined, back: () => undefined}),
}));

import {DenseRow} from "./DenseRow.tsx";
import {ListRow, RowList} from "./ListRow.tsx";
import {RowCounters} from "./RowCounters.tsx";
import {Tech} from "./Tech.tsx";

const render = (node: ReactNode, locale: "en" | "fa" = "en") =>
  renderToString(
    <NextIntlClientProvider locale={locale} messages={{common: locale === "en" ? common : faCommon}}>
      {node}
    </NextIntlClientProvider>,
  );

describe("Tech", () => {
  it("isolates a technical token from the direction of the sentence", () => {
    expect(render(<Tech>example.org</Tech>)).toBe('<bdi dir="ltr" translate="no" class="font-mono">example.org</bdi>');
  });
  it("is never sent to the browser's page translation (gate-r3-12)", () => {
    // A code or key that a person copies by hand would be rewritten, and a one-time secret would reach the vendor's server.
    expect(render(<Tech mono={false}>JBSWY3DP</Tech>)).toContain('translate="no"');
  });
});

describe("ListRow (spec 8.10)", () => {
  it("is a list item of at least 75px with the control-75 corner, and two lines when the list is narrower than 42rem", () => {
    const html = render(<ListRow title="Home" subtitle="Router" href="/profiles" />);
    expect(html).toContain('role="listitem"');
    expect(html).toMatch(/class="[^"]*\bcontrol-75\b/);
    expect(html).toContain("min-h-control-75");
    // A minimum and never a fixed height at the one-line width (S1-r3-4).
    expect(html).not.toContain("@2xl:h-control-75");
    expect(html).toContain("flex-wrap");
    expect(html).toContain("@2xl:flex-nowrap");
  });

  it("makes the title the stretched link and does not nest another link inside it", () => {
    const html = render(<ListRow title="Home" href="/profiles" counters={<RowCounters items={[{id: "a", label: "A", value: 1, href: "/profiles?tab=a"}]} />} />);
    expect(html).toContain('data-row-main=""');
    expect(html).toContain("after:absolute");
    // The title anchor holds only the title; the counter link is a sibling, above it.
    expect(html.match(/<a /g)?.length).toBe(2);
    expect(html).toMatch(/<a [^>]*data-row-main[^>]*>Home<\/a>/);
    expect(html).toContain("relative z-10");
  });

  it("is information only without an action: no pointer, no hover, no chevron, no link", () => {
    const html = render(<ListRow title="Home" />);
    expect(html).not.toContain("hover:bg-default");
    expect(html).not.toContain('data-row-main=""');
    expect(html).not.toContain("<a ");
    expect(html).not.toContain("<button");
  });

  it("marks the new row", () => {
    expect(render(<ListRow title="New" href="/p" isHighlighted />)).toContain('data-highlighted="true"');
    expect(render(<ListRow title="Old" href="/p" />)).not.toContain("data-highlighted");
  });

  it("puts rows in a list", () => {
    expect(render(<RowList aria-label="Profiles"><ListRow title="a" /></RowList>)).toContain('role="list"');
  });

  // The rows decide one line or two by the width of their list, not of the window: the sidebar takes 280px of a 768px window.
  it("makes the list the container that its rows measure", () => {
    expect(render(<RowList aria-label="Profiles"><ListRow title="a" /></RowList>)).toMatch(/class="[^"]*@container/);
  });

  it("uses no physical edge", () => {
    const html = render(<ListRow title="Home" href="/p" counters={<RowCounters items={[{id: "a", label: "A", value: 1}]} />} />);
    expect(html).not.toMatch(/\b(?:ml|mr|pl|pr|left|right|text-left|text-right)-/);
  });
});

describe("RowCounters", () => {
  const items = [
    {id: "filters", label: "Filters", value: 12},
    {id: "rules", label: "Rules", value: 1204},
  ];

  it("writes digits as the language does (spec 4.4)", () => {
    expect(render(<RowCounters items={items} />)).toContain("1,204");
    expect(render(<RowCounters items={items} />, "fa")).toContain("۱٬۲۰۴");
  });

  it("separates the counters with a mark that is hidden from readers, and has one fewer than the counters", () => {
    const html = render(<RowCounters items={items} />);
    expect(html.match(/aria-hidden="true"/g)?.length).toBe(1);
  });
});

describe("DenseRow", () => {
  it("is 50px with the control-50 corner and swaps tags for hover actions in one grid cell", () => {
    const html = render(<DenseRow title="a.example" tags={<i>tag</i>} hoverActions={<b>act</b>} />);
    expect(html).toMatch(/class="[^"]*\bcontrol-50\b/);
    expect(html).toContain("group-hover:invisible");
    expect(html).toContain("group-hover:opacity-100");
    expect(html.match(/col-start-1 row-start-1/g)?.length).toBe(2);
  });

  it("is the compact small-view row: 10 steps high with the row-counter corner, and the question of a pinned row stays without hover (T-196, T-190)", () => {
    const html = render(<DenseRow title="a.example" compact actionsPinned tags={<i>tag</i>} hoverActions={<b>act</b>} place={{style: {top: 96}, index: 2, count: 10}} />);
    expect(html).toMatch(/class="row-counter h-10 group/);
    expect(html).not.toContain("control-50");
    expect(html).toContain('data-pinned="true"');
    expect(html).toContain("group-data-pinned:opacity-100");
    expect(html).toContain("group-data-pinned:invisible");
    expect(html).toContain('aria-posinset="3"');
    expect(html).toContain('aria-setsize="10"');
  });

  it("tells a screen reader the size of the whole list, or -1 when it is not known, and not only the rows that are loaded (S4-r1-4)", () => {
    const style = {top: 0};
    expect(render(<DenseRow title="a.example" place={{style, index: 0, count: 100, setSize: 9880}} />)).toContain('aria-setsize="9880"');
    expect(render(<DenseRow title="a.example" place={{style, index: 0, count: 100, setSize: -1}} />)).toContain('aria-setsize="-1"');
    expect(render(<DenseRow title="a.example" place={{style, index: 0, count: 100}} />)).toContain('aria-setsize="100"');
  });

  it("has a labelled checkbox in selection mode, above the row action", () => {
    const html = render(<DenseRow title="a.example" onPress={() => undefined} selection={{isSelected: true, onChange: () => undefined, label: "Select row"}} />);
    expect(html).toContain('aria-label="Select row"');
    expect(html).toContain("relative z-10");
    expect(html).toContain('data-selected="true"');
  });

  it("reveals the actions on keyboard focus and not on any focus, so a click does not pin them (wp7-r1-2)", () => {
    const html = render(<DenseRow title="a.example" tags={<i>tag</i>} hoverActions={<b>act</b>} />);
    expect(html).toContain("group-has-[:focus-visible]:opacity-100");
    expect(html).toContain("group-has-[:focus-visible]:invisible");
    expect(html).not.toContain("focus-within");
  });

  it("keeps the hidden actions in the accessibility tree and gives a selected row on touch its actions (wp7-r1-3)", () => {
    const html = render(<DenseRow title="a.example" tags={<i>tag</i>} hoverActions={<b>act</b>} selection={{isSelected: false, onChange: () => undefined, label: "Select row"}} />);
    expect(html).toMatch(/class="[^"]*\bopacity-0\b[^"]*"><b>act<\/b>/);
    expect(html).not.toMatch(/class="[^"]*\binvisible\b[^"]*"><b>act/);
    expect(html).toContain("pointer-coarse:group-data-selected:opacity-100");
    expect(html).toContain("pointer-coarse:group-data-selected:invisible");
  });

  it("does not hide tags that have no hover actions", () => {
    expect(render(<DenseRow title="a" tags={<i>tag</i>} />)).not.toContain("group-hover:invisible");
  });
});
