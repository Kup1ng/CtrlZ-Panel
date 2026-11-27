import {NextIntlClientProvider} from "next-intl";
import type {ReactNode} from "react";
import {renderToString} from "react-dom/server";
import {describe, expect, it} from "vitest";

import commonEn from "../../../i18n/messages/en/common.json";
import commonFa from "../../../i18n/messages/fa/common.json";
import rulesEn from "../../../i18n/messages/en/rules.json";
import rulesFa from "../../../i18n/messages/fa/rules.json";
import {batchTarget, isSelected, OFF, reduce, selectedCount, selectionOverflow, type Selection} from "./selection.ts";
import {SelectionBar} from "./SelectionBar.tsx";
import {ThreeStateControl} from "./ThreeStateControl.tsx";
import {controlNote, effectiveAction, isChoiceDisabled, offeredChoices, redirectOffReason} from "./threeState.ts";

const render = (node: ReactNode, locale: "en" | "fa" = "en") =>
  renderToString(
    <NextIntlClientProvider locale={locale} messages={locale === "en" ? {common: commonEn, rules: rulesEn} : {common: commonFa, rules: rulesFa}}>
      {node}
    </NextIntlClientProvider>,
  );

describe("three-state rules (p2 9.4, D42, T-166, T-521)", () => {
  const base = {value: "block" as const, redirectAllowed: true, hasDestination: true};

  it("offers Block, Bypass and Redirect, and Redirect not at all for a name that is never proxied", () => {
    expect(offeredChoices(["block", "bypass", "redirect"], base)).toEqual(["block", "bypass", "redirect"]);
    expect(offeredChoices(["block", "bypass", "redirect"], {...base, redirectAllowed: false})).toEqual(["block", "bypass"]);
  });

  it("keeps the Redirect button on a row that already says Redirect, so its state is never hidden", () => {
    expect(offeredChoices(["block", "bypass", "redirect"], {value: "redirect", redirectAllowed: false})).toEqual(["block", "bypass", "redirect"]);
    expect(isChoiceDisabled("redirect", {value: "redirect", redirectAllowed: false, hasDestination: false})).toBe(false);
  });

  it("shows Redirect disabled, with its reason, when the set has no shared destination", () => {
    const empty = {...base, hasDestination: false};
    expect(isChoiceDisabled("redirect", empty)).toBe(true);
    expect(isChoiceDisabled("block", empty)).toBe(false);
    expect(redirectOffReason(empty)).toBe("no_shared");
    expect(controlNote(empty)).toBe("noShared");
  });

  it("prefers the never-proxied reason to the empty set", () => {
    expect(redirectOffReason({redirectAllowed: false, hasDestination: false})).toBe("never_proxied");
    expect(controlNote({...base, redirectAllowed: false, hasDestination: false})).toBe("neverProxied");
  });

  it("says a Redirect acts as Bypass when its name is Iranian or its destination left the set, and Block stays Block", () => {
    expect(effectiveAction({value: "redirect", iranianBypass: true})).toBe("bypass");
    expect(effectiveAction({value: "redirect", locationUnavailable: true})).toBe("bypass");
    expect(effectiveAction({value: "redirect"})).toBe("redirect");
    expect(effectiveAction({value: "block", iranianBypass: true})).toBe("block");
    expect(controlNote({...base, value: "redirect", iranianBypass: true})).toBe("iranianBypass");
    expect(controlNote({...base, value: "redirect", locationUnavailable: true})).toBe("unavailable");
    expect(controlNote(base)).toBeNull();
  });
});

describe("ThreeStateControl", () => {
  it("is a labelled group whose buttons all name their subject", () => {
    const html = render(<ThreeStateControl value="bypass" onChange={() => undefined} subject="Telegram" />);
    expect(html).toContain('aria-label="Action for Telegram"');
    expect(html).toContain('aria-label="Block for Telegram"');
    expect(html).toContain('aria-label="Bypass for Telegram"');
    expect(html).toContain('aria-label="Redirect for Telegram"');
  });

  it("has no Redirect button for a service that is never proxied, and says why in words", () => {
    const html = render(<ThreeStateControl value="block" onChange={() => undefined} subject="Aparat" redirectAllowed={false} />);
    expect(html).not.toContain("Redirect for Aparat");
    expect(html).toContain("Aparat is never sent through a proxy");
  });

  it("marks a Redirect that acts as Bypass in the button's own name and in a line under the control", () => {
    const html = render(<ThreeStateControl value="redirect" onChange={() => undefined} subject="Digikala" iranianBypass />);
    expect(html).toContain("In effect: Bypass");
    expect(html).toContain("Set to Redirect but acts as Bypass");
  });

  it("shows the destination button only on a Redirect row that can open it, named for the subject and the place", () => {
    const withIt = render(<ThreeStateControl value="redirect" onChange={() => undefined} subject="Netflix" onOpenDestination={() => undefined} destinationName="Germany" />);
    expect(withIt).toContain("Redirect destination of Netflix");
    expect(withIt).toContain("Destination: Germany");
    expect(render(<ThreeStateControl value="block" onChange={() => undefined} subject="Netflix" onOpenDestination={() => undefined} />)).not.toContain("Redirect destination of");
  });

  it("offers Inherit where a rule may follow its folder, and reads in Persian", () => {
    const html = render(<ThreeStateControl value="inherit" onChange={() => undefined} subject="example.com" choices={["block", "bypass", "redirect", "inherit"]} />, "fa");
    expect(html).toContain("ارث‌بری");
    expect(html).toContain("example.com");
  });
});

describe("selection mode (p2 9.6)", () => {
  const enter = (id?: string): Selection => reduce(OFF, {type: "enter", id});
  const loaded = ["a", "b", "c"];

  it("starts off, and entering with a row selects it", () => {
    expect(OFF.mode).toBe("off");
    const s = enter("a");
    expect(isSelected(s, "a")).toBe(true);
    expect(isSelected(s, "b")).toBe(false);
    expect(selectedCount(s, 3)).toBe(1);
  });

  it("toggles rows, and leaves an off list alone", () => {
    let s = enter("a");
    s = reduce(s, {type: "toggle", id: "b", loaded});
    expect(selectedCount(s, 3)).toBe(2);
    s = reduce(s, {type: "toggle", id: "a", loaded});
    expect(isSelected(s, "a")).toBe(false);
    expect(reduce(OFF, {type: "toggle", id: "a", loaded})).toBe(OFF);
  });

  it("makes Select All a selection of the whole filter, counted by the server's total, and sent as a selector", () => {
    const all = reduce(enter("a"), {type: "selectAll"});
    expect(all.mode).toBe("all");
    expect(isSelected(all, "zzz")).toBe(true);
    expect(selectedCount(all, 100, 10_000)).toBe(10_000);
    expect(selectedCount(all, 100)).toBe(100);
    expect(batchTarget(all)).toEqual({kind: "selector"});
  });

  it("turns Select All into the loaded rows minus one when a row is unticked, since a selector cannot say all but", () => {
    const after = reduce(reduce(enter("a"), {type: "selectAll"}), {type: "toggle", id: "b", loaded});
    expect(after.mode).toBe("ids");
    expect(batchTarget(after)).toEqual({kind: "ids", ids: ["a", "c"]});
  });

  it("sends nothing for an empty selection, and cuts a list of ids at the route's limit", () => {
    expect(batchTarget(reduce(enter("a"), {type: "clear"}))).toBeNull();
    expect(batchTarget(OFF)).toBeNull();
    const many = reduce(enter(), {type: "toggle", id: "x", loaded: []});
    expect(batchTarget(many, 1)).toEqual({kind: "ids", ids: ["x"]});
  });

  it("counts the ids a smaller route would leave out, so a screen can say so before it sends", () => {
    let s: Selection = enter("a");
    for (const id of ["b", "c", "d"]) s = reduce(s, {type: "toggle", id, loaded: []});
    expect(selectionOverflow(s, 500)).toBe(0);
    expect(selectionOverflow(s, 3)).toBe(1);
    expect(selectionOverflow(reduce(s, {type: "selectAll"}), 1)).toBe(0);
    expect(selectionOverflow(OFF, 1)).toBe(0);
  });

  it("drops the ids that left the list, and ends Select All when the filter changed", () => {
    const s = reduce(reduce(enter("a"), {type: "toggle", id: "b", loaded}), {type: "reconcile", loaded: ["a"], filterChanged: false});
    expect(batchTarget(s)).toEqual({kind: "ids", ids: ["a"]});
    const all = reduce(enter("a"), {type: "selectAll"});
    expect(reduce(all, {type: "reconcile", loaded: ["a"], filterChanged: false}).mode).toBe("all");
    expect(reduce(all, {type: "reconcile", loaded: ["a"], filterChanged: true})).toEqual({mode: "ids", ids: new Set()});
  });

  it("exits to off", () => {
    expect(reduce(enter("a"), {type: "exit"})).toBe(OFF);
  });
});

describe("SelectionBar", () => {
  const actions = [
    {id: "copy", label: "Copy", onPress: () => undefined},
    {id: "delete", label: "Delete", variant: "danger" as const, onPress: () => undefined},
  ];

  it("is a toolbar with the count, and every action's name has the count in it", () => {
    const html = render(<SelectionBar count={12} onClear={() => undefined} onSelectAll={() => undefined} total={500} actions={actions} />);
    expect(html).toContain('role="toolbar"');
    expect(html).toContain("12 items selected");
    expect(html).toContain('aria-label="Delete: 12 items selected"');
    expect(html).toContain('aria-label="Select all 500 items"');
    expect(html).toContain('aria-label="Clear selection"');
  });

  it("says that everything of the filter is selected, and drops the Select All button", () => {
    const html = render(<SelectionBar count={500} allMatching onClear={() => undefined} onSelectAll={() => undefined} actions={actions} />);
    expect(html).toContain("Every item of this list is selected");
    expect(html).not.toContain("Select all");
  });

  it("does not claim a count it does not know: Select All over a filter with more pages says every matching item (T-191)", () => {
    const html = render(<SelectionBar count={100} allMatching countUnknown onClear={() => undefined} actions={actions} />);
    expect(html).toContain("Every matching item");
    expect(html).not.toContain("100 items selected");
    expect(html).toContain('aria-label="Delete: Every matching item"');
  });

  it("disables every action while nothing is selected", () => {
    const html = render(<SelectionBar count={0} onClear={() => undefined} actions={actions} />);
    expect(html.match(/data-disabled="true"/g)?.length).toBeGreaterThanOrEqual(2);
  });
});
