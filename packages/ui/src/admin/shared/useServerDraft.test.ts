import {describe, expect, it} from "vitest";

import {moveEdits, pruneEdits} from "./useServerDraft.ts";

// The pure part of useServerForm (wp10-r4-3): which edits survive when the server's value moves under an open form.

type Form = {cap: string; ip: number; enabled: boolean};
const same = (a: Form, b: Form) => a.cap.replace(/\.0+$/, "") === b.cap.replace(/\.0+$/, "") && a.ip === b.ip && a.enabled === b.enabled;
const base: Form = {cap: "", ip: 10, enabled: true};

describe("pruneEdits", () => {
  it("keeps an edit that differs from the value the server held", () => {
    expect(pruneEdits<Form>({ip: 20}, base, same)).toEqual({ip: 20});
  });

  it("drops an edit that is only the value the server held, so that field follows the server again", () => {
    expect(pruneEdits<Form>({ip: 10, enabled: false}, base, same)).toEqual({enabled: false});
  });

  it("reads two spellings of one value as no edit", () => {
    expect(pruneEdits<Form>({cap: "250000"}, {...base, cap: "250000.0000"}, same)).toEqual({});
  });

  it("keeps an edit to an empty value", () => {
    expect(pruneEdits<Form>({cap: ""}, {...base, cap: "5"}, same)).toEqual({cap: ""});
  });

  it("does not turn an untouched field into an edit", () => {
    expect(pruneEdits<Form>({}, base, same)).toEqual({});
  });
});

// wp10-r5-3: an edit the server also changed is a conflict, not a silent overwrite.
describe("moveEdits", () => {
  it("is a conflict when the admin edited a field and the server then changed it to another value", () => {
    expect(moveEdits<Form>({ip: 60}, {...base, ip: 50}, {...base, ip: 10}, same)).toEqual({kept: {ip: 60}, conflicts: ["ip"]});
  });

  it("is no conflict when the server changed another field", () => {
    expect(moveEdits<Form>({ip: 60}, base, {...base, enabled: false}, same)).toEqual({kept: {ip: 60}, conflicts: []});
  });

  it("is no conflict when the server now holds what the admin typed, and the edit follows the server again", () => {
    expect(moveEdits<Form>({ip: 10}, {...base, ip: 50}, {...base, ip: 10}, same)).toEqual({kept: {}, conflicts: []});
  });

  it("is no conflict when the edit was only the old value", () => {
    expect(moveEdits<Form>({ip: 50}, {...base, ip: 50}, {...base, ip: 10}, same)).toEqual({kept: {}, conflicts: []});
  });

  it("reads two spellings of one value as no change by the server", () => {
    expect(moveEdits<Form>({cap: "9"}, {...base, cap: "250000"}, {...base, cap: "250000.0000"}, same)).toEqual({kept: {cap: "9"}, conflicts: []});
  });

  it("names only the fields that conflict", () => {
    const moved = moveEdits<Form>({ip: 60, enabled: false}, {...base, ip: 50}, {...base, ip: 10, enabled: true}, same);
    expect(moved.kept).toEqual({ip: 60, enabled: false});
    expect(moved.conflicts).toEqual(["ip"]);
  });
});
