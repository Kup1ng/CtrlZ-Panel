import {describe, expect, it} from "vitest";

import {paramsText} from "./AuditPage.tsx";

// Spec 13.5. Audit params are one compact line of `name=value` text. It is text: nothing here is HTML, and a long row is cut.

describe("paramsText", () => {
  it("joins scalars and short lists as name=value", () => {
    expect(paramsText({method: "password", cleared: 1, kept: false, fields: ["a", "b"]})).toBe("method=password cleared=1 kept=false fields=a,b");
  });
  it("leaves markup as the characters it is", () => {
    expect(paramsText({note: "<b>x</b>"})).toBe("note=<b>x</b>");
  });
  it("cuts a very long row at 300 characters, with an ellipsis", () => {
    const text = paramsText({a: "x".repeat(250), b: "y".repeat(250)});
    expect(text.length).toBe(301);
    expect(text.endsWith("…")).toBe(true);
  });
  it("is empty for no params", () => {
    expect(paramsText({})).toBe("");
  });
});
