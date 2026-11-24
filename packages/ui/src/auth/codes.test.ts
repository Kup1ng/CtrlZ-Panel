import {describe, expect, it} from "vitest";

import {canonicalInvite, canonicalRecovery, groupCode, groupedCaret, isFullInvite, isFullRecovery} from "./codes.ts";

describe("invite and recovery codes", () => {
  it("canonicalises what was typed: upper case, no spaces or hyphens", () => {
    expect(canonicalInvite("abcd-efgh ijkl-mnop qrst")).toBe("ABCDEFGHIJKLMNOPQRST");
    expect(canonicalRecovery(" ab12-cd34 ")).toBe("AB12CD34");
  });

  it("reads Persian and Arabic digits as ASCII", () => {
    expect(canonicalRecovery("۱۲۳۴-abcd")).toBe("1234ABCD");
    expect(canonicalRecovery("٠١٢٣")).toBe("0123");
  });

  it("cuts at the length of the code", () => {
    expect(canonicalInvite("A".repeat(30))).toHaveLength(20);
    expect(canonicalRecovery("B".repeat(30))).toHaveLength(16);
  });

  it("groups four at a time for display and the grouping survives a round trip", () => {
    expect(groupCode("ABCDEFGHIJ")).toBe("ABCD-EFGH-IJ");
    expect(groupCode("")).toBe("");
    const typed = groupCode("ABCDEFGHIJKLMNOPQRST");
    expect(typed).toBe("ABCD-EFGH-IJKL-MNOP-QRST");
    expect(canonicalInvite(typed)).toBe("ABCDEFGHIJKLMNOPQRST");
  });

  it("knows a full code", () => {
    expect(isFullInvite("A".repeat(20))).toBe(true);
    expect(isFullInvite("A".repeat(19))).toBe(false);
    expect(isFullRecovery("A".repeat(16))).toBe(true);
  });
});

describe("groupedCaret (wp8-r5-3)", () => {
  it("puts the caret after the same number of characters in the grouped text", () => {
    const shown = groupCode("ABCDEFGHJKMN");
    expect(shown).toBe("ABCD-EFGH-JKMN");
    for (const count of [0, 1, 3, 4, 5, 8, 9, 12]) {
      const at = groupedCaret(count);
      // The characters before the caret, with the hyphens left out, are the same count.
      expect(shown.slice(0, at).replace(/-/g, "")).toHaveLength(count);
    }
    expect(groupedCaret(4)).toBe(4);
    expect(groupedCaret(5)).toBe(6);
    expect(groupedCaret(8)).toBe(9);
  });
});
