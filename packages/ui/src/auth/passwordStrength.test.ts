import {describe, expect, it} from "vitest";

import {containsPhoneTail, countedLength, hintFor, loadScorer, meterColor, meterValue, prepare, prepareInputs, SCORED_RUNES} from "./passwordStrength.ts";

// T-100, the client half: advisory, so the tests are about what the meter says and what it does not do.

describe("hintFor", () => {
  it("says nothing for an empty field", () => {
    expect(hintFor("", null)).toBe("none");
  });

  it("puts the length rule first, because the server always enforces it", () => {
    expect(hintFor("short", 4)).toBe("short");
    expect(hintFor("۱۲۳۴۵۶۷۸۹", 4)).toBe("short");
  });

  it("asks for more only below the score the server wants", () => {
    expect(hintFor("a-long-enough-one", 2)).toBe("weak");
    expect(hintFor("a-long-enough-one", 3)).toBe("advisory");
    expect(hintFor("a-long-enough-one", null)).toBe("advisory");
  });

  it("counts code points, not UTF-16 units", () => {
    expect(hintFor("😀".repeat(9), 4)).toBe("short");
    expect(hintFor("😀".repeat(10), 4)).toBe("advisory");
  });
});

describe("the length the server counts (AUTH 4.2, wp8-r8-2)", () => {
  it("is the smaller of the typed code points and the NFKC form's", () => {
    // Ten typed code points (e and a combining acute, five times) compose to five.
    const composed = "é".repeat(5);
    expect([...composed]).toHaveLength(10);
    expect(countedLength(composed)).toBe(5);
    expect(hintFor(composed, 4)).toBe("short");
    // Ten fullwidth letters fold to ten ASCII ones: no shorter, no longer.
    expect(countedLength("ａ".repeat(10))).toBe(10);
  });

  // merge-r1-7: password.Normalize removes U+200C, so the server counts and scores the password without it.
  it("does not count the half-space, which the server removes before it counts", () => {
    const typed = "abcde‌fghi";
    expect([...typed]).toHaveLength(10);
    expect(countedLength(typed)).toBe(9);
    expect(hintFor(typed, 4)).toBe("short");
    expect(prepare("ab‌cd")).toBe("abcd");
  });

  it("does not shorten a password that NFKC leaves alone", () => {
    expect(hintFor("a-long-enough-one", 3)).toBe("advisory");
    expect(hintFor("😀".repeat(10), 4)).toBe("advisory");
  });
});

describe("the meter", () => {
  it("fills in fifths, and the lowest score still shows a sliver", () => {
    expect([0, 1, 2, 3, 4].map((s) => meterValue(s as 0 | 1 | 2 | 3 | 4))).toEqual([20, 40, 60, 80, 100]);
  });

  it("is red below fair, amber at fair, green from good", () => {
    expect([0, 1, 2, 3, 4].map((s) => meterColor(s as 0 | 1 | 2 | 3 | 4))).toEqual(["danger", "danger", "warning", "success", "success"]);
  });
});

describe("what is scored", () => {
  it("reads Persian digits as ASCII and cuts to the first runes", () => {
    expect(prepare("۱۲۳abc")).toBe("123abc");
    expect([...prepare("x".repeat(200))]).toHaveLength(SCORED_RUNES);
  });

  it("reads the same 24 runes as the server (AUTH 4.3 item 4, wp8-r16-1)", () => {
    expect(SCORED_RUNES).toBe(24);
    const head = "abcdefghijklmnopqrstuvwx";
    expect(prepare(`${head}Xq7!vK2#mZ9$wR4&bN8*`)).toBe(head);
    // Code points, not UTF-16 units.
    expect([...prepare("😀".repeat(40))]).toHaveLength(24);
  });

  it("offers the phone with and without its leading zero and with the country code, digits only, plus ctrlz", () => {
    expect(prepareInputs(["09123456789", "۰۹۱۲۳۴۵۶۷۸۹", "12"])).toEqual(["ctrlz", "09123456789", "9123456789", "989123456789"]);
    expect(prepareInputs(["0912 358-2641"])).toEqual(["ctrlz", "09123582641", "9123582641", "989123582641"]);
    expect(prepareInputs(["+98 912 358 2641"])).toEqual(["ctrlz", "989123582641", "9123582641", "09123582641"]);
  });
});

describe("the phone rule of AUTH 4.3 item 3 (wp8-r24-2)", () => {
  const phone = ["0912 358 2641"];

  it("sees the last 7 digits anywhere in the password", () => {
    expect(containsPhoneTail("Kh3582641!x", phone)).toBe(true);
    expect(containsPhoneTail("Kh۳۵۸۲۶۴۱!x", phone)).toBe(true);
    expect(containsPhoneTail("Kh358-2641!x", phone)).toBe(true);
    expect(containsPhoneTail("Kh35_82.6 41", phone)).toBe(true);
    expect(containsPhoneTail("Kh358‌2641!x", phone)).toBe(true);
  });

  it("does not flag other digits or a number too short to carry a tail", () => {
    expect(containsPhoneTail("Kh3582640!x", phone)).toBe(false);
    expect(containsPhoneTail("Kh3582641", ["0912"])).toBe(false);
    expect(containsPhoneTail("Kh3582641", [])).toBe(false);
  });

  it("takes the tail of a number typed with the country code too", () => {
    expect(containsPhoneTail("zz3582641", ["+98 912 358 2641"])).toBe(true);
  });
});

describe("the scorer", () => {
  it("scores a password that holds the phone's last 7 digits as the lowest, though it is long and random", async () => {
    const score = await loadScorer();
    expect(score("correct-horse-battery-3582641-staple-9X!", ["0912 358 2641"])).toBe(0);
    expect(score("correct-horse-battery-3582641-staple-9X!", [])).toBeGreaterThanOrEqual(3);
  }, 30_000);

  it("loads the three language packs and scores a common password low and a long random one high", async () => {
    const score = await loadScorer();
    expect(score("password", [])).toBeLessThanOrEqual(1);
    expect(score("correct-horse-battery-staple-9X!", [])).toBeGreaterThanOrEqual(3);
  }, 30_000);

  it("scores the phone it was told about as weak", async () => {
    const score = await loadScorer();
    expect(score("09123456789", ["09123456789"])).toBeLessThanOrEqual(1);
  }, 30_000);

  it("does not rate text the server never reads (wp8-r16-1)", async () => {
    const score = await loadScorer();
    const head = "passwordpasswordpassword";
    const tail = "Xq7!vK2#mZ9$wR4&bN8*";
    expect(score(head + tail, [])).toBe(score(head, []));
    expect(score(head + tail, [])).toBeLessThan(3);
  }, 30_000);

  it("is one load, however many callers", async () => {
    expect(loadScorer()).toBe(loadScorer());
  });
});
