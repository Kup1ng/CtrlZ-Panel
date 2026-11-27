import {describe, expect, it} from "vitest";

import {checkLockMessage, checkLockPassword, checkUnlockPassword, lockPasswordLength} from "./lockPassword.ts";

describe("lock password bound (spec p2 7.1)", () => {
  it("is 6 to 128 code points", () => {
    expect(checkLockPassword("")).toBe("required");
    expect(checkLockPassword("a".repeat(5))).toBe("too_short");
    expect(checkLockPassword("a".repeat(6))).toBeNull();
    expect(checkLockPassword("a".repeat(128))).toBeNull();
    expect(checkLockPassword("a".repeat(129))).toBe("too_long");
  });

  it("counts code points and not UTF-16 units", () => {
    // Six emoji are twelve units and six code points: long enough.
    expect(checkLockPassword("😀".repeat(6))).toBeNull();
    expect(checkLockPassword("😀".repeat(5))).toBe("too_short");
  });

  it("counts after NFKC, as the server does: U+FDFA is one point that becomes eighteen", () => {
    expect(lockPasswordLength("ﷺ")).toBe(18);
    expect(checkLockPassword("ﷺ".repeat(7))).toBeNull(); // 126
    expect(checkLockPassword("ﷺ".repeat(8))).toBe("too_long"); // 144
    expect(checkUnlockPassword("ﷺ".repeat(8))).toBe("too_long");
  });

  it("drops the half-space, so a Persian keyboard's password is the same with or without it", () => {
    expect(lockPasswordLength("می‌خواهم")).toBe(lockPasswordLength("میخواهم"));
  });

  it("does not hold a short wrong password against the person on unlock", () => {
    expect(checkUnlockPassword("abc")).toBeNull();
    expect(checkUnlockPassword("")).toBe("required");
  });

  it("bounds the message at 256 characters", () => {
    expect(checkLockMessage("a".repeat(256))).toBeNull();
    expect(checkLockMessage("a".repeat(257))).toBe("too_long");
    expect(checkLockMessage("  ")).toBeNull();
  });
});
