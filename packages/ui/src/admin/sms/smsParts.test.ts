import {describe, expect, it} from "vitest";

import {isTemplateId} from "./providers.ts";
import {countSms, filled, isOnePartKey, OTP_EN_MAX_UNITS, OTP_FA_MAX_UNITS, otpBodyRefusal, placeholders} from "./smsParts.ts";

describe("countSms", () => {
  it("fills {code} with a code of full length before it counts", () => {
    expect(filled("Code: {code}")).toBe("Code: 000000");
    expect(countSms("Code: {code}").units).toBe(12);
  });

  it("counts a Latin text as GSM-7 with 160 for one part and 153 after", () => {
    const a = countSms("a".repeat(160));
    expect(a).toMatchObject({encoding: "gsm7", parts: 1, single: 160, multi: 153});
    expect(countSms("a".repeat(161)).parts).toBe(2);
    expect(countSms("a".repeat(306)).parts).toBe(2);
    expect(countSms("a".repeat(307)).parts).toBe(3);
  });

  it("counts the GSM extension characters twice", () => {
    expect(countSms("{}").units).toBe(4);
    expect(countSms("€").units).toBe(2);
  });

  it("switches to UCS-2 for one Persian character: 70 for one part and 67 after", () => {
    expect(countSms("سلام").encoding).toBe("ucs2");
    expect(countSms("س".repeat(70)).parts).toBe(1);
    expect(countSms("س".repeat(71)).parts).toBe(2);
    expect(countSms("س".repeat(134)).parts).toBe(2);
    expect(countSms("س".repeat(135)).parts).toBe(3);
  });

  it("counts a character outside the BMP as two units and one character", () => {
    const c = countSms("😀");
    expect(c.characters).toBe(1);
    expect(c.units).toBe(2);
    expect(c.encoding).toBe("ucs2");
  });

  it("has no part for an empty body", () => {
    expect(countSms("").parts).toBe(0);
  });
});

// The same cases as sms.CheckBodyLength on the server (internal/sms, TestCheckBodyLengthBoundsTheThreeOTPBodiesAndNothingElse):
// the page must refuse before Save exactly what the API refuses after it (wp10-r17-1).
describe("the one-billed-part rule of the login-code templates", () => {
  const fa = (n: number) => "ک".repeat(n);
  it("bounds the three login-code keys and nothing else", () => {
    expect(["otp", "otp_reset", "otp_phone"].every(isOnePartKey)).toBe(true);
    expect(["invite", "otp_login", "otp.x", "hotp", "welcome"].some(isOnePartKey)).toBe(false);
    expect(otpBodyRefusal("invite", "fa", fa(500))).toBeNull();
    expect(otpBodyRefusal("otp_login", "fa", fa(500))).toBeNull();
  });

  it("holds Persian to 64 UCS-2 units with the code filled in", () => {
    expect(OTP_FA_MAX_UNITS).toBe(64);
    expect(otpBodyRefusal("otp", "fa", fa(64))).toBeNull();
    expect(otpBodyRefusal("otp", "fa", fa(65))).toBe("too_long");
    // {code} counts as six characters, so a short text with the code in it can cross the line.
    expect(otpBodyRefusal("otp", "fa", `${fa(58)}{code}`)).toBeNull();
    expect(otpBodyRefusal("otp", "fa", `${fa(59)}{code}`)).toBe("too_long");
    // A character outside the BMP is two units on the wire.
    expect(otpBodyRefusal("otp_phone", "fa", `${fa(63)}😀`)).toBe("too_long");
    // Latin text in a Persian-language template is counted in UCS-2 units too, as the server does.
    expect(otpBodyRefusal("otp", "fa", "a".repeat(65))).toBe("too_long");
  });

  it("holds English to 160 GSM-7 units, and to GSM characters only", () => {
    expect(OTP_EN_MAX_UNITS).toBe(160);
    expect(otpBodyRefusal("otp", "en", "a".repeat(160))).toBeNull();
    expect(otpBodyRefusal("otp", "en", "a".repeat(161))).toBe("too_long");
    // Extension characters take two units.
    expect(otpBodyRefusal("otp_reset", "en", "€".repeat(80))).toBeNull();
    expect(otpBodyRefusal("otp_reset", "en", "€".repeat(81))).toBe("too_long");
    // One character outside the alphabet makes the whole message UCS-2, however short it is.
    expect(otpBodyRefusal("otp", "en", "Code ç {code}")).toBe("not_gsm");
    expect(otpBodyRefusal("otp", "en", "کد {code}")).toBe("not_gsm");
    expect(otpBodyRefusal("otp", "en", "ok 😀")).toBe("not_gsm");
  });
});

describe("a provider template id", () => {
  it("is 1 to 18 digits above zero for every provider", () => {
    for (const provider of ["melipayamak", "noop", "sms_ir"]) {
      expect(isTemplateId(provider, "")).toBe(false);
      expect(isTemplateId(provider, "0")).toBe(false);
      expect(isTemplateId(provider, "000")).toBe(false);
      expect(isTemplateId(provider, "-5")).toBe(false);
      expect(isTemplateId(provider, "12a")).toBe(false);
      expect(isTemplateId(provider, "1234567890123456789")).toBe(false);
      expect(isTemplateId(provider, "1")).toBe(true);
    }
    expect(isTemplateId("melipayamak", "123456789012345678")).toBe(true);
  });

  it("is also within int32 for sms.ir", () => {
    expect(isTemplateId("sms_ir", "2147483647")).toBe(true);
    expect(isTemplateId("sms_ir", "2147483648")).toBe(false);
    expect(isTemplateId("sms_ir", "9999999999")).toBe(false);
    expect(isTemplateId("melipayamak", "2147483648")).toBe(true);
  });
});

describe("placeholders", () => {
  it("lists the names once, in order", () => {
    expect(placeholders("a {code} b {code} c {name}")).toEqual(["code", "name"]);
    expect(placeholders("none")).toEqual([]);
  });
});
