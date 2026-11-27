import {describe, expect, it} from "vitest";

import {MAX_ALLOWED, canonicalAllowed, checkAllowed, sameAllowed} from "./tokenModel.ts";

describe("checkAllowed (spec p3 6.4: an address or a subnet with no host bits)", () => {
  it("takes an address and a subnet of both families", () => {
    for (const ok of ["203.0.113.7", "203.0.113.0/24", "0.0.0.0/0", "2001:db8::", "2001:db8::/32", "2001:0DB8:0:0:0:0:0:0/32"]) {
      expect(checkAllowed(ok, []).problem, ok).toBeNull();
    }
  });
  it("refuses a subnet that has host bits, and says which problem it is", () => {
    expect(checkAllowed("203.0.113.7/24", []).problem).toBe("hostBits");
    expect(checkAllowed("2001:db8::1/32", []).problem).toBe("hostBits");
    expect(checkAllowed("203.0.113.1/31", []).problem).toBe("hostBits");
  });
  it("refuses what is not an address: a name, a bad mask, a zone, a mapped address", () => {
    for (const bad of ["", " ", "example.com", "203.0.113", "203.0.113.256", "203.0.113.0/33", "203.0.113.0/", "203.0.113.0/-1", "2001:db8::/129", "fe80::1%eth0", "::ffff:1.2.3.4", "::ffff:102:304"]) {
      expect(checkAllowed(bad, []).problem, bad).toBe("invalid");
    }
  });
  // S8-r1-4: the schema of an entry starts with a hex digit and the server refuses a mask with a leading zero.
  it("refuses an entry that starts with a colon and a mask with a leading zero", () => {
    for (const bad of ["::1", "::", "::/0", "::2001:db8", "203.0.113.0/024", "203.0.113.0/00", "2001:db8::/032"]) {
      expect(checkAllowed(bad, []).problem, bad).toBe("invalid");
    }
    expect(checkAllowed("0.0.0.0/0", []).problem).toBeNull();
    expect(checkAllowed("1::", []).problem).toBeNull();
  });
  // S8-r3-4: only the IPv4-mapped form is refused; a dotted tail on another prefix is an address the server takes.
  it("takes a dotted IPv4 tail that is not the mapped form, as the same address as its hex spelling, and refuses the mapped one", () => {
    expect(checkAllowed("64:ff9b::192.0.2.1", []).problem).toBeNull();
    expect(checkAllowed("64:ff9b::192.0.2.1/128", []).problem).toBeNull();
    expect(canonicalAllowed("64:ff9b::192.0.2.1")).toBe(canonicalAllowed("64:ff9b::c000:201"));
    expect(checkAllowed("64:ff9b::c000:201", ["64:ff9b::192.0.2.1"]).problem).toBe("duplicate");
    expect(checkAllowed("64:ff9b::192.0.2.1/96", []).problem).toBe("hostBits");
    expect(checkAllowed("0:0:0:0:0:ffff:1.2.3.4", []).problem).toBe("invalid");
    expect(checkAllowed("64:ff9b::192.0.2.256", []).problem).toBe("invalid");
  });
  it("drops invisible characters before it looks, so a paste from a chat is the address it shows", () => {
    expect(checkAllowed("‎203.0.113.7‏ ", [])).toEqual({value: "203.0.113.7", problem: null});
  });
  it("sees the same entry in two spellings, and the cap", () => {
    expect(checkAllowed("203.0.113.7", ["203.0.113.7/32"]).problem).toBe("duplicate");
    expect(checkAllowed("2001:0db8::/32", ["2001:DB8:0::/32"]).problem).toBe("duplicate");
    expect(checkAllowed("203.0.113.8", Array.from({length: MAX_ALLOWED}, (_, i) => `198.51.100.${i}`)).problem).toBe("max");
  });
});

describe("sameAllowed", () => {
  it("compares as the API does: a bare address is its /32, and the order does not matter", () => {
    expect(sameAllowed(["203.0.113.7/32", "198.51.100.0/24"], ["198.51.100.0/24", "203.0.113.7"])).toBe(true);
    expect(sameAllowed(["203.0.113.7"], [])).toBe(false);
  });
  it("gives no canonical form to junk", () => {
    expect(canonicalAllowed("nope")).toBeNull();
  });
});
