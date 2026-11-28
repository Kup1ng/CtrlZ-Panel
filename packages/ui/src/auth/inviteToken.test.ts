import {describe, expect, it} from "vitest";

import {INVITE_TOKEN_LENGTH, inviteTokenFromFragment, inviteTokenFromPaste, isInviteToken} from "./inviteToken.ts";

// A token of the real shape: 140 characters of the base64url alphabet, upper and lower case, digits, hyphen and underscore. Made of a
// repeated word so that a secret scanner does not take it for a key.
const base = "Fixture-token_Aa-09";
const token = base.repeat(8).slice(0, INVITE_TOKEN_LENGTH);

describe("isInviteToken (D67)", () => {
  it("takes exactly 140 characters of A-Z a-z 0-9 _ - and nothing else", () => {
    expect(token).toHaveLength(140);
    expect(isInviteToken(token)).toBe(true);
    expect(isInviteToken(token.slice(1))).toBe(false);
    expect(isInviteToken(`${token}a`)).toBe(false);
    expect(isInviteToken(`${token.slice(1)}=`)).toBe(false);
    expect(isInviteToken(`${token.slice(1)}.`)).toBe(false);
    expect(isInviteToken(`${token.slice(1)}۱`)).toBe(false);
    expect(isInviteToken("")).toBe(false);
  });
});

describe("inviteTokenFromPaste", () => {
  it("returns a bare token unchanged: case, hyphens, underscores and digits stay", () => {
    expect(inviteTokenFromPaste(token)).toBe(token);
    expect(inviteTokenFromPaste(token.toLowerCase())).toBe(token.toLowerCase());
    expect(inviteTokenFromPaste(token.toLowerCase())).not.toBe(token);
  });

  it("cuts the token out of a whole link, with or without a language prefix, and out of a bare fragment", () => {
    expect(inviteTokenFromPaste(`https://panel.example.ir/invite#${token}`)).toBe(token);
    expect(inviteTokenFromPaste(`https://panel.example.ir/fa/invite#${token}`)).toBe(token);
    expect(inviteTokenFromPaste(`/en/invite#${token}`)).toBe(token);
    expect(inviteTokenFromPaste(`#${token}`)).toBe(token);
  });

  it("drops white space, line breaks and invisible marks a paste brings along", () => {
    const wrapped = `  https://panel.example.ir/invite#\u200e${token.slice(0, 70)}\n${token.slice(70)}\u00a0\u200f `;
    expect(inviteTokenFromPaste(wrapped)).toBe(token);
    expect(inviteTokenFromPaste(`\t${token.slice(0, 10)} ${token.slice(10, 20)}\u200c${token.slice(20)}\r\n`)).toBe(token);
  });

  it("refuses what is not a token: wrong length, wrong alphabet, no fragment, a second fragment", () => {
    expect(inviteTokenFromPaste("")).toBeNull();
    expect(inviteTokenFromPaste("https://panel.example.ir/invite")).toBeNull();
    expect(inviteTokenFromPaste("https://panel.example.ir/invite#")).toBeNull();
    expect(inviteTokenFromPaste(token.slice(0, 139))).toBeNull();
    expect(inviteTokenFromPaste(`${token}x`)).toBeNull();
    expect(inviteTokenFromPaste(`${token.slice(0, 139)}!`)).toBeNull();
    expect(inviteTokenFromPaste(`https://h/invite#${token}#${token}`)).toBeNull();
  });

  // webi-r1-4: the server folds the digits (invite.fold) before it opens the token, so a paste that shows them as Persian is the same invite.
  it("reads Persian, Arabic and fullwidth digits as ASCII the way the server does, and never folds case or hyphens", () => {
    const digitsAt = token.replace(/0/g, "۰").replace(/9/g, "٩");
    expect(digitsAt).not.toBe(token);
    expect(inviteTokenFromPaste(digitsAt)).toBe(token);
    expect(inviteTokenFromFragment(`#${digitsAt}`)).toBe(token);
    expect(inviteTokenFromPaste(token.replace(/0/g, "０"))).toBe(token);
    expect(inviteTokenFromPaste(token.toLowerCase())).not.toBe(token);
    expect(inviteTokenFromPaste(token)).toBe(token);
    // A letter that is not in the alphabet stays refused.
    expect(inviteTokenFromPaste(`${token.slice(0, 139)}ب`)).toBeNull();
  });
});

describe("inviteTokenFromFragment", () => {
  it("takes a token behind the #", () => {
    expect(inviteTokenFromFragment(`#${token}`)).toBe(token);
    expect(inviteTokenFromFragment(token)).toBe(token);
  });

  // webi-r2-1, webi-r2-9: a browser gives `location.hash` percent-encoded, so the marks and digits arrive as %XX. The test goes through
  // `new URL`, which is what the address bar does, and not through a string a browser never produces.
  it("reads the percent-encoded fragment a browser gives: a trailing mark, a space and Persian digits fold as in a paste", () => {
    const hashOf = (fragment: string) => new URL(`https://panel.example.ir/invite#${fragment}`).hash;
    expect(hashOf(`${token}‏`)).toContain("%E2%80%8F");
    expect(inviteTokenFromFragment(hashOf(`${token}‏`))).toBe(token);
    expect(inviteTokenFromFragment(hashOf(`${token} `))).toBe(token);
    expect(inviteTokenFromFragment(hashOf(token.replace(/0/g, "۰")))).toBe(token);
    expect(hashOf(token.replace(/0/g, "۰"))).toContain("%DB%B0");
    expect(inviteTokenFromPaste(`https://panel.example.ir/invite${hashOf(`${token}‏`)}`)).toBe(token);
    expect(inviteTokenFromPaste(hashOf(token.replace(/0/g, "۰")))).toBe(token);
  });

  it("refuses a malformed percent escape and a token that decodes to something else, without throwing", () => {
    expect(inviteTokenFromFragment(`#${token.slice(0, 137)}%E2%`)).toBeNull();
    expect(inviteTokenFromFragment(`#${token.slice(0, 137)}%zz`)).toBeNull();
    expect(inviteTokenFromPaste(`/invite#${token.slice(0, 139)}%`)).toBeNull();
  });

  it("returns null for something that is not a token, and for nothing", () => {
    expect(inviteTokenFromFragment("")).toBeNull();
    expect(inviteTokenFromFragment("#")).toBeNull();
    expect(inviteTokenFromFragment("#---")).toBeNull();
    expect(inviteTokenFromFragment(`#${token.slice(0, 20)}`)).toBeNull();
    expect(inviteTokenFromFragment(`#${token}a`)).toBeNull();
  });
});
