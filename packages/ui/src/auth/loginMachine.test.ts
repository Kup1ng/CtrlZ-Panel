import {ApiError} from "@ctrlz/api-client/errors.ts";
import {describe, expect, it} from "vitest";

import {initialLoginState, loginErrorOutcome, loginReducer, resultOutcome, stepFromParam} from "./loginMachine.ts";

// The two outcome tables of spec 10.2, row by row.

const err = (code: ConstructorParameters<typeof ApiError>[1], status = 401) => new ApiError(status, code);

describe("resultOutcome (the first rows of the table)", () => {
  it("authenticated goes in", () => {
    expect(resultOutcome({status: "authenticated"})).toEqual({kind: "authenticated"});
  });

  it("mfa_required keeps the ticket and its methods", () => {
    expect(resultOutcome({status: "mfa_required", ticket: "t1", ticket_expires_in_s: 120, methods: ["totp", "recovery_code"]})).toEqual({
      kind: "mfa",
      ticket: "t1",
      expiresInS: 120,
      methods: ["totp", "recovery_code"],
    });
  });

  it("mfa_required without methods offers the authenticator code", () => {
    expect(resultOutcome({status: "mfa_required", ticket: "t1"})).toMatchObject({kind: "mfa", methods: ["totp"]});
  });

  it("mfa_required without a ticket cannot continue", () => {
    expect(resultOutcome({status: "mfa_required"})).toEqual({kind: "unreadable"});
  });

  it("passkey_required goes to the passkey step", () => {
    expect(resultOutcome({status: "passkey_required"})).toEqual({kind: "passkey"});
  });
});

describe("loginErrorOutcome (the error rows)", () => {
  it("invalid_credentials: one neutral message, password cleared", () => {
    expect(loginErrorOutcome("password", err("invalid_credentials"))).toEqual({kind: "invalidCredentials"});
  });

  it("otp_invalid is the code's error, the slots clear", () => {
    expect(loginErrorOutcome("otp-code", err("otp_invalid"))).toEqual({kind: "code"});
  });

  it("otp_expired and otp_locked go back to the number, which stays", () => {
    expect(loginErrorOutcome("otp-code", err("otp_expired"))).toEqual({kind: "back", to: "otp-phone"});
    expect(loginErrorOutcome("otp-code", err("otp_locked", 429))).toEqual({kind: "back", to: "otp-phone"});
  });

  it("totp_invalid and totp_step_reused stay on the code, the ticket is kept", () => {
    expect(loginErrorOutcome("2fa", err("totp_invalid"))).toEqual({kind: "code"});
    expect(loginErrorOutcome("2fa", err("totp_step_reused"))).toEqual({kind: "code"});
  });

  it("ticket_invalid goes back to the password step", () => {
    expect(loginErrorOutcome("2fa", err("ticket_invalid"))).toEqual({kind: "back", to: "password"});
  });

  it("ticket_invalid on the passkey step goes back to the password step too (10.2, wp8-r16-2)", () => {
    expect(loginErrorOutcome("passkey", err("ticket_invalid"))).toEqual({kind: "back", to: "password"});
  });

  it("passkey_invalid is a form error with Try again", () => {
    expect(loginErrorOutcome("passkey", err("passkey_invalid"))).toEqual({kind: "form"});
  });

  it("passkey_unavailable removes the passkey button, wherever it came from", () => {
    expect(loginErrorOutcome("passkey", err("passkey_unavailable", 404))).toEqual({kind: "passkeyGone"});
    expect(loginErrorOutcome("password", err("passkey_unavailable", 404))).toEqual({kind: "passkeyGone"});
  });

  it("account_suspended is explained in place on every step, since the refusal made no session (wp8-r2-1)", () => {
    for (const step of ["password", "otp-phone", "otp-code", "2fa", "passkey"] as const) {
      expect(loginErrorOutcome(step, err("account_suspended", 403))).toEqual({kind: "suspended"});
    }
  });

  it("a closed WebAuthn prompt is silent", () => {
    expect(loginErrorOutcome("passkey", new DOMException("closed", "NotAllowedError"))).toEqual({kind: "silent"});
    expect(loginErrorOutcome("passkey", new DOMException("replaced", "AbortError"))).toEqual({kind: "silent"});
  });

  it("everything else is the form's: a wait, a busy server, an unknown failure", () => {
    expect(loginErrorOutcome("password", err("too_many_attempts", 429))).toEqual({kind: "form"});
    expect(loginErrorOutcome("password", err("server_busy", 503))).toEqual({kind: "form"});
    expect(loginErrorOutcome("otp-phone", err("sms_unavailable", 503))).toEqual({kind: "form"});
    expect(loginErrorOutcome("password", new TypeError("network"))).toEqual({kind: "form"});
  });

  it("a wrong code of the wrong step is not taken for a code error", () => {
    expect(loginErrorOutcome("password", err("otp_invalid"))).toEqual({kind: "form"});
    expect(loginErrorOutcome("otp-code", err("totp_invalid"))).toEqual({kind: "form"});
  });
});

describe("loginReducer", () => {
  it("suspended shows the explanation on the first step, drops the ticket and the challenge, and back leaves it", () => {
    const at2fa = loginReducer(initialLoginState(), {type: "mfa", ticket: "t", endsAt: 1, methods: ["totp"]});
    const suspended = loginReducer(at2fa, {type: "suspended"});
    expect(suspended).toMatchObject({suspended: true, step: "password", ticket: null, challenge: null});
    const back = loginReducer(suspended, {type: "back", to: "password"});
    expect(back).toMatchObject({suspended: false, returned: true});
    expect(loginReducer(suspended, {type: "tab", step: "otp-phone"}).suspended).toBe(false);
  });

  const start = initialLoginState();

  it("keeps the number and drops the challenge when it goes back", () => {
    let s = loginReducer(start, {type: "phone", value: "0912"});
    s = loginReducer(s, {type: "otpSent", id: "c1", readyAt: 5});
    expect(s.step).toBe("otp-code");
    expect(s.challenge).toEqual({id: "c1", readyAt: 5});
    const notice = err("otp_expired");
    s = loginReducer(s, {type: "back", to: "otp-phone", notice});
    expect(s).toMatchObject({step: "otp-phone", phone: "0912", challenge: null, notice});
  });

  it("holds the ticket only while it is on the 2fa step", () => {
    let s = loginReducer(start, {type: "mfa", ticket: "t", endsAt: 9, methods: ["totp"]});
    expect(s.ticket).toEqual({value: "t", endsAt: 9, methods: ["totp"]});
    s = loginReducer(s, {type: "back", to: "password"});
    expect(s.ticket).toBeNull();
  });

  it("a passkey step carries no ticket", () => {
    const s = loginReducer(loginReducer(start, {type: "mfa", ticket: "t", endsAt: 9, methods: ["totp"]}), {type: "passkey"});
    expect(s).toMatchObject({step: "passkey", ticket: null});
  });

  it("passkey_unavailable leaves the passkey step and stays gone", () => {
    const s = loginReducer(loginReducer(start, {type: "passkey"}), {type: "passkeyGone"});
    expect(s).toMatchObject({step: "password", passkeyGone: true});
  });

  it("a step reached by going back says so, so it can take the focus the left step lost (wp8-r1-4)", () => {
    expect(start.returned).toBe(false);
    const back = loginReducer(loginReducer(start, {type: "otpSent", id: "c", readyAt: 1}), {type: "back", to: "otp-phone"});
    expect(back.returned).toBe(true);
    const gone = loginReducer(loginReducer(start, {type: "passkey"}), {type: "passkeyGone"});
    expect(gone.returned).toBe(true);
    // Going on, or switching a tab (the focus is on the tab), is not a return.
    expect(loginReducer(back, {type: "otpSent", id: "d", readyAt: 2}).returned).toBe(false);
    expect(loginReducer(back, {type: "tab", step: "password"}).returned).toBe(false);
    expect(loginReducer(back, {type: "passkey"}).returned).toBe(false);
    expect(loginReducer(back, {type: "mfa", ticket: "t", endsAt: 9, methods: ["totp"]}).returned).toBe(false);
  });

  it("switching the tab clears a notice", () => {
    const s = loginReducer({...start, notice: err("ticket_invalid")}, {type: "tab", step: "otp-phone"});
    expect(s.notice).toBeNull();
  });
});

describe("stepFromParam", () => {
  it("lets a reload land only on a step that needs no ticket", () => {
    expect(stepFromParam("otp-phone", true)).toBe("otp-phone");
    expect(stepFromParam("2fa", true)).toBe("password");
    expect(stepFromParam("passkey", true)).toBe("password");
    expect(stepFromParam("otp-code", true)).toBe("password");
    expect(stepFromParam(null, true)).toBe("password");
  });

  it("does not offer the SMS step when SMS is down", () => {
    expect(stepFromParam("otp-phone", false)).toBe("password");
  });
});

describe("the notice of a step we came back to (wp8-r3-2)", () => {
  const back = loginReducer(initialLoginState(), {type: "back", to: "password", notice: err("ticket_invalid")});

  it("is kept until the visitor does something, and is gone after an edit of the number or a clearNotice", () => {
    expect(back.notice).not.toBeNull();
    expect(loginReducer(back, {type: "remember", value: true}).notice).not.toBeNull();
    expect(loginReducer(back, {type: "phone", value: "0912"}).notice).toBeNull();
    expect(loginReducer(back, {type: "clearNotice"}).notice).toBeNull();
  });

  it("clearNotice with nothing to clear returns the same state, so it costs no render", () => {
    const clean = loginReducer(back, {type: "clearNotice"});
    expect(loginReducer(clean, {type: "clearNotice"})).toBe(clean);
  });
});
