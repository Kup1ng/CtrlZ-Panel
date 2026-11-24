import {ApiError, type ErrorCode} from "@ctrlz/api-client/errors.ts";
import {beforeEach, describe, expect, it, vi} from "vitest";

// The session modules read `window`, which this node-environment suite has not got: they are replaced.
const session = vi.hoisted(() => ({
  isSessionEnding: vi.fn(() => false),
  isOnLoginPath: vi.fn(() => false),
  logoutLocal: vi.fn(),
  leaveEndedAdminSession: vi.fn(),
}));
vi.mock("@ctrlz/api-client/session.ts", () => ({
  isSessionEnding: session.isSessionEnding,
  isOnLoginPath: session.isOnLoginPath,
  logoutLocal: session.logoutLocal,
}));
vi.mock("@ctrlz/api-client/admin/session.ts", () => ({leaveEndedAdminSession: session.leaveEndedAdminSession}));
vi.mock("../shell/currentNext.ts", () => ({currentNext: (app: string) => `/next-of-${app}`}));

import {callWithRecovery, classifyApiError, endSessionFor, handleApiError, isHandledError, type ApiErrorActions} from "./handleApiError.ts";

const err = (code: ErrorCode, status = 400) => new ApiError(status, code);

function actions(over: Partial<ApiErrorActions> = {}) {
  return {app: "panel", navigate: vi.fn(), endSession: vi.fn(() => true), ...over} as ApiErrorActions & {
    navigate: ReturnType<typeof vi.fn>;
    endSession: ReturnType<typeof vi.fn>;
  };
}

describe("classifyApiError (spec 14.3 table)", () => {
  it("ends the session on session_expired", () => {
    expect(classifyApiError(err("session_expired", 401), "panel")).toEqual({kind: "session_ended"});
    expect(classifyApiError(err("session_expired", 401), "admin")).toEqual({kind: "session_ended"});
  });

  it("sends to the page of the state", () => {
    expect(classifyApiError(err("password_change_required", 403), "panel")).toEqual({kind: "navigate", to: "/change-password"});
    expect(classifyApiError(err("account_suspended", 403), "panel")).toEqual({kind: "navigate", to: "/suspended"});
  });

  it("answers setup_required only in admin", () => {
    expect(classifyApiError(err("setup_required", 403), "admin")).toEqual({kind: "navigate", to: "/setup"});
    expect(classifyApiError(err("setup_required", 403), "panel")).toEqual({kind: "inline"});
  });

  it("asks for the proof of the app that has it", () => {
    expect(classifyApiError(err("reauth_required", 403), "panel")).toEqual({kind: "reauth"});
    expect(classifyApiError(err("reauth_required", 403), "admin")).toEqual({kind: "inline"});
    expect(classifyApiError(err("totp_fresh_required", 403), "admin")).toEqual({kind: "fresh_totp"});
    expect(classifyApiError(err("totp_fresh_required", 403), "panel")).toEqual({kind: "inline"});
  });

  it("leaves everything else, and anything that is not an ApiError, to the caller", () => {
    expect(classifyApiError(err("invalid_credentials", 401), "panel")).toEqual({kind: "inline"});
    expect(classifyApiError(err("validation_failed"), "panel")).toEqual({kind: "inline"});
    expect(classifyApiError(new TypeError("fetch failed"), "panel")).toEqual({kind: "inline"});
    expect(classifyApiError(undefined, "panel")).toEqual({kind: "inline"});
  });

  it("treats not_found as the section's own state", () => {
    expect(classifyApiError(err("not_found", 404), "panel")).toEqual({kind: "not_found"});
  });
});

describe("handleApiError", () => {
  it("acts and reports handled for a session end, a navigation and a section 404 it has a state for", () => {
    const a = actions({onNotFound: vi.fn()});
    const e1 = err("session_expired", 401);
    expect(handleApiError(e1, a)).toBe(true);
    expect(a.endSession).toHaveBeenCalledOnce();
    expect(isHandledError(e1)).toBe(true);

    expect(handleApiError(err("account_suspended", 403), a)).toBe(true);
    expect(a.navigate).toHaveBeenCalledWith("/suspended");

    expect(handleApiError(err("not_found", 404), a)).toBe(true);
    expect(a.onNotFound).toHaveBeenCalledOnce();
  });

  it("does not claim a not_found it has no state for, nor an inline error", () => {
    const a = actions();
    const nf = err("not_found", 404);
    expect(handleApiError(nf, a)).toBe(false);
    expect(isHandledError(nf)).toBe(false);
    expect(handleApiError(err("conflict", 409), a)).toBe(false);
    expect(a.navigate).not.toHaveBeenCalled();
    expect(a.endSession).not.toHaveBeenCalled();
  });
});

describe("callWithRecovery", () => {
  it("returns the value of a call that works, and touches nothing", async () => {
    const a = actions();
    expect(await callWithRecovery(async () => 7, a)).toBe(7);
    expect(a.navigate).not.toHaveBeenCalled();
  });

  it("repeats a reauth_required call exactly once after the user confirmed", async () => {
    const call = vi.fn().mockRejectedValueOnce(err("reauth_required", 403)).mockResolvedValueOnce("ok");
    const reauth = vi.fn().mockResolvedValue(true);
    expect(await callWithRecovery(call, actions({reauth}))).toBe("ok");
    expect(reauth).toHaveBeenCalledOnce();
    expect(call).toHaveBeenCalledTimes(2);
  });

  it("does not loop: a second reauth_required is thrown and the dialog is not opened again", async () => {
    const second = err("reauth_required", 403);
    const call = vi.fn().mockRejectedValueOnce(err("reauth_required", 403)).mockRejectedValueOnce(second);
    const reauth = vi.fn().mockResolvedValue(true);
    await expect(callWithRecovery(call, actions({reauth}))).rejects.toBe(second);
    expect(reauth).toHaveBeenCalledOnce();
    expect(call).toHaveBeenCalledTimes(2);
  });

  it("throws the original error, with no repeat, when the user gives up or the dialog fails", async () => {
    const first = err("reauth_required", 403);
    const call = vi.fn().mockRejectedValue(first);
    await expect(callWithRecovery(call, actions({reauth: vi.fn().mockResolvedValue(false)}))).rejects.toBe(first);
    await expect(callWithRecovery(call, actions({reauth: vi.fn().mockRejectedValue(new Error("x"))}))).rejects.toBe(first);
    expect(call).toHaveBeenCalledTimes(2);
  });

  it("throws as is when the screen gave no dialog for a proof", async () => {
    const first = err("totp_fresh_required", 403);
    await expect(callWithRecovery(() => Promise.reject(first), actions({app: "admin"}))).rejects.toBe(first);
  });

  it("uses the fresh-TOTP dialog in admin", async () => {
    const call = vi.fn().mockRejectedValueOnce(err("totp_fresh_required", 403)).mockResolvedValueOnce(1);
    const freshTotp = vi.fn().mockResolvedValue(true);
    const reauth = vi.fn();
    expect(await callWithRecovery(call, actions({app: "admin", freshTotp, reauth}))).toBe(1);
    expect(freshTotp).toHaveBeenCalledOnce();
    expect(reauth).not.toHaveBeenCalled();
  });

  it("applies the global rules to the error of the repeat", async () => {
    const dead = err("session_expired", 401);
    const call = vi.fn().mockRejectedValueOnce(err("reauth_required", 403)).mockRejectedValueOnce(dead);
    const a = actions({reauth: vi.fn().mockResolvedValue(true)});
    await expect(callWithRecovery(call, a)).rejects.toBe(dead);
    expect(a.endSession).toHaveBeenCalledOnce();
  });

  it("acts on a global error and still throws it, marked handled", async () => {
    const a = actions();
    const e = err("password_change_required", 403);
    await expect(callWithRecovery(() => Promise.reject(e), a)).rejects.toBe(e);
    expect(a.navigate).toHaveBeenCalledWith("/change-password");
    expect(isHandledError(e)).toBe(true);
  });
});

describe("handleApiError when the session cannot be ended here (wp7-r1-1)", () => {
  it("does not claim a session_expired that nothing acted on, so the screen can show it", () => {
    const a = actions({endSession: vi.fn(() => false)});
    const e = err("session_expired", 401);
    expect(handleApiError(e, a)).toBe(false);
    expect(isHandledError(e)).toBe(false);
  });
});

describe("endSessionFor", () => {
  const context = {queryClient: {} as never, locale: "fa"};
  beforeEach(() => {
    session.isSessionEnding.mockReturnValue(false);
    session.isOnLoginPath.mockReturnValue(false);
    session.logoutLocal.mockClear();
    session.leaveEndedAdminSession.mockClear();
  });

  it("leaves the admin with the ended marker, with no panel binding anywhere", () => {
    expect(endSessionFor("admin", context)).toBe(true);
    expect(session.leaveEndedAdminSession).toHaveBeenCalledWith(context, "/next-of-admin");
    expect(session.logoutLocal).not.toHaveBeenCalled();
  });

  it("clears and leaves the panel without needing its binding", () => {
    expect(endSessionFor("panel", context)).toBe(true);
    expect(session.logoutLocal).toHaveBeenCalledWith(context, {broadcast: false, next: "/next-of-panel"});
    expect(session.leaveEndedAdminSession).not.toHaveBeenCalled();
  });

  it("reports true and does nothing twice when the page is already leaving", () => {
    session.isSessionEnding.mockReturnValue(true);
    expect(endSessionFor("admin", context)).toBe(true);
    expect(endSessionFor("panel", context)).toBe(true);
    expect(session.logoutLocal).not.toHaveBeenCalled();
    expect(session.leaveEndedAdminSession).not.toHaveBeenCalled();
  });

  it("reports false on the login page, so the screen shows the error there", () => {
    session.isOnLoginPath.mockReturnValue(true);
    expect(endSessionFor("admin", context)).toBe(false);
    expect(endSessionFor("panel", context)).toBe(false);
    expect(session.logoutLocal).not.toHaveBeenCalled();
    expect(session.leaveEndedAdminSession).not.toHaveBeenCalled();
  });
});
