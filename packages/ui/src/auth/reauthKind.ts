import type {Me} from "@ctrlz/api-client/session.ts";

// Spec 12.1 and AUTH 3.5: what a reauth asks for depends on what the account has, and the server
// decides it by the same table. The client only chooses which fields to draw. SMS never stands in
// for a password or an authenticator (a SIM swap is the threat the rule is for), so the OTP kind
// exists only for an account with neither.

export type ReauthKind = "password" | "password_totp" | "totp" | "otp";

export function reauthKind(me: Pick<Me, "user" | "security">): ReauthKind {
  const password = me.user.has_password;
  const totp = me.security.totp_enabled;
  if (password && totp) return "password_totp";
  if (password) return "password";
  if (totp) return "totp";
  return "otp";
}

/**
 * Whether "Use a passkey" is offered (spec 12.1). A passkey assertion is refused while a review of the
 * list is pending (AUTH 7.7), and the operator can switch passkeys off altogether (`passkey_enabled`).
 */
export function canReauthWithPasskey(me: Pick<Me, "security">, passkeyEnabled: boolean): boolean {
  return passkeyEnabled && me.security.passkeys > 0 && !me.security.passkey_review_required;
}
