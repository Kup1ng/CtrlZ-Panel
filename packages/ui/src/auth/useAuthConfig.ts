"use client";

import {usePublicConfig} from "@ctrlz/api-client/hooks/config.ts";

// `GET /auth/config` on every auth page (spec 10.1). While it loads and when it fails the page shows
// the safest subset: the password form, with no SMS tab, no register or invite link and no passkey
// button. A failure is not shown as an error: the visitor can still sign in, which is all they came for,
// and the pages that cannot work without the answer (register, forgot password) say so themselves.

export type AuthConfig = {
  /** `loading` until the first answer; `failed` after the client's retries gave up. */
  status: "loading" | "ready" | "failed";
  registrationMode: "closed" | "invite" | "open" | null;
  smsAvailable: boolean;
  passkeyEnabled: boolean;
  retry: () => void;
};

export function useAuthConfig(): AuthConfig {
  const {data, isPending, refetch} = usePublicConfig();
  return {
    status: data ? "ready" : isPending ? "loading" : "failed",
    registrationMode: data?.registration_mode ?? null,
    smsAvailable: data?.sms_available ?? false,
    passkeyEnabled: data?.passkey_enabled ?? false,
    retry: () => void refetch(),
  };
}
