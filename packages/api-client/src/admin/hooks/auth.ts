import type {QueryClient} from "@tanstack/react-query";

import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {adminApi} from "../client.ts";
import {adminMeKeys} from "../session.ts";

// Spec 11.1 and 11.2. The calls of the two admin auth screens. They are plain functions, not mutations: a login or a
// setup step holds a password or a one-time secret, and a mutation keeps its variables in memory for as long as the
// screen is mounted (queryDefaults.ts). The screens call these and keep nothing but what they must show.

type S = components["schemas"];
export type AdminLoginRequest = S["AdminLoginRequest"];
export type AdminLoginResult = S["AdminLoginResult"];
export type AdminPasswordRequest = S["AdminPasswordRequest"];
export type AdminTotpSetup = S["AdminTotpSetup"];

export const adminAuthApi = {
  /** `POST /auth/login`. One request: username, password and, once enrolled, the TOTP code (AUTH 10.2). */
  async login(body: AdminLoginRequest): Promise<AdminLoginResult> {
    return required(await adminApi.POST("/auth/login", {body}));
  },
  /** `POST /me/password`. Rotates this session and ends the others, so the cookie changes under the page. */
  async changePassword(body: AdminPasswordRequest): Promise<void> {
    await adminApi.POST("/me/password", {body});
  },
  /** `POST /me/totp/setup`: a secret that is not enabled yet. Shown once, so it is held in component state only. */
  async totpSetup(): Promise<AdminTotpSetup> {
    return required(await adminApi.POST("/me/totp/setup", {body: {}}));
  },
  /** `POST /me/totp/confirm`: turns TOTP on, sets a new session cookie and ends the other sessions. */
  async totpConfirm(code: string): Promise<void> {
    await adminApi.POST("/me/totp/confirm", {body: {code}});
  },
  /** `POST /me/notices/ack`. Always 204. */
  async ackNotices(): Promise<void> {
    await adminApi.POST("/me/notices/ack");
  },
  /** A sign-in that landed on a page the admin had already left ends its own session: nothing shows it, so nothing may keep it. */
  async dropSession(): Promise<void> {
    try {
      await adminApi.POST("/auth/logout", {keepalive: true});
    } catch {
      // Nothing more can be done: the idle limit of the server ends it.
    }
  },
  /** `GET /me`, once, outside the cache: the stall probe of the login page asks whether a session holds. */
  async sessionHolds(): Promise<"live" | "dead" | "unknown"> {
    try {
      await adminApi.GET("/me");
      return "live";
    } catch (error) {
      return (error as {code?: string} | null)?.code === "session_expired" ? "dead" : "unknown";
    }
  },
};

/** `/me` is another visit's answer once the account changed (login): the shell asks again. */
export function dropAdminMe(queryClient: QueryClient): void {
  queryClient.removeQueries({queryKey: adminMeKeys.all});
}

/** After a setup step the account differs (`must_change_password`, `totp_enrolled`): refetch `/me` and let it decide. */
export function refreshAdminMe(queryClient: QueryClient) {
  return queryClient.invalidateQueries({queryKey: adminMeKeys.all});
}
