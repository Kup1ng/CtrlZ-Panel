"use client";

import {adminAuthApi, dropAdminMe} from "@ctrlz/api-client/admin/hooks/auth.ts";
import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {ENDED_PARAM} from "@ctrlz/api-client/session.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {Alert, FieldError, Input, Label, TextField} from "@heroui/react";
import {AuthCard} from "../../auth/AuthCard.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {hasInvisible, hasInvisiblePassword} from "../../forms/invisible.ts";
import {OTP_LENGTH, OtpField} from "../../forms/OtpField.tsx";
import {PasswordField} from "../../forms/PasswordField.tsx";
import {SubmitButton} from "../../forms/SubmitButton.tsx";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {ADMIN_PROTECTED_PREFIXES} from "../../proxy/prefixes.ts";
import {sanitizeNext} from "../../proxy/safeNext.ts";
import {isPageLeaving} from "../../shell/pageLeaving.ts";
import {useQueryClient} from "@tanstack/react-query";
import {useLocale, useTranslations} from "next-intl";
import {useSearchParams} from "next/navigation";
import {useCallback, useEffect, useRef, useState} from "react";
import {keepFocus} from "../shared/restoreFocus.ts";

// Spec 11.1. One form, one request (AUTH 10.2): username, password and the TOTP code. The code field is always shown,
// with a hint that it stays empty on the very first sign-in: hiding it would need a lookup the API deliberately does
// not offer. No Remember me, no passkey, no recovery code (an admin has none: `ctrlz-admin reset-totp` is the way).
//
// Every failure of the credentials is the one neutral message, whichever of the three was wrong, and the password and
// the code are cleared: the message must not say which was right. A 429 or a locked account shows a countdown on the
// button (`useApiForm`). `ended=1` is the marker of a session that ended on its own (idle, revoked), written by
// `leaveEndedAdminSession`.

// How long a sign-in that moved on may leave this page mounted before it asks whether the session holds (as the panel's
// login does, wp8-r11-2). A page that stays after a success is one the proxy sent back to /login: the cookie was not kept.
const STALL_MS = 12_000;

export function AdminLoginFlow() {
  const t = useTranslations("admin");
  const a = useTranslations("auth");
  const router = useRouter();
  const locale = useLocale();
  const queryClient = useQueryClient();
  const params = useSearchParams();
  const ended = params.get(ENDED_PARAM) === "1";
  const rawNext = params.get("next");

  const form = useAdminForm({focus: "username"});
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [stalled, setStalled] = useState(false);
  const busy = useRef(false);
  const here = useRef(false);
  const stall = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Set in the effect, not at the first render, so a development remount is still "here".
  useEffect(() => {
    here.current = true;
    return () => {
      here.current = false;
      if (stall.current !== null) clearTimeout(stall.current);
      stall.current = null;
    };
  }, []);

  const moveOn = useCallback(
    (target: string) => {
      dropAdminMe(queryClient);
      router.replace(target);
      if (stall.current !== null) clearTimeout(stall.current);
      stall.current = setTimeout(() => {
        stall.current = null;
        if (!here.current) return;
        void adminAuthApi.sessionHolds().then((state) => {
          if (!here.current || isPageLeaving()) return;
          if (state === "dead") {
            // The browser did not keep the cookie: the form comes back, and says so.
            busy.current = false;
            setPending(false);
            setStalled(true);
            setPassword("");
            setCode("");
          } else {
            window.location.assign(`/${locale}${target}`);
          }
        });
      }, STALL_MS);
    },
    [queryClient, router, locale],
  );

  async function submit(codeOverride?: string) {
    if (busy.current || form.blocked) return;
    // What the slots show may be Persian digits; what is sent is ASCII, however the form was submitted (wp10-r3-4).
    const totp = toAsciiDigits(codeOverride ?? code);
    const name = username.trim();
    if (!name) return form.setFieldError("username", t("login.usernameRequired"));
    if (!password) return form.setFieldError("password", a("fields.password.required"));
    if (hasInvisible(name)) return form.setFieldError("username", t("login.usernameInvisible"));
    if (hasInvisiblePassword(password)) return form.setFieldError("password", a("fields.password.invisible"));
    // Empty is the first sign-in. A half-typed code is a typo, and is not sent.
    if (totp !== "" && totp.length !== OTP_LENGTH) return form.setFieldError("totp_code", a("fields.totp.required"));

    busy.current = true;
    setPending(true);
    setStalled(false);
    form.clear();
    let moved = false;
    try {
      const result = await adminAuthApi.login({username: name, password, ...(totp ? {totp_code: totp} : {})});
      // A page that has been left must not pull the admin off the page they chose, and the session it opened is ended.
      if (!here.current || isPageLeaving()) {
        void adminAuthApi.dropSession();
        return;
      }
      moved = true;
      moveOn(result.state === "setup_required" ? "/setup" : (sanitizeNext(rawNext, ADMIN_PROTECTED_PREFIXES) ?? "/users"));
    } catch (error) {
      // Only a credential refusal empties the fields: one neutral message does not say which was wrong, so none is
      // kept. A 503, a 429 or a dropped connection says nothing about what was typed, and Retry must resend it (wp10-r5-1).
      if (hasCode(error, "invalid_credentials")) {
        setPassword("");
        setCode("");
      }
      if (hasCode(error, "totp_step_reused")) {
        setCode("");
        form.fail(error, {field: "totp_code"});
      } else form.fail(error);
    } finally {
      // A success stays pending until the page changes.
      if (!moved) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  return (
    <AuthCard title={t("login.title")} description={t("login.subtitle")}>
      {ended ? (
        <Alert status="warning" data-testid="session-ended">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("login.ended")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      {stalled ? (
        <Alert status="warning" data-testid="login-stalled">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("login.stalled")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      <AuthForm form={form} onSubmit={() => void submit()}>
        <TextField
          name="username"
          variant="secondary"
          fullWidth
          autoComplete="username"
          isDisabled={pending}
          isInvalid={form.fieldMessage("username") !== undefined}
          value={username}
          onChange={form.bind("username", setUsername).onChange}
        >
          <Label>{t("login.username")}</Label>
          <Input dir="ltr" className="text-start" spellCheck={false} autoCapitalize="none" autoCorrect="off" />
          <FieldError>{form.fieldMessage("username")}</FieldError>
        </TextField>
        <PasswordField
          name="password"
          autoComplete="current-password"
          value={password}
          {...form.bind("password", setPassword)}
          isDisabled={pending}
        />
        <OtpField
          name="totp_code"
          label={a("fields.totp.label")}
          description={t("login.totpHint")}
          value={code}
          onChange={form.bind("totp_code", setCode).onChange}
          onComplete={(full) => (username.trim() && password ? void submit(full) : undefined)}
          isDisabled={pending}
          errorMessage={form.fieldMessage("totp_code")}
        />
        <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn}>
          {t("login.submit")}
        </SubmitButton>
      </AuthForm>
    </AuthCard>
  );
}
