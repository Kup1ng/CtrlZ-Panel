"use client";

import {ApiError, hasCode} from "@ctrlz/api-client/errors.ts";
import {isWebAuthnSupported} from "@ctrlz/api-client/webauthn.ts";
import {Alert, Button, Link, Skeleton, Tabs} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import {useSearchParams} from "next/navigation";
import {Fragment, useCallback, useEffect, useReducer, useRef, useState, useSyncExternalStore, type ReactNode} from "react";

import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {hasInvisiblePassword} from "../forms/invisible.ts";
import {PasswordField} from "../forms/PasswordField.tsx";
import {PhoneField} from "../forms/PhoneField.tsx";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {replaceUrlAfterRouterMount} from "../shell/routerHistory.ts";
import {useApiForm} from "../forms/useApiForm.ts";
import {useOnlineStatus} from "../forms/useOnlineStatus.ts";
import {LoadingBlock} from "../forms/LoadingBlock.tsx";
import {AuthCard} from "./AuthCard.tsx";
import {authApi, type LoginResult} from "./authApi.ts";
import {useAuthHref} from "./authHref.ts";
import {initialLoginState, loginReducer, resultOutcome, stepFromParam, type LoginStep} from "./loginMachine.ts";
import {handleLoginError, OtpCodeStep, PasskeyStep, TwoFactorStep, type LoginDispatch, type LoginStepProps} from "./LoginSteps.tsx";
import {RememberMe} from "./RememberMe.tsx";
import {useAuthConfig, type AuthConfig} from "./useAuthConfig.ts";
import {useCompleteSignIn} from "./useCompleteSignIn.ts";

// Spec 10.2: one route, a state machine in component state (loginMachine.ts), mirrored to `?step=`. The
// tickets stay in memory. A reload at a later step finds no ticket, and the mirror below puts the URL back
// on the first step.

function useMirroredStep(step: LoginStep) {
  useEffect(() => {
    // Through the router's replaceState, once it is installed (gate-r21-9): on the first load this effect runs before
    // the router's, and a write made now would reach the native method, drop the entry's router marker and leave the
    // router with the old address. The address is read when the write happens, not now.
    return replaceUrlAfterRouterMount(() => {
      const url = new URL(window.location.href);
      if (step === "password") url.searchParams.delete("step");
      else url.searchParams.set("step", step);
      const next = `${url.pathname}${url.search}${url.hash}`;
      // Next.js folds a replaceState into useSearchParams, so `next` is still read by the same hook.
      return next !== `${window.location.pathname}${window.location.search}${window.location.hash}` ? next : null;
    });
  }, [step]);
}

const noopSubscribe = () => () => undefined;
/** `PublicKeyCredential` exists only in the browser, so the server render and the first client render say no. */
function useWebAuthnSupport(): boolean {
  return useSyncExternalStore(noopSubscribe, isWebAuthnSupported, () => false);
}

export function LoginFlow() {
  const params = useSearchParams();
  const config = useAuthConfig();
  const [state, dispatch] = useReducer(loginReducer, params.get("step"), (param) => initialLoginState(stepFromParam(param, true)));
  // A sign-in that moved on and came back to this very route (no session cookie was kept) leaves every form
  // pending, since nothing unmounts the page. After the bound of useCompleteSignIn the forms are made again, which
  // clears their pending state, and the first step says it did not hold (wp8-r11-2).
  const [epoch, setEpoch] = useState(0);
  const finish = useCompleteSignIn({
    onStall: () => {
      dispatch({type: "back", to: "password", notice: new ApiError(401, "session_expired")});
      setEpoch((value) => value + 1);
    },
  });

  // The SMS steps exist only while the API says SMS works. While the answer is awaited, or if it never
  // comes, the visitor sees the password form: the safest subset (10.1).
  const smsUsable = config.status === "ready" && config.smsAvailable;
  // A URL that asked for the SMS form waits for the answer before it picks a form. Showing the password form
  // meanwhile would let the visitor type into it, and the answer would swap it for the SMS form under their
  // hands (wp8-r8-1). The step stays `otp-phone` while the answer is awaited, so the mirror keeps `?step=`.
  // With no connection the request is paused and the answer may never come, so the skeleton would hold the page
  // for as long as the browser is offline: the visitor is moved to the password form instead, with the offline
  // line, and the tab list shows the SMS tab once the answer arrives (wp8-r17-3).
  const online = useOnlineStatus();
  const awaitingConfig = config.status === "loading" && state.step === "otp-phone" && online;
  // Every state in which the password form is shown for a state that asked for the SMS form: the answer has not come
  // (offline), failed, or says SMS is down. The state is moved to the password tab too, not only the derived step, so
  // a later answer that says SMS works adds the SMS tab beside the form and does not swap the form under what was
  // typed (wp8-r17-3, wp8-r20-2). Not while the suspended notice shows: the tab event would end it.
  const fallsBack = !awaitingConfig && !smsUsable && state.step === "otp-phone" && !state.suspended;
  useEffect(() => {
    if (fallsBack) dispatch({type: "tab", step: "password"});
  }, [fallsBack]);
  // Only the number step falls back. Once a code was sent, a later answer that says SMS is down leaves the step
  // alone (the code is still valid); its Resend is what goes off (wp8-r14-1).
  const step: LoginStep = !awaitingConfig && !smsUsable && state.step === "otp-phone" ? "password" : state.step;
  useMirroredStep(step);

  const applyResult = useCallback(
    (result: LoginResult): boolean => {
      const outcome = resultOutcome(result);
      switch (outcome.kind) {
        case "authenticated":
          return finish();
        case "mfa":
          dispatch({
            type: "mfa",
            ticket: outcome.ticket,
            // AUTH 5.7: the ticket lives five minutes when the server does not say.
            endsAt: Date.now() + (outcome.expiresInS ?? 300) * 1000,
            methods: outcome.methods,
          });
          return true;
        case "passkey":
          dispatch({type: "passkey"});
          return true;
        default:
          // A 200 that is none of the three statuses: the page cannot continue, and says so.
          throw new ApiError(502, "unknown");
      }
    },
    [finish],
  );

  const props: LoginStepProps = {
    state,
    dispatch,
    applyResult,
    onError: (error, at, form, extras) => handleLoginError(dispatch, error, at, form, extras),
  };

  // A suspended tenant's correct credentials end here, with the reason (wp8-r2-1).
  let view: ReactNode;
  if (state.suspended) view = <SuspendedNotice onBack={() => dispatch({type: "back", to: "password"})} />;
  else if (awaitingConfig) view = <ConfigSkeleton />;
  else if (step === "otp-code") view = <OtpCodeStep {...props} smsAvailable={config.smsAvailable} />;
  else if (step === "2fa") view = <TwoFactorStep {...props} />;
  else if (step === "passkey") view = <PasskeyStep {...props} smsUsable={smsUsable} />;
  else view = <SignInStep {...props} step={step} config={config} />;

  return <Fragment key={epoch}>{view}</Fragment>;
}

/**
 * `account_suspended` on a sign-in route. The explanation of /suspended (10.8), without its Log out: the
 * refusal created no session, so there is nothing to end, and /suspended would ask /me, be told the session
 * is gone, and send the visitor back to a blank sign-in form.
 */
function SuspendedNotice({onBack}: {onBack: () => void}) {
  const t = useTranslations("auth");
  return (
    <AuthCard title={t("suspended.title")} description={t("suspended.text")} focusHeading>
      <Button variant="secondary" fullWidth onPress={onBack}>
        {t("suspended.back")}
      </Button>
    </AuthCard>
  );
}

/** The sign-in card with no form yet: the visitor's URL asked for a form that /auth/config has not confirmed. */
function ConfigSkeleton() {
  const t = useTranslations("auth");
  return (
    <AuthCard title={t("login.title")} description={t("login.subtitle")}>
      <LoadingBlock rows={3} />
    </AuthCard>
  );
}

function SignInStep({state, dispatch, applyResult, onError, step, config}: LoginStepProps & {step: LoginStep; config: AuthConfig}) {
  const t = useTranslations("auth");
  const href = useAuthHref();
  const supportsPasskey = useWebAuthnSupport();
  const smsUsable = config.status === "ready" && config.smsAvailable;
  const showPasskey = config.status === "ready" && config.passkeyEnabled && supportsPasskey && !state.passkeyGone;
  const mode = config.registrationMode;
  // A call of the form that is shown is still running: the visitor stays on that form until it answers, or its
  // answer would act on a step they are no longer looking at (wp8-r6-1).
  const [busy, setBusy] = useState(false);
  const here = step === "otp-phone" ? "otp-phone" : "password";
  const disabledTabs = [...(smsUsable ? [] : ["otp-phone"]), ...(busy ? [here === "password" ? "otp-phone" : "password"] : [])];

  return (
    <AuthCard title={t("login.title")} description={t("login.subtitle")}>
      {config.status === "ready" && !config.smsAvailable ? (
        <Alert status="warning">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("login.smsDown")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}

      {/* What the step we came back to still has to say: an expired code, a ticket that ended. */}
      {/* Always in the page, so the live region is there before the notice is put in it (FormError). */}
      <FormError error={state.notice} />

      {/*
        One Tabs for every state of /auth/config, so the password form stays at one place in the tree. A form
        that moved into a Tabs when the answer says SMS works would remount, and a password typed during a slow
        load would be gone, with the focus (wp8-r2-3). While the answer is awaited, or if SMS is down, the list
        is in the page but hidden (display none), so the panel still names a tab that exists: a tab panel
        whose `aria-labelledby` points at nothing fails axe. The SMS tab is disabled meanwhile.
      */}
      <Tabs
        selectedKey={here}
        disabledKeys={disabledTabs}
        onSelectionChange={(key) => dispatch({type: "tab", step: key === "otp-phone" ? "otp-phone" : "password"})}
      >
        <Tabs.ListContainer className={smsUsable ? undefined : "hidden"}>
          <Tabs.List aria-label={t("login.methodsLabel")}>
            <Tabs.Tab id="password">
              {t("login.tabPassword")}
              <Tabs.Indicator />
            </Tabs.Tab>
            <Tabs.Tab id="otp-phone">
              {t("login.tabOtp")}
              <Tabs.Indicator />
            </Tabs.Tab>
          </Tabs.List>
        </Tabs.ListContainer>
        {config.status === "loading" ? <Skeleton aria-hidden className="h-10 w-full rounded-(--radius-box)" /> : null}
        <Tabs.Panel id="password" className={smsUsable ? "px-0 pt-4 pb-0" : "p-0"}>
          <PasswordForm {...{state, dispatch, applyResult, onError, onBusy: setBusy}} />
        </Tabs.Panel>
        {smsUsable ? (
          <Tabs.Panel id="otp-phone" className="px-0 pt-4 pb-0">
            <OtpPhoneForm {...{state, dispatch, applyResult, onError, onBusy: setBusy}} />
          </Tabs.Panel>
        ) : null}
      </Tabs>

      {showPasskey ? (
        <Button variant="secondary" fullWidth isDisabled={busy} onPress={() => dispatch({type: "passkey"})}>
          {t("login.passkey")}
        </Button>
      ) : null}

      <div className="flex flex-col items-center gap-2 text-sm">
        {/* Forgot Password needs a text message, so without one the link is hidden (10.6). */}
        {/* Off while a call runs, like the tabs: a visitor who left by a link would be pulled back by the answer (wp8-r7-3). */}
        {smsUsable ? (
          <Link href={href("/forgot-password")} isDisabled={busy}>
            {t("login.forgot")}
          </Link>
        ) : null}
        {mode === "open" ? (
          <Link href={href("/register")} isDisabled={busy}>
            {t("login.register")}
          </Link>
        ) : null}
        {mode === "invite" ? (
          <Link href={href("/invite")} isDisabled={busy}>
            {t("login.invite")}
          </Link>
        ) : null}
      </div>
    </AuthCard>
  );
}

type FormProps = Pick<LoginStepProps, "state" | "dispatch" | "applyResult" | "onError"> & {
  /** Told when a call starts and ends, so the page can keep the visitor on this form while it runs (wp8-r6-1). */
  onBusy: (busy: boolean) => void;
};

/** Passes `pending` up. The cleanup lets go if the form is removed while a call still runs. */
function useReportBusy(pending: boolean, onBusy: (busy: boolean) => void) {
  useEffect(() => {
    onBusy(pending);
    return () => onBusy(false);
  }, [pending, onBusy]);
}

function PasswordForm({state, dispatch, applyResult, onError, onBusy}: FormProps) {
  const t = useTranslations("auth");
  // After a step that has been left (an expired ticket, "back to sign in") the focus goes to the field the
  // visitor has to fill: the password, unless the number is still missing.
  const form = useApiForm({focus: state.returned ? (state.phone.trim() ? "password" : "phone") : undefined});
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  useReportBusy(pending, onBusy);
  const refocusPassword = useRef(false);

  // The field is disabled while the call runs, so the focus goes back to it once it is enabled again.
  useEffect(() => {
    if (pending || !refocusPassword.current) return;
    refocusPassword.current = false;
    form.focusField("password");
  }, [pending, form]);

  async function submit() {
    if (pending || form.blocked) return;
    if (!state.phone.trim()) return form.setFieldError("phone", t("fields.phone.required"));
    if (!password) return form.setFieldError("password", t("fields.password.required"));
    if (hasInvisiblePassword(password)) return form.setFieldError("password", t("fields.password.invisible"));
    setPending(true);
    form.clear();
    dispatch({type: "clearNotice"});
    // A success leaves the form pending: the page it asked for is still loading, and a form that went back
    // to idle would take a second press, and send a second sign-in (wp8-r5-1).
    let leaving = false;
    try {
      leaving = applyResult(await authApi.loginPassword({phone: state.phone, password, remember_me: state.remember}));
    } catch (error) {
      // `invalid_credentials` clears the password and puts the focus on it (10.2); the message is one
      // neutral line that says nothing about which of the two was wrong.
      onError(error, "password", form, {
        onInvalidCredentials: () => {
          setPassword("");
          refocusPassword.current = true;
        },
      });
    } finally {
      if (!leaving) setPending(false);
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <PhoneField
        autoComplete="username"
        value={state.phone}
        {...form.bind("phone", (value: string) => dispatch({type: "phone", value}))}
        isDisabled={pending}
      />
      <PasswordField
        autoComplete="current-password"
        value={password}
        {...form.bind("password", (value: string) => {
          setPassword(value);
          dispatch({type: "clearNotice"});
        })}
        isDisabled={pending}
      />
      <RememberMe isSelected={state.remember} onChange={(value) => dispatch({type: "remember", value})} isDisabled={pending} />
      <FormError error={form.formError} onRetry={() => void submit()} />
      <OfflineNotice />
      <SubmitButton isPending={pending} retryIn={form.retryIn}>
        {t("login.submit")}
      </SubmitButton>
    </AuthForm>
  );
}

function OtpPhoneForm({state, dispatch, onError, onBusy}: FormProps) {
  const t = useTranslations("auth");
  const locale = useLocale() as "fa" | "en";
  const form = useApiForm({focus: state.returned ? "phone" : undefined});
  const [pending, setPending] = useState(false);
  useReportBusy(pending, onBusy);

  async function submit() {
    if (pending || form.blocked) return;
    if (!state.phone.trim()) return form.setFieldError("phone", t("fields.phone.required"));
    setPending(true);
    form.clear();
    dispatch({type: "clearNotice"});
    try {
      // Always advances for a well-formed number, known or not (AUTH 5.3).
      const issued = await authApi.requestOtp({purpose: "login", phone: state.phone, locale});
      dispatch({type: "otpSent", id: issued.challenge_id, readyAt: Date.now() + issued.resend_after_s * 1000});
    } catch (error) {
      // `invalid_phone` belongs under the number; `otp_limited` and `sms_unavailable` are the form's.
      if (hasCode(error, "invalid_phone")) form.fail(error, {field: "phone"});
      else onError(error, "otp-phone", form);
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <PhoneField
        value={state.phone}
        {...form.bind("phone", (value: string) => dispatch({type: "phone", value}))}
        isDisabled={pending}
        description={t("login.otpPhone.description")}
      />
      <RememberMe isSelected={state.remember} onChange={(value) => dispatch({type: "remember", value})} isDisabled={pending} />
      <FormError error={form.formError} onRetry={() => void submit()} />
      <OfflineNotice />
      <SubmitButton isPending={pending} retryIn={form.retryIn}>
        {t("login.otpPhone.submit")}
      </SubmitButton>
    </AuthForm>
  );
}

export type {LoginDispatch};
