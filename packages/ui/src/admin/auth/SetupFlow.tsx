"use client";

import {adminAuthApi, refreshAdminMe, type AdminTotpSetup} from "@ctrlz/api-client/admin/hooks/auth.ts";
import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";
import {useAdminSession} from "@ctrlz/api-client/admin/session.ts";
import {ONE_TIME_SECRET_ATTRIBUTE} from "@ctrlz/api-client/clipboard.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link, useRouter} from "@ctrlz/i18n/navigation.ts";
import {Alert, Button, buttonVariants, Skeleton} from "@heroui/react";
import {Stepper} from "@heroui-pro/react";
import {PasswordMeter} from "../../auth/PasswordMeter.tsx";
import {ADMIN_RULE} from "../../auth/passwordStrength.ts";
import {AuthCard} from "../../auth/AuthCard.tsx";
import {TotpQr} from "../../auth/TotpQr.tsx";
import {groupSecret} from "../../account/recoveryCodes.ts";
import {Tech} from "../../data/Tech.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {handleApiError, useApiErrorActions} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {EditorActions} from "../../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {hasInvisiblePassword} from "../../forms/invisible.ts";
import {LoadingBlock} from "../../forms/LoadingBlock.tsx";
import {OTP_LENGTH, OtpField} from "../../forms/OtpField.tsx";
import {useAuthBusy, useReportAuthBusy, useReportAuthHolding} from "../../forms/useAuthBusy.ts";
import {PasswordField} from "../../forms/PasswordField.tsx";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {LogoutDialog} from "../../shell/LogoutDialog.tsx";
import {SessionBinding} from "../../shell/SessionBinding.tsx";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useCallback, useEffect, useRef, useState, useSyncExternalStore} from "react";

import {CopyButton} from "../shared/CopyButton.tsx";
import {keepFocus, keepRetry} from "../shared/restoreFocus.ts";

// Spec 11.2, T-323. The forced setup of a first admin, outside the shell: a one-time password has to become a real one,
// and an authenticator has to be enrolled, before any admin page works. The shell's gate sends a session in setup here
// (`AdminGate`), and any 403 `setup_required` does the same (handleApiError). The page mounts the session binding
// itself, since it is not inside `SessionGate`.
//
// The steps shown are the ones the account needs at the moment it is first read: password when `must_change_password`,
// authenticator when `!totp_enrolled`, then Done. They are fixed at that moment and do not shift as `/me` is refetched
// after each step. Done is local state: by then `/me` says the account is ready, and the page must not leave for
// /users before the admin has seen the last step.
//
// The one-time password lasts 24 hours (AUTH 10.1), and an admin has no recovery codes: `ctrlz-admin reset-password`
// and `ctrlz-admin reset-totp` are the ways back, and both are named on the screens where the loss would be felt.

/** `/me` is asked again inside a catch block, where a rejection would reach no one: the next render of the guard decides anyway. */
async function refreshQuietly(queryClient: ReturnType<typeof useQueryClient>) {
  try {
    await refreshAdminMe(queryClient);
  } catch {
    // Nothing to show: this runs when the account is already past this step.
  }
}

type StepId = "password" | "totp" | "done";

const wide = "(min-width: 48rem)";
const subscribeWide = (cb: () => void) => {
  const query = window.matchMedia(wide);
  query.addEventListener("change", cb);
  return () => query.removeEventListener("change", cb);
};

/** Horizontal from `md`, vertical below it (spec 11.2). The server snapshot is the narrow one, which every width can lay out. */
function useWide(): boolean {
  return useSyncExternalStore(subscribeWide, () => window.matchMedia(wide).matches, () => false);
}

// The library draws the step number in Latin digits; the Persian page wants its own (spec 4.4).
function StepNumber() {
  const {index, status} = Stepper.useStep();
  const f = useAppFormat();
  return <Stepper.Indicator>{status === "complete" ? undefined : f.number(index + 1)}</Stepper.Indicator>;
}

export function SetupFlow() {
  const t = useTranslations("admin");
  const {status, me, error, retry} = useAdminSession();
  return (
    <>
      <SessionBinding />
      {status === "error" ? (
        <SectionError error={error} onRetry={keepRetry(retry)} />
      ) : (status === "setup" || status === "ready") && me ? (
        <Steps initial={{password: me.must_change_password, totp: !me.totp_enrolled}} ready={status === "ready"} />
      ) : (
        <AuthCard title={t("setup.title")}>
          <LoadingBlock />
        </AuthCard>
      )}
    </>
  );
}

function Steps({initial, ready}: {initial: {password: boolean; totp: boolean}; ready: boolean}) {
  const t = useTranslations("admin");
  const router = useRouter();
  const wideNow = useWide();
  const [steps] = useState<StepId[]>(() => [...(initial.password ? (["password"] as const) : []), ...(initial.totp ? (["totp"] as const) : []), "done"]);
  const [index, setIndex] = useState(0);
  // Log out asks first (T-109); the shell's dialog ends the session and says why when it cannot.
  const [logoutOpen, setLogoutOpen] = useState(false);
  const step = steps[index] ?? "done";
  // Both calls of the steps rotate the admin session's token. A logout sent with the old token after the rotation commits answers 401,
  // which an admin page reads as "already gone" while the browser holds the new, full session (pg2-1-4). So Log out waits for them.
  const callRunning = useAuthBusy();

  // An admin who needs nothing here (the page was typed in by hand, or another tab finished the setup) goes on. The steps
  // are fixed when the page is first drawn, so a setup that ends here is never mistaken for one that was never needed:
  // it has more than the Done step, and stays on it.
  const nothingNeeded = steps.length === 1;
  useEffect(() => {
    if (ready && nothingNeeded) router.replace("/users");
  }, [ready, nothingNeeded, router]);

  const next = useCallback(() => setIndex((i) => Math.min(i + 1, steps.length - 1)), [steps.length]);

  return (
    <AuthCard title={t(`setup.${step}.title`)} description={t(`setup.${step}.subtitle`)} focusHeading={step === "done"}>
      <Stepper currentStep={index} size="sm" orientation={wideNow ? "horizontal" : "vertical"} aria-label={t("setup.stepsLabel")}>
        {steps.map((id) => (
          <Stepper.Step key={id}>
            <StepNumber />
            <Stepper.Content>
              <Stepper.Title>{t(`setup.steps.${id}`)}</Stepper.Title>
            </Stepper.Content>
            <Stepper.Separator />
          </Stepper.Step>
        ))}
      </Stepper>
      {step === "password" ? <PasswordStep onDone={next} /> : null}
      {step === "totp" ? <TotpStep onDone={next} autoStart={steps[0] === "password"} /> : null}
      {step === "done" ? (
        <Link href="/users" className={buttonVariants({variant: "primary", fullWidth: true})}>
          {t("setup.done.go")}
        </Link>
      ) : null}
      <div className="flex flex-col items-center gap-2">
        <Button size="sm" variant="ghost" isDisabled={callRunning} onPress={() => setLogoutOpen(true)}>
          {t("setup.logout")}
        </Button>
      </div>
      <LogoutDialog isOpen={logoutOpen} onOpenChange={setLogoutOpen} />
    </AuthCard>
  );
}

function PasswordStep({onDone}: {onDone: () => void}) {
  const t = useTranslations("admin");
  const a = useTranslations("auth");
  const queryClient = useQueryClient();
  const form = useAdminForm({focus: "current_password"});
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  useReportAuthBusy(pending);

  async function submit() {
    if (busy.current || form.blocked) return;
    if (!current) return form.setFieldError("current_password", a("fields.password.required"));
    if (!next) return form.setFieldError("new_password", a("fields.password.newRequired"));
    if (hasInvisiblePassword(current)) return form.setFieldError("current_password", a("fields.password.invisible"));
    if (hasInvisiblePassword(next)) return form.setFieldError("new_password", a("fields.password.invisible"));
    busy.current = true;
    setPending(true);
    form.clear();
    let done = false;
    try {
      await adminAuthApi.changePassword({current_password: current, new_password: next});
      // The session was rotated: `/me` says what is left (the authenticator), and the next step starts on it.
      await refreshAdminMe(queryClient);
      done = true;
      setCurrent("");
      setNext("");
      onDone();
    } catch (error) {
      // `invalid_credentials` here means the one-time password is wrong (or has run out), and says nothing else.
      if (hasCode(error, "invalid_credentials")) {
        setCurrent("");
        form.fail(error, {field: "current_password", message: t("setup.password.currentWrong")});
      } else {
        form.fail(error);
      }
    } finally {
      if (!done) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <PasswordField
        name="current_password"
        label={t("setup.password.current")}
        autoComplete="current-password"
        value={current}
        {...form.bind("current_password", setCurrent)}
        isDisabled={pending}
        description={t("setup.password.currentHint")}
      />
      <div className="flex flex-col gap-2">
        <PasswordField
          name="new_password"
          label={a("fields.password.newLabel")}
          autoComplete="new-password"
          value={next}
          {...form.bind("new_password", setNext)}
          isDisabled={pending}
        />
        <PasswordMeter password={next} rule={ADMIN_RULE} shortText={t("password.short")} />
      </div>
      <p className="text-muted text-xs">
        {t.rich("setup.password.expiry", {command: "ctrlz-admin reset-password", cmd: (chunks) => <Tech>{chunks}</Tech>})}
      </p>
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <EditorActions submitLabel={t("setup.password.submit")} isPending={pending} retryIn={form.retryIn} />
    </AuthForm>
  );
}

// `autoStart`: the secret is made at once only for an admin who has just passed the password step on this page, which is a press of theirs.
// A page that is opened straight on this step (a reload, a link, the shell's move of a session in setup) makes nothing until a press: the
// call replaces the one pending secret, and a navigation that starts on another site must not be able to do that with the session's
// cookie, which the page's own calls carry (gate-r33-2).
function TotpStep({onDone, autoStart}: {onDone: () => void; autoStart: boolean}) {
  const t = useTranslations("admin");
  const a = useTranslations("auth");
  const queryClient = useQueryClient();
  const actions = useApiErrorActions();
  const form = useAdminForm({focus: "totp_code"});
  const [setup, setSetup] = useState<AdminTotpSetup | null>(null);
  const [setupError, setSetupError] = useState<unknown>(null);
  const [notice, setNotice] = useState(false);
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const busy = useRef(false);
  useReportAuthBusy(pending);
  // A shown secret is held by the server as the one pending secret: a language switch is a full load that would ask for another and
  // replace it, and the entry the admin already scanned would stop verifying. The corner menu keeps the other language off (gate-r31-6).
  // This step has no way back (password, authenticator, done), so the hint says "finish", not "go back" (gate-r32-5).
  useReportAuthHolding(setup !== null, "finish");
  const [asked, setAsked] = useState(autoStart);
  const started = useRef(false);

  // The secret is made once, when it is asked for: asking twice would replace the first one.
  const start = useCallback(async () => {
    setSetupError(null);
    try {
      setSetup(await adminAuthApi.totpSetup());
    } catch (failure) {
      // Another tab turned it on meanwhile: nothing is left to do here.
      if (hasCode(failure, "totp_already_enabled")) {
        await refreshQuietly(queryClient);
        onDone();
        return;
      }
      // This call is made outside the query caches, so the guard's listener never sees its 401: a session that has ended
      // must leave for /login?ended=1 here, as it does for the password and the code (wp10-r1-7).
      if (handleApiError(failure, actions)) return;
      setSetupError(failure);
    }
  }, [queryClient, onDone, actions]);

  useEffect(() => {
    if (!asked || started.current) return;
    started.current = true;
    void start();
  }, [asked, start]);

  async function submit(override?: string) {
    // A page opened on this step holds no secret of ours, but the server may still hold the one the admin scanned before a reload: the
    // confirm needs only the code, and a "no pending secret" answer falls through to a new key below (gate-r34-9). While a key is being
    // made (asked, not yet shown) there is nothing to confirm against.
    if (busy.current || form.blocked || (asked && !setup)) return;
    const value = toAsciiDigits(override ?? code);
    if (value.length !== OTP_LENGTH) return form.setFieldError("totp_code", a("fields.totp.required"));
    busy.current = true;
    setPending(true);
    form.clear();
    let done = false;
    try {
      await adminAuthApi.totpConfirm(value);
      await refreshAdminMe(queryClient);
      done = true;
      setSetup(null);
      onDone();
    } catch (error) {
      // Only a code that was refused (or a lockout, after which a new one is needed anyway, or a secret that is gone) is emptied: a 503, server_busy, an
      // unknown failure or a dropped connection keeps it, so Retry resends the same one (wp10-r9-2).
      if (hasCode(error, "totp_invalid", "totp_step_reused", "too_many_attempts", "totp_not_pending")) setCode("");
      if (hasCode(error, "totp_already_enabled")) {
        await refreshQuietly(queryClient);
        done = true;
        onDone();
      } else if (hasCode(error, "totp_not_pending")) {
        // The pending secret is gone (it ran out, or another tab replaced it): a new one is made and shown.
        setSetup(null);
        setNotice(true);
        started.current = true;
        setAsked(true);
        void start();
      } else if (hasCode(error, "totp_invalid", "totp_step_reused")) {
        form.fail(error, {field: "totp_code"});
      } else {
        form.fail(error);
      }
    } finally {
      if (!done) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      {notice ? (
        <Alert status="warning" data-testid="totp-restarted">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("setup.totp.restarted")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      <p className="text-muted text-sm">{t("setup.totp.scan")}</p>
      {setup ? (
        <>
          {/* A QR code needs a light ground and dark modules in both themes, or a phone cannot read it. */}
          <div className="flex justify-center">
            <div className="rounded-(--radius-box) bg-white p-3" data-testid="totp-qr">
              <TotpQr uri={setup.otpauth_uri} title={t("setup.totp.qrTitle")} />
            </div>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-muted text-xs">{t("setup.totp.secretLabel")}</span>
            <div className="flex items-center justify-between gap-2">
              <span data-testid="totp-secret" {...{[ONE_TIME_SECRET_ATTRIBUTE]: ""}} className="text-sm tracking-wider select-all">
                <Tech>{groupSecret(setup.secret)}</Tech>
              </span>
              <CopyButton text={setup.secret} label={t("setup.totp.copySecret")} />
            </div>
            <p className="text-muted text-xs" data-testid="copy-note">
              {t("copyNote")}
            </p>
          </div>
        </>
      ) : setupError ? null : !asked ? (
        <div className="flex flex-col items-center gap-2">
          {/* Not while the confirm of a key scanned before a reload is running: the new key would replace the pending one under that call (gate-r35-8). */}
          <Button variant="secondary" data-testid="totp-show" isDisabled={pending} onPress={() => !busy.current && setAsked(true)}>
            {t("setup.totp.show")}
          </Button>
          <p className="text-muted text-center text-xs" data-testid="totp-show-note">
            {t("setup.totp.showNote")}
          </p>
        </div>
      ) : (
        <div role="status" aria-busy="true">
          <span className="sr-only">{a("form.waiting")}</span>
          <Skeleton aria-hidden className="mx-auto h-48 w-48 rounded-(--radius-box)" />
        </div>
      )}
      <FormError error={setupError} onRetry={() => keepFocus(() => start())} />
      <OtpField
        name="totp_code"
        label={a("fields.totp.label")}
        description={t("setup.totp.verify")}
        value={code}
        onChange={form.bind("totp_code", setCode).onChange}
        onComplete={(full) => void submit(full)}
        isDisabled={pending || (asked && !setup)}
        errorMessage={form.fieldMessage("totp_code")}
      />
      <p className="text-muted text-xs">{t.rich("setup.totp.noRecovery", {command: "ctrlz-admin reset-totp", cmd: (chunks) => <Tech>{chunks}</Tech>})}</p>
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <EditorActions submitLabel={t("setup.totp.submit")} isPending={pending} retryIn={form.retryIn} isDisabled={asked && !setup} />
    </AuthForm>
  );
}
