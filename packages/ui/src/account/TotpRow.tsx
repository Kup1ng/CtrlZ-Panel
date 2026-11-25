"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {copyOneTimeSecret, ONE_TIME_SECRET_ATTRIBUTE} from "@ctrlz/api-client/clipboard.ts";
import type {Me} from "@ctrlz/api-client/session.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert, Button, Checkbox, Chip, Skeleton, toast} from "@heroui/react";
import {Stepper} from "@heroui-pro/react";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {QRCodeSVG} from "qrcode.react";
import {useCallback, useEffect, useRef, useState} from "react";

import {useRecoverable} from "../auth/ReauthDialog.tsx";
import {ReauthPanel} from "../auth/ReauthPanel.tsx";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Tech} from "../data/Tech.tsx";
import {ConfirmFrame} from "../dialog/ConfirmFrame.tsx";
import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {useLeaveGuard} from "../dialog/useLeaveGuard.ts";
import {useWipeCopiedOnClose} from "../dialog/useWipeCopiedOnClose.ts";
import {AuthForm} from "../forms/AuthForm.tsx";
import {EditorActions} from "../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {InlineEditRow} from "../forms/InlineEditRow.tsx";
import {OTP_LENGTH, OtpField} from "../forms/OtpField.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {accountApi, answerMayBeLost, refreshAccount, type TotpSetup} from "./accountApi.ts";
import {useStepFocus} from "./useStepFocus.ts";
import {downloadTextFile, groupSecret, RECOVERY_FILE_NAME, recoveryCodesText, recoveryFileContent} from "./recoveryCodes.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec 12.3 (T-101): the authenticator app. Enable is a four step wizard in a state-only modal, so the
// secret and the recovery codes live in this component's state and nowhere else: not in the address bar,
// not in a query cache. Disable and "new recovery codes" take the password and a code first (AUTH 6.4),
// which is the reauth the table of 12.1 gives an account with an authenticator.
//
// The row warns when fewer than three recovery codes are left. Closing the last step asks for
// confirmation, since the codes are shown once and nothing can show them again.

type Flow = "enable" | "regenerate" | "disable" | null;

const LOW_CODES = 3;

export function TotpRow({me}: {me: Me}) {
  const t = useTranslations("account");
  const [flow, setFlow] = useState<Flow>(null);
  const on = me.security.totp_enabled;
  // Turn off replaces Regenerate and Turn off with Turn on, so the button that opened the flow is gone when the dialog
  // closes and the focus would fall to the page body. The flag is set when the call has succeeded; once /me shows the
  // row as off and the dialog has left, the focus goes to Turn on, one frame later than the dialog's own restore (wp9-r4-1).
  const disabled = useRef(false);
  const turnOn = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (on || flow !== null || !disabled.current) return;
    disabled.current = false;
    const frame = requestAnimationFrame(() => turnOn.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [on, flow]);
  const left = me.security.recovery_codes_left;
  const low = on && left < LOW_CODES;

  return (
    <>
      <InlineEditRow
        id="totp"
        label={t("totp.label")}
        value={
          <span className="flex flex-wrap items-center gap-2">
            <Chip size="sm" color={on ? "success" : "default"} variant="soft">
              {on ? t("totp.on") : t("totp.off")}
            </Chip>
            {on && !low ? <span className="text-muted text-xs font-normal">{t("totp.codesLeft", {count: left})}</span> : null}
          </span>
        }
        description={
          low ? <span className="text-(--warning-text)">{t("totp.lowCodes", {count: left})}</span> : on ? undefined : t("totp.offHint")
        }
        trailing={
          <>
            {on ? (
              <>
                <Button size="sm" variant="tertiary" onPress={() => setFlow("regenerate")}>
                  {t("totp.regenerate")}
                </Button>
                <Button size="sm" variant="danger-soft" onPress={() => setFlow("disable")}>
                  {t("totp.disable")}
                </Button>
              </>
            ) : (
              <Button ref={turnOn} size="sm" variant="tertiary" onPress={() => setFlow("enable")}>
                {t("totp.enable")}
              </Button>
            )}
          </>
        }
      />
      {flow === "enable" ? <EnableWizard me={me} onClose={() => setFlow(null)} /> : null}
      {flow === "regenerate" ? <RegenerateDialog me={me} onClose={() => setFlow(null)} /> : null}
      {flow === "disable" ? (
        <DisableFlow me={me} onDisabled={() => (disabled.current = true)} onClose={() => setFlow(null)} />
      ) : null}
    </>
  );
}

// ---- enable ---------------------------------------------------------------------------------------------

function EnableWizard({me, onClose}: {me: Me; onClose: () => void}) {
  useWipeCopiedOnClose();
  const t = useTranslations("account");
  const [step, setStep] = useState(0);
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [confirmClose, setConfirmClose] = useState(false);
  // The confirm call is in flight: its answer carries the recovery codes, shown once, so the dialog stays until it ends (wp9-r1-2).
  const [confirming, setConfirming] = useState(false);
  // Why the person is back at the scan step (the pending secret ran out): shown there.
  const [notice, setNotice] = useState<unknown>(null);
  // A step that replaces the one with the focus hands it to its heading, so Escape and Tab stay in the dialog (wp9-r3-1).
  const {panel, heading} = useStepFocus(step);

  // Once the recovery codes are on screen, nothing but this dialog holds them.
  const requestClose = () => (codes ? setConfirmClose(true) : onClose());
  // Back, a reload and a closed tab leave the page without the dialog's own close paths: while the confirm runs and
  // while the codes are on screen they ask first (wp9-r2-6). Back with the codes shown asks "close anyway?".
  useLeaveGuard(confirming || codes !== null, () => {
    if (codes) setConfirmClose(true);
  });

  return (
    <DialogFrame isOpen onClose={requestClose} isLocked={confirming} title={t("totp.enableTitle")}>
      <div ref={panel} className="flex flex-col gap-4">
        <Stepper currentStep={step} size="sm" aria-label={t("totp.stepsLabel")}>
          {[0, 1, 2, 3].map((index) => (
            <Stepper.Step key={index}>
              <StepNumber />
              <Stepper.Separator />
            </Stepper.Step>
          ))}
        </Stepper>
        <h3 ref={heading} tabIndex={-1} className="text-sm font-medium outline-none">
          {t(`totp.step${step as 0 | 1 | 2 | 3}`)}
        </h3>
        {step === 0 ? <ReauthPanel me={me} onDone={() => setStep(1)} onCancel={onClose} /> : null}
        {step === 1 ? (
          <ScanStep
            setup={setup}
            onSetup={setSetup}
            notice={notice}
            onCancel={onClose}
            onNext={() => {
              setNotice(null);
              setStep(2);
            }}
          />
        ) : null}
        {step === 2 && setup ? (
          <VerifyStep
            onCancel={onClose}
            onBusy={setConfirming}
            onEnabled={(result) => {
              setConfirming(false);
              setSetup(null);
              setCodes(result);
              setStep(3);
            }}
            onRestart={(why) => {
              setNotice(why);
              setSetup(null);
              setStep(1);
            }}
          />
        ) : null}
        {step === 3 && codes ? (
          <CodesView codes={codes} confirmClose={confirmClose} onKeep={() => setConfirmClose(false)} onClose={onClose} />
        ) : null}
      </div>
    </DialogFrame>
  );
}

// The library draws the step number with its own formatting, which is Latin in the Persian page (spec 4.4, wp9-r2-4).
// The check mark of a finished step stays the library's.
function StepNumber() {
  const {index, status} = Stepper.useStep();
  const f = useAppFormat();
  return <Stepper.Indicator>{status === "complete" ? undefined : f.number(index + 1)}</Stepper.Indicator>;
}

function ScanStep({
  setup,
  onSetup,
  notice,
  onNext,
  onCancel,
}: {
  setup: TotpSetup | null;
  onSetup: (setup: TotpSetup) => void;
  notice: unknown;
  onNext: () => void;
  onCancel: () => void;
}) {
  const t = useTranslations("account");
  const c = useTranslations("common");
  const queryClient = useQueryClient();
  const recover = useRecoverable();
  const [error, setError] = useState<unknown>(null);
  const started = useRef(false);

  const start = useCallback(async () => {
    setError(null);
    try {
      onSetup(await recover(() => accountApi.totpSetup()));
    } catch (failure) {
      // Another tab turned it on meanwhile: `/me` knows, and the row behind the dialog follows it.
      if (hasCode(failure, "totp_already_enabled")) void refreshAccount(queryClient);
      setError(failure);
    }
  }, [onSetup, recover, queryClient]);

  // The secret is made when the step is reached, once: asking twice would replace the first one.
  useEffect(() => {
    if (started.current || setup) return;
    started.current = true;
    void start();
  }, [setup, start]);

  async function copy(text: string) {
    try {
      await copyOneTimeSecret(text);
      toast.success(c("copied"));
    } catch {
      toast.danger(t("totp.copyFailed"));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {notice ? (
        <Alert status="warning" data-testid="totp-restarted">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("totp.restarted")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      <p className="text-muted text-sm">{t("totp.scanText")}</p>
      {setup ? (
        <>
          {/* A QR code needs a light ground and dark modules in both themes, or a phone cannot read it. */}
          <div className="flex justify-center">
            <div className="rounded-(--radius-box) bg-white p-3" data-testid="totp-qr">
              <QRCodeSVG value={setup.otpauth_uri} size={176} level="M" bgColor="#ffffff" fgColor="#000000" title={t("totp.qrTitle")} />
            </div>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-muted text-xs">{t("totp.secretLabel")}</span>
            <div className="flex items-center justify-between gap-2">
              <span data-testid="totp-secret" {...{[ONE_TIME_SECRET_ATTRIBUTE]: ""}} translate="no" className="text-sm tracking-wider select-all">
                <Tech>{groupSecret(setup.secret)}</Tech>
              </span>
              <Button size="sm" variant="tertiary" onPress={() => void copy(setup.secret)}>
                <Icon name="copy" className="size-4" />
                {c("copy")}
              </Button>
            </div>
            <p className="text-muted text-xs" data-testid="copy-note">
              {t("totp.copyNote")}
            </p>
          </div>
        </>
      ) : error ? null : (
        <div role="status" aria-busy="true">
          <span className="sr-only">{c("loading")}</span>
          <Skeleton aria-hidden className="mx-auto h-48 w-48 rounded-(--radius-box)" />
        </div>
      )}
      <FormError error={error} onRetry={() => void start()} />
      {hasCode(error, "totp_already_enabled") ? <p className="text-muted text-sm">{t("totp.alreadyOnHint")}</p> : null}
      <div className="flex justify-end gap-2">
        <Button variant="tertiary" onPress={onCancel}>
          {c("cancel")}
        </Button>
        <PrimaryButton isDisabled={!setup} onPress={onNext}>
          {c("next")}
        </PrimaryButton>
      </div>
    </div>
  );
}

function VerifyStep({
  onEnabled,
  onRestart,
  onCancel,
  onBusy,
}: {
  onEnabled: (codes: string[]) => void;
  onRestart: (why: unknown) => void;
  onCancel: () => void;
  /** Tells the dialog around this step that the confirm call runs, so it cannot be dismissed under it. */
  onBusy: (busy: boolean) => void;
}) {
  const t = useTranslations("account");
  const a = useTranslations("auth");
  const queryClient = useQueryClient();
  const recover = useRecoverable();
  const form = useApiForm({focus: "totp_code"});
  const [saved, setSaved] = useState(false);
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  // The answer did not come, so the server may have turned it on and made codes nobody saw (wp9-r2-7).
  const [lost, setLost] = useState(false);
  const busy = useRef(false);
  const done = useRef(false);

  async function submit(override?: string, tickedNow = false) {
    if (busy.current || form.blocked) return;
    const value = override ?? code;
    if (!saved && !tickedNow) return form.setFieldError("saved", t("totp.savedRequired"));
    if (value.length !== OTP_LENGTH) return form.setFieldError("code", a("fields.totp.required"));
    busy.current = true;
    setPending(true);
    onBusy(true);
    setLost(false);
    form.clear();
    try {
      // This route needs a live window too, and the one that began the wizard may have ended (AUTH 14.2).
      const result = await recover(() => accountApi.totpConfirm(value));
      done.current = true;
      if (result.ended_sessions > 0) toast.info(t("totp.ended", {count: result.ended_sessions}));
      void refreshAccount(queryClient);
      onEnabled(result.recovery_codes);
    } catch (error) {
      if (hasCode(error, "totp_not_pending")) {
        onRestart(error);
        return;
      }
      if (hasCode(error, "totp_invalid", "totp_step_reused")) {
        setCode("");
        form.fail(error, {field: "code"});
      } else {
        if (answerMayBeLost(error)) {
          void refreshAccount(queryClient);
          setLost(true);
        }
        form.fail(error);
      }
    } finally {
      if (!done.current) {
        busy.current = false;
        setPending(false);
        onBusy(false);
      }
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <Checkbox
        name="saved"
        isSelected={saved}
        onChange={(next) => {
          setSaved(next);
          form.clearField("saved");
          // The code was typed first and held back for the tick: ticking is the answer it waited for.
          if (next && code.length === OTP_LENGTH) void submit(code, true);
        }}
        isDisabled={pending}
        isInvalid={form.fieldMessage("saved") !== undefined}
      >
        <Checkbox.Content>
          <Checkbox.Control>
            <Checkbox.Indicator />
          </Checkbox.Control>
          {t("totp.saved")}
        </Checkbox.Content>
      </Checkbox>
      {form.fieldMessage("saved") ? (
        <p role="alert" className="text-sm text-(--danger-text)">
          {form.fieldMessage("saved")}
        </p>
      ) : null}
      <OtpField
        name="totp_code"
        label={a("fields.totp.label")}
        description={t("totp.verifyText")}
        value={code}
        onChange={form.bind("code", setCode).onChange}
        onComplete={(done6) => void submit(done6)}
        isDisabled={pending}
        errorMessage={form.fieldMessage("code")}
      />
      <FormError error={form.formError} onRetry={() => void submit()} />
      {lost && form.formError ? <LostAnswer text={t("totp.enableLost")} /> : null}
      <OfflineNotice />
      <EditorActions submitLabel={t("totp.confirm")} isPending={pending} retryIn={form.retryIn} onCancel={onCancel} />
    </AuthForm>
  );
}

/** What to say when a call that makes one-time codes got no answer: the codes may exist and nobody saw them. */
function LostAnswer({text}: {text: string}) {
  return (
    <Alert status="warning" data-testid="totp-lost">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Description>{text}</Alert.Description>
      </Alert.Content>
    </Alert>
  );
}

// ---- the codes (enable and regenerate) ------------------------------------------------------------------

function CodesView({
  codes,
  confirmClose,
  onKeep,
  onClose,
}: {
  codes: string[];
  confirmClose: boolean;
  onKeep: () => void;
  onClose: () => void;
}) {
  const t = useTranslations("account");
  const c = useTranslations("common");
  // The Copy of the codes lives here, so the wipe does too: a dialog built on CodesView cannot forget it (gate-r8-8). The two dialogs that
  // use it keep their own call for the secret's Copy, which is in the wizard's scan step; a second wipe finds nothing remembered and writes nothing.
  useWipeCopiedOnClose();

  async function copy() {
    try {
      await copyOneTimeSecret(recoveryCodesText(codes));
      toast.success(c("copied"));
    } catch {
      toast.danger(t("totp.copyFailed"));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Alert status="warning">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Description>{t("totp.codesWarning")}</Alert.Description>
        </Alert.Content>
      </Alert>
      <ul
        aria-label={t("totp.codesLabel")}
        className="bg-surface-secondary grid grid-cols-1 gap-x-4 gap-y-2 rounded-(--radius-box) p-4 sm:grid-cols-2"
        data-testid="recovery-codes"
        {...{[ONE_TIME_SECRET_ATTRIBUTE]: ""}}
        translate="no"
      >
        {codes.map((code) => (
          <li key={code} className="text-sm">
            <Tech className="select-all">{code}</Tech>
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="tertiary" onPress={() => void copy()}>
          <Icon name="copy" className="size-4" />
          {c("copy")}
        </Button>
        <Button
          size="sm"
          variant="tertiary"
          onPress={() => downloadTextFile(RECOVERY_FILE_NAME, recoveryFileContent(t("totp.fileHeader"), codes))}
        >
          <Icon name="download" className="size-4" />
          {t("totp.download")}
        </Button>
      </div>
      <p className="text-muted text-xs" data-testid="copy-note">
        {t("totp.copyNote")}
      </p>
      {confirmClose ? (
        <Alert status="danger">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("totp.closeAsk")}</Alert.Description>
            <div className="mt-2 flex flex-wrap gap-2">
              <PrimaryButton size="sm" onPress={onKeep}>
                {t("totp.closeKeep")}
              </PrimaryButton>
              <Button size="sm" variant="danger-soft" onPress={onClose}>
                {t("totp.closeAnyway")}
              </Button>
            </div>
          </Alert.Content>
        </Alert>
      ) : null}
      <div className="flex justify-end">
        <PrimaryButton onPress={onClose}>
          {t("totp.saveDone")}
        </PrimaryButton>
      </div>
    </div>
  );
}

// ---- regenerate ------------------------------------------------------------------------------------------

function RegenerateDialog({me, onClose}: {me: Me; onClose: () => void}) {
  useWipeCopiedOnClose();
  const t = useTranslations("account");
  const queryClient = useQueryClient();
  const recover = useRecoverable();
  const [proved, setProved] = useState(false);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [confirmClose, setConfirmClose] = useState(false);
  const [lost, setLost] = useState(false);
  const started = useRef(false);
  // The proof, the wait and the codes replace one another; the group that holds them takes the focus the one that had it left (wp9-r3-1).
  const {panel, heading} = useStepFocus<HTMLDivElement>(proved ? (codes ? "codes" : "working") : "proof");

  const generate = useCallback(async () => {
    setError(null);
    setLost(false);
    try {
      const result = await recover(() => accountApi.regenerateRecoveryCodes());
      setCodes(result.recovery_codes);
      void refreshAccount(queryClient);
    } catch (failure) {
      // Off in another tab (the row follows `/me`), or no answer: the old codes may be dead already, so the row's count
      // is not to be trusted either (wp9-r2-3, wp9-r2-7).
      if (hasCode(failure, "totp_not_enabled")) void refreshAccount(queryClient);
      else if (answerMayBeLost(failure)) {
        void refreshAccount(queryClient);
        setLost(true);
      }
      setError(failure);
    }
  }, [recover, queryClient]);

  const locked = proved && !codes && !error;
  useLeaveGuard(locked || codes !== null, () => {
    if (codes) setConfirmClose(true);
  });

  // The old codes stop working at this call, so it runs after the proof and not before.
  useEffect(() => {
    if (!proved || started.current) return;
    started.current = true;
    void generate();
  }, [proved, generate]);

  return (
    // From the proof until the codes arrive (or the call fails) the old codes are dead and the new ones are on their
    // way: the dialog must be there to show them (wp9-r1-2).
    <DialogFrame
      isOpen
      onClose={() => (codes ? setConfirmClose(true) : onClose())}
      isLocked={locked}
      title={t("totp.regenerateTitle")}
    >
      <div ref={panel}>
        <div ref={heading} tabIndex={-1} role="group" aria-label={t("totp.regenerateTitle")} className="outline-none">
          {!proved ? <ReauthPanel me={me} onDone={() => setProved(true)} onCancel={onClose} /> : null}
          {proved && codes ? (
            <CodesView codes={codes} confirmClose={confirmClose} onKeep={() => setConfirmClose(false)} onClose={onClose} />
          ) : null}
          {proved && !codes ? (
            <div className="flex flex-col gap-4">
              {error ? null : <Skeleton aria-hidden className="h-32 w-full rounded-(--radius-box)" />}
              <FormError error={error} onRetry={() => void generate()} />
              {lost && error ? <LostAnswer text={t("totp.regenerateLost")} /> : null}
              {error ? (
                <div className="flex justify-end">
                  <Button variant="tertiary" onPress={onClose}>
                    {t("totp.cancel")}
                  </Button>
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </DialogFrame>
  );
}

// ---- disable ---------------------------------------------------------------------------------------------

function DisableFlow({me, onDisabled, onClose}: {me: Me; onDisabled: () => void; onClose: () => void}) {
  const t = useTranslations("account");
  const c = useTranslations("common");
  const queryClient = useQueryClient();
  const recover = useRecoverable();
  const [proved, setProved] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function disable() {
    setPending(true);
    setError(null);
    try {
      const result = await recover(() => accountApi.totpDisable());
      onDisabled();
      toast.success(result.ended_sessions > 0 ? t("totp.disabledEnded", {count: result.ended_sessions}) : t("totp.disabled"));
      await refreshAccount(queryClient);
      onClose();
    } catch (failure) {
      // Already off in another tab: the row follows `/me`.
      if (hasCode(failure, "totp_not_enabled")) void refreshAccount(queryClient);
      setError(failure);
      setPending(false);
    }
  }

  if (!proved) {
    return (
      <DialogFrame isOpen onClose={onClose} title={t("totp.disableTitle")}>
        <ReauthPanel me={me} onDone={() => setProved(true)} onCancel={onClose} />
      </DialogFrame>
    );
  }
  return (
    <ConfirmFrame
      isOpen
      onOpenChange={(open) => !open && !pending && onClose()}
      status="danger"
      icon={<Icon name="shield" className="size-5" />}
      title={t("totp.disableTitle")}
      footer={
        <>
          <Button slot="close" variant="tertiary" isDisabled={pending}>
            {c("cancel")}
          </Button>
          <Button variant="danger" isPending={pending} onPress={() => void disable()}>
            {t("totp.disableConfirm")}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <p>{t("totp.disableText")}</p>
        <FormError error={error} onRetry={() => void disable()} />
      </div>
    </ConfirmFrame>
  );
}
