"use client";

import {ApiError, hasCode} from "@ctrlz/api-client/errors.ts";
import {Link} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import {useState} from "react";

import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {PhoneField} from "../forms/PhoneField.tsx";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {useApiForm} from "../forms/useApiForm.ts";
import {LoadingBlock} from "../forms/LoadingBlock.tsx";
import {AuthCard} from "./AuthCard.tsx";
import {authApi, type Locale} from "./authApi.ts";
import {useAuthHref} from "./authHref.ts";
import {RegisterConfirm, type Challenge} from "./RegisterConfirm.tsx";
import {useAuthConfig} from "./useAuthConfig.ts";

// Spec 10.4. Only when `registration_mode` is `open`; any other mode shows "Registration is closed",
// and `invite` mode adds the link to the invite page. A server that says the door shut while the
// page was open (`registration_closed`) ends in the same state.

// Registration cannot be judged without the answer of /auth/config, so a failure is a 503 with Retry.
const CONFIG_FAILED = new ApiError(503, "service_unavailable");

export function RegisterFlow() {
  const t = useTranslations("auth");
  const href = useAuthHref();
  const config = useAuthConfig();
  const [phone, setPhone] = useState("");
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [notice, setNotice] = useState<unknown>(null);
  const [shut, setShut] = useState(false);

  // The gates guard the number step, the one that sends a text. With a challenge in hand, a later answer of
  // /auth/config (SMS down, registration closed) must not replace the code step: the code is still valid and
  // what was typed would be lost. Only the server's own `registration_closed` ends it then (wp8-r14-1).
  const first = challenge === null;

  if (first && config.status === "loading") {
    return (
      <AuthCard title={t("register.title")}>
        <LoadingBlock />
        <p className="text-center text-sm">
          <Link href={href("/login")}>{t("register.signIn")}</Link>
        </p>
      </AuthCard>
    );
  }
  if (first && config.status === "failed") {
    return (
      <AuthCard title={t("register.title")}>
        <FormError error={CONFIG_FAILED} onRetry={config.retry} />
        {/* Like every other gated state, so a config that keeps failing is not a dead end (wp8-r21-1). */}
        <p className="text-center text-sm">
          <Link href={href("/login")}>{t("register.signIn")}</Link>
        </p>
      </AuthCard>
    );
  }

  if (shut || (first && config.registrationMode !== "open")) {
    return (
      <AuthCard title={t("register.closedTitle")} description={t("register.closedText")} focusHeading>
        <div className="flex flex-col items-center gap-2 text-sm">
          {config.registrationMode === "invite" ? <Link href={href("/invite")}>{t("login.invite")}</Link> : null}
          <Link href={href("/login")}>{t("register.signIn")}</Link>
        </div>
      </AuthCard>
    );
  }

  // Registration is confirmed by a text message, so without SMS it cannot complete (10.4).
  if (first && !config.smsAvailable) {
    return (
      <AuthCard title={t("register.title")} description={t("register.smsDown")} focusHeading>
        <div className="flex justify-center text-sm">
          <Link href={href("/login")}>{t("register.signIn")}</Link>
        </div>
      </AuthCard>
    );
  }

  if (challenge) {
    return (
      <RegisterConfirm
        identity={{kind: "phone", phone}}
        challenge={challenge}
        smsAvailable={config.smsAvailable}
        onChallenge={setChallenge}
        onRestart={(error) => {
          setNotice(error);
          setChallenge(null);
        }}
        onClosed={() => setShut(true)}
        title={t("register.confirmTitle")}
        description={t("register.confirmDescriptionGeneric")}
        submitLabel={t("register.create")}
        secondary={{label: t("register.change"), onPress: () => setChallenge(null)}}
        userInputs={[phone]}
      />
    );
  }

  // The notice (an expired code) belongs to the attempt that has just ended. It goes with the next thing the
  // visitor does: editing the number, or sending it. Left set, it came back whenever this step was shown again
  // (wp8-r1-6).
  return (
    <PhoneStep
      phone={phone}
      onPhone={(value) => {
        setPhone(value);
        setNotice(null);
      }}
      notice={notice}
      onSend={() => setNotice(null)}
      onSent={(sent) => {
        setNotice(null);
        setChallenge(sent);
      }}
      onClosed={() => setShut(true)}
    />
  );
}

function PhoneStep({
  phone,
  onPhone,
  notice,
  onSend,
  onSent,
  onClosed,
}: {
  phone: string;
  onPhone: (value: string) => void;
  notice: unknown;
  onSend: () => void;
  onSent: (challenge: Challenge) => void;
  onClosed: () => void;
}) {
  const t = useTranslations("auth");
  const href = useAuthHref();
  const locale = useLocale() as Locale;
  const form = useApiForm({focus: "phone"});
  const [pending, setPending] = useState(false);

  async function submit() {
    if (pending || form.blocked) return;
    if (!phone.trim()) return form.setFieldError("phone", t("fields.phone.required"));
    setPending(true);
    form.clear();
    onSend();
    try {
      const issued = await authApi.requestOtp({purpose: "signup", phone, locale});
      onSent({id: issued.challenge_id, readyAt: Date.now() + issued.resend_after_s * 1000});
    } catch (error) {
      if (hasCode(error, "registration_closed")) onClosed();
      else form.fail(error, hasCode(error, "invalid_phone") ? {field: "phone"} : {});
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthCard title={t("register.title")} description={t("register.subtitle")}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <FormError error={notice} />
        <PhoneField value={phone} {...form.bind("phone", onPhone)} isDisabled={pending} />
        <FormError error={form.formError} smsDown={t("register.smsDown")} onRetry={() => void submit()} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn}>
          {t("register.submit")}
        </SubmitButton>
      </AuthForm>
      <p className="text-muted text-center text-sm">
        {t("register.haveAccount")} <Link href={href("/login")}>{t("register.signIn")}</Link>
      </p>
    </AuthCard>
  );
}
