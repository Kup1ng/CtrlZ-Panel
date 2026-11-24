"use client";

import {Button, FieldError, Input, Label, TextField} from "@heroui/react";
import {useTranslations} from "next-intl";
import type {ReactNode, Ref} from "react";

import {OtpField} from "../forms/OtpField.tsx";

import {changeGrouped, groupCode, RECOVERY_LENGTH, RECOVERY_PLACEHOLDER} from "./codes.ts";

// The recovery code of the 2fa step, the Forgot Password step 3 and any other place a TOTP code can be
// swapped for one (AUTH 6.5). It shows what the user types in groups of four, upper case, and the value it
// reports is the canonical text, so the caller sends exactly that.

export function RecoveryCodeField({
  value,
  onChange,
  isDisabled,
  errorMessage,
  ref,
}: {
  /** The canonical value, without hyphens. */
  value: string;
  onChange: (canonical: string) => void;
  isDisabled?: boolean;
  errorMessage?: string;
  ref?: Ref<HTMLInputElement>;
}) {
  const t = useTranslations("auth");
  return (
    <TextField
      name="recovery_code"
      variant="secondary"
      fullWidth
      isDisabled={isDisabled}
      isInvalid={errorMessage !== undefined}
      value={groupCode(value)}
      onChange={(text) => changeGrouped(text, RECOVERY_LENGTH, onChange)}
      autoComplete="off"
    >
      <Label>{t("fields.recovery.label")}</Label>
      <Input
        ref={ref}
        dir="ltr"
        className="text-start font-mono"
        placeholder={RECOVERY_PLACEHOLDER}
        autoCapitalize="characters"
        autoCorrect="off"
        spellCheck={false}
      />
      <FieldError>{errorMessage}</FieldError>
    </TextField>
  );
}

export type SecondFactorMode = "totp" | "recovery";

/**
 * The code of an account's second factor: six digits from the authenticator app, or (when `canRecover`)
 * one recovery code in its place. The mode and both values belong to the caller, who sends whichever
 * one the mode names. `onComplete` fires when the six digits are in, with ASCII digits.
 */
export function SecondFactorField({
  mode,
  onModeChange,
  totp,
  onTotp,
  recovery,
  onRecovery,
  onComplete,
  canRecover,
  isDisabled,
  errorMessage,
  description,
  otpRef,
  recoveryRef,
}: {
  mode: SecondFactorMode;
  onModeChange: (mode: SecondFactorMode) => void;
  totp: string;
  onTotp: (value: string) => void;
  recovery: string;
  onRecovery: (canonical: string) => void;
  onComplete: (code: string) => void;
  canRecover: boolean;
  isDisabled?: boolean;
  errorMessage?: string;
  description?: ReactNode;
  otpRef?: Ref<HTMLInputElement>;
  recoveryRef?: Ref<HTMLInputElement>;
}) {
  const t = useTranslations("auth");
  return (
    <div className="flex flex-col gap-2">
      {mode === "totp" ? (
        <OtpField
          ref={otpRef}
          name="totp_code"
          label={t("fields.totp.label")}
          description={description}
          value={totp}
          onChange={onTotp}
          onComplete={onComplete}
          isDisabled={isDisabled}
          errorMessage={errorMessage}
        />
      ) : (
        <RecoveryCodeField
          ref={recoveryRef}
          value={recovery}
          onChange={onRecovery}
          isDisabled={isDisabled}
          errorMessage={errorMessage}
        />
      )}
      {canRecover ? (
        <div className="flex justify-center">
          <Button size="sm" variant="ghost" isDisabled={isDisabled} onPress={() => onModeChange(mode === "totp" ? "recovery" : "totp")}>
            {mode === "totp" ? t("login.twoFactor.useRecovery") : t("login.twoFactor.useApp")}
          </Button>
        </div>
      ) : null}
    </div>
  );
}
