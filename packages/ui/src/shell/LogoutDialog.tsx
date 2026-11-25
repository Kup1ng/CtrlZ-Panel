"use client";

import {Button, toast} from "@heroui/react";
import {errorMessageArgs, errorMessageKey} from "@ctrlz/api-client/errors.ts";
import {useAdminLogout} from "@ctrlz/api-client/admin/session.ts";
import {useLogout} from "@ctrlz/api-client/hooks/me.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useLocale, useTranslations} from "next-intl";
import {useState} from "react";

import {ConfirmFrame} from "../dialog/ConfirmFrame.tsx";
import {useShellApp} from "./shellContext.tsx";

// T-109. Confirm, then end the session: POST /auth/logout, then logoutLocal() (spec 14.4). Every Log out of the product
// opens this one: the shell's sidebar and user menu, and the buttons of the pages outside the shell (change password,
// suspended, the admin setup). It reads the app from AppProviders, so it works on those pages as well.

export function LogoutDialog({isOpen, onOpenChange}: {isOpen: boolean; onOpenChange: (open: boolean) => void}) {
  const t = useTranslations("shell");
  const c = useTranslations("common");
  const e = useTranslations("errors");
  const locale = useLocale();
  // Both are cheap callbacks; only the one of this app's API is called. Admin's has no refresh and no channel.
  const panelLogout = useLogout(locale);
  const adminLogout = useAdminLogout(locale);
  const logout = useShellApp() === "admin" ? adminLogout : panelLogout;
  const [pending, setPending] = useState(false);

  return (
    <ConfirmFrame
      isOpen={isOpen}
      // The call is already running: closing the dialog now would show an untouched page that the logout then takes away (pg2-1-5).
      onOpenChange={(open) => {
        if (!open && pending) return;
        onOpenChange(open);
      }}
      status="warning"
      icon={<Icon name="logout" className="size-5" />}
      title={t("logout.title")}
      footer={
        <>
          <Button slot="close" variant="tertiary" isDisabled={pending}>
            {c("cancel")}
          </Button>
          <Button
            isPending={pending}
            variant="danger"
            onPress={async () => {
              setPending(true);
              try {
                await logout();
              } catch (error) {
                // The server did not end the session, so the page stays and says why.
                setPending(false);
                toast.danger(e(errorMessageKey(error), errorMessageArgs(error)));
              }
            }}
          >
            {t("logout.confirm")}
          </Button>
        </>
      }
    >
      <p>{t("logout.text")}</p>
    </ConfirmFrame>
  );
}
