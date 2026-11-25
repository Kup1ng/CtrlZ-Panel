"use client";

import {AlertDialog, Button, toast} from "@heroui/react";
import {errorMessageArgs, errorMessageKey} from "@ctrlz/api-client/errors.ts";
import {useAdminLogout} from "@ctrlz/api-client/admin/session.ts";
import {useLogout} from "@ctrlz/api-client/hooks/me.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useLocale, useTranslations} from "next-intl";
import {useState} from "react";

import {useShellApp} from "./shellContext.tsx";

// T-109. Confirm, then end the session: POST /auth/logout, then logoutLocal() (spec 14.4).

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
    <AlertDialog.Backdrop isOpen={isOpen} onOpenChange={onOpenChange}>
      <AlertDialog.Container placement="center">
        <AlertDialog.Dialog className="sm:max-w-[400px]">
          <AlertDialog.CloseTrigger aria-label={c("close")} />
          <AlertDialog.Header>
            <AlertDialog.Icon status="warning">
              <Icon name="logout" className="size-5" />
            </AlertDialog.Icon>
            <AlertDialog.Heading>{t("logout.title")}</AlertDialog.Heading>
          </AlertDialog.Header>
          <AlertDialog.Body>
            <p>{t("logout.text")}</p>
          </AlertDialog.Body>
          <AlertDialog.Footer>
            <Button slot="close" variant="tertiary">
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
          </AlertDialog.Footer>
        </AlertDialog.Dialog>
      </AlertDialog.Container>
    </AlertDialog.Backdrop>
  );
}
