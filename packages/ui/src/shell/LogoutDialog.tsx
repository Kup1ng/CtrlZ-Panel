"use client";

import {AlertDialog, Button} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useLocale, useTranslations} from "next-intl";
import {useCallback, useState} from "react";

// T-109. Confirm, then end the session.

/**
 * STUB until WP4 lands. The real sequence is `POST /auth/logout`, then
 * `logoutLocal()` (clear the query cache, post `logout` on
 * BroadcastChannel("ctrlz-session"), full-load the login page; spec 14.4).
 * Until then this only leaves for the login page, which does NOT end the
 * session on the server.
 */
function useLogout() {
  const locale = useLocale();
  return useCallback(async () => {
    window.location.assign(`/${locale}/login`);
  }, [locale]);
}

export function LogoutDialog({isOpen, onOpenChange}: {isOpen: boolean; onOpenChange: (open: boolean) => void}) {
  const t = useTranslations("shell");
  const c = useTranslations("common");
  const logout = useLogout();
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
                await logout();
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
