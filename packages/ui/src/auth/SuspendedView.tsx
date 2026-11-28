"use client";

import {useSession} from "@ctrlz/api-client/hooks/me.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useEffect, useState} from "react";

import {LogoutDialog} from "../shell/LogoutDialog.tsx";
import {SessionBinding} from "../shell/SessionBinding.tsx";
import {AuthCard} from "./AuthCard.tsx";

// Spec 10.8. A static explanation and Log out, for `account_suspended` and for `Me.tenant.status =
// "suspended"`. /me, POST /auth/logout and POST /auth/refresh stay open for a suspended tenant (AUTH 3.5),
// so the binding and the button both work. Like /change-password it sits outside the shell, so it mounts
// SessionBinding itself.

export function SuspendedView() {
  const t = useTranslations("auth");
  const router = useRouter();
  const {status} = useSession();
  // Log out asks first (T-109); the shell's dialog ends the session and says why when it cannot.
  const [logoutOpen, setLogoutOpen] = useState(false);

  // A visitor whose account is fine is not stuck here: the page is only for a suspended tenant.
  useEffect(() => {
    if (status === "ready") router.replace("/profiles");
    else if (status === "restricted") router.replace("/change-password");
  }, [status, router]);

  return (
    <>
      <SessionBinding />
      <AuthCard title={t("suspended.title")} description={t("suspended.text")} focusHeading>
        <Button variant="secondary" fullWidth onPress={() => setLogoutOpen(true)}>
          {t("logout")}
        </Button>
        <LogoutDialog isOpen={logoutOpen} onOpenChange={setLogoutOpen} />
      </AuthCard>
    </>
  );
}
