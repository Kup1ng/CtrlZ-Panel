"use client";

import {useLogout, useSession} from "@ctrlz/api-client/hooks/me.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {Button} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useState} from "react";

import {FormError} from "../forms/FormError.tsx";
import {SessionBinding} from "../shell/SessionBinding.tsx";
import {AuthCard} from "./AuthCard.tsx";

// Spec 10.8. A static explanation and Log out, for `account_suspended` and for `Me.tenant.status =
// "suspended"`. /me, POST /auth/logout and POST /auth/refresh stay open for a suspended tenant (AUTH 3.5),
// so the binding and the button both work. Like /change-password it sits outside the shell, so it mounts
// SessionBinding itself.

export function SuspendedView() {
  const t = useTranslations("auth");
  const router = useRouter();
  const locale = useLocale();
  const logout = useLogout(locale);
  const {status} = useSession();
  const [pending, setPending] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);

  // A visitor whose account is fine is not stuck here: the page is only for a suspended tenant.
  useEffect(() => {
    if (status === "ready") router.replace("/profiles");
    else if (status === "restricted") router.replace("/change-password");
  }, [status, router]);

  async function signOut() {
    setPending(true);
    setFailure(null);
    try {
      await logout();
    } catch (error) {
      setFailure(error);
      setPending(false);
    }
  }

  return (
    <>
      <SessionBinding />
      <AuthCard title={t("suspended.title")} description={t("suspended.text")} focusHeading>
        <FormError error={failure} onRetry={() => void signOut()} />
        <Button variant="secondary" fullWidth isPending={pending} onPress={() => void signOut()}>
          {t("logout")}
        </Button>
      </AuthCard>
    </>
  );
}
