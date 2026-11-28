"use client";

import {toast} from "@heroui/react";
import type {ProfileCreated} from "@ctrlz/api-client/hooks/profiles.ts";
import {useTranslations} from "next-intl";
import {useCallback} from "react";

import {markNewProfile} from "./newProfile.ts";

// What follows a profile that has been made (Add, Import, Duplicate): it is marked as new for the list (T-136), a toast says so, and
// when some destinations in it are not available yet and act as Bypass (`flagged`, spec p2 4.2, 9.2) a second toast says that.

export function useAnnounceFlagged() {
  const t = useTranslations("profiles");
  return useCallback((flagged: number) => {
    if (flagged > 0) toast.warning(t("dialogs.flagged", {count: flagged}));
  }, [t]);
}

export function useAnnounceCreated() {
  const flagged = useAnnounceFlagged();
  return useCallback(
    (created: ProfileCreated, message: string) => {
      markNewProfile(created.profile.id);
      toast.success(message);
      flagged(created.flagged);
    },
    [flagged],
  );
}
