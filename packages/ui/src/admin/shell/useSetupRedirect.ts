"use client";

import {adminMeKeys} from "@ctrlz/api-client/admin/session.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {useQueryClient} from "@tanstack/react-query";
import {useEffect} from "react";

// Spec 11.2: "any 403 `setup_required` routes to /setup, and the shell does not render" (T-323). `/me` is the usual way an
// account in setup is found (AdminGate), but the state can change under a page that is already showing: the console reset the
// password from the server's side, or another tab finished or undid a step. Then the next admin call answers 403
// `setup_required` instead of `/me`, from any query or mutation of any page. Every call passes the caches, so this listens
// there, as the session guard does for a 401: it refetches `/me` (which now says `setup`, so the gate takes over) and moves
// to /setup at once, without waiting for the screen that asked to render the error.

export function useSetupRedirect() {
  const queryClient = useQueryClient();
  const router = useRouter();
  useEffect(() => {
    const onError = (error: unknown) => {
      if (!hasCode(error, "setup_required")) return;
      void queryClient.invalidateQueries({queryKey: adminMeKeys.all});
      router.replace("/setup");
    };
    const offQueries = queryClient.getQueryCache().subscribe((event) => {
      if (event.type === "updated" && event.action.type === "error") onError(event.action.error);
    });
    const offMutations = queryClient.getMutationCache().subscribe((event) => {
      if (event.type === "updated" && event.action.type === "error") onError(event.action.error);
    });
    return () => {
      offQueries();
      offMutations();
    };
  }, [queryClient, router]);
}
