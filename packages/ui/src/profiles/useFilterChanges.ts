"use client";

import {useSetProfileFilter, type CatalogFilter, type ProfileFilter} from "@ctrlz/api-client/hooks/filters.ts";
import {toast} from "@heroui/react";
import {useCallback, useState} from "react";

import {useErrorText} from "../feedback/errorText.ts";
import {modeToSend, needsNewDomainsWarning} from "./filtersModel.ts";

// The two writes of the Filters screens, Native and 3rd Party: a switch (with the default or remembered mode when it goes on, T-146) and a
// mode (applied at once, T-147). A refusal puts the switch back (the hook does) and says why in a toast. New Domains also opens the `.ir`
// notice once its change has gone through (T-537).

export function useFilterChanges(profileId: string, rows: readonly ProfileFilter[] | undefined) {
  const set = useSetProfileFilter();
  const errorText = useErrorText();
  const [notice, setNotice] = useState(false);

  const change = useCallback(
    (filter: CatalogFilter, next: {enabled: boolean; mode?: string}) => {
      const row = rows?.find((r) => r.filter_id === filter.id);
      const mode = next.enabled ? (next.mode ?? modeToSend(filter, row)) : undefined;
      const warn = needsNewDomainsWarning({filterId: filter.id, enabled: next.enabled, wasEnabled: row?.enabled ?? false, ...(mode !== undefined ? {mode} : {}), ...(row?.mode !== undefined ? {wasMode: row.mode} : {})});
      // `mutateAsync`: every tile shares this mutation, and the callbacks of `mutate` run for the latest call only, so the notice or the toast of
      // a write that was still open when another began would be lost.
      void set.mutateAsync({profileId, filterId: filter.id, enabled: next.enabled, ...(mode !== undefined ? {mode} : {})}).then(
        () => {
          if (warn) setNotice(true);
        },
        (error: unknown) => toast.danger(errorText(error)),
      );
    },
    [profileId, rows, set, errorText],
  );

  return {
    toggle: (filter: CatalogFilter, enabled: boolean) => change(filter, {enabled}),
    setMode: (filter: CatalogFilter, mode: string) => change(filter, {enabled: true, mode}),
    notice,
    closeNotice: () => setNotice(false),
  };
}
