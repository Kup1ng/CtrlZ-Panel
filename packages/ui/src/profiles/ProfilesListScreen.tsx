"use client";

import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useMemo, useState} from "react";

import {ListRowSkeleton, RowList} from "../data/ListRow.tsx";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {OnboardingCard} from "../shell/OnboardingCard.tsx";
import {PageHeader, type HeaderAction} from "../shell/PageHeader.tsx";
import {useClearNewProfileOnLeave, useNewProfileId} from "./newProfile.ts";
import {ProfileDialogs} from "./ProfileDialogs.tsx";
import {ProfileListRow} from "./ProfileListRow.tsx";
import {visibleProfiles, type ProfileSort} from "./profileList.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec p2 9.1, WF "Profiles" (T-127, T-128, T-135, T-136). `/profiles`:
//
//   PageHeader     search, the three-dot menu (Import, sort by name, sort by last change) and `+` (profileDialog=add)
//   the checklist  the first-run card of FE 8.12, above the list
//   the rows       ProfileListRow: icon with the flag of the Default Rule, name, Endpoint line, four counters, arrow
//
// A tenant holds few profiles, so the list is one request, searched and sorted here. The name sort uses the locale's `Intl.Collator`
// (`useAppFormat().compare`). A profile that was just made, imported or duplicated is first with a highlight until the list is left (T-136).

export function ProfilesListScreen() {
  const t = useTranslations("profiles");
  const s = useTranslations("shell");
  const format = useAppFormat();
  const dialog = useUrlDialog("profileDialog");
  const profiles = useProfiles();
  const newId = useNewProfileId();
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<ProfileSort>("changed");

  // "Until the next load": the mark does not outlive the visit to the list.
  useClearNewProfileOnLeave();

  const shown = useMemo(
    () => visibleProfiles(profiles.data ?? [], {query, sort, compare: format.compare, newId}),
    [profiles.data, query, sort, format.compare, newId],
  );

  const actions: HeaderAction[] = [
    {id: "import", label: t("list.menu.import"), icon: "upload", onAction: () => dialog.open("import")},
    {id: "sort-name", label: t(sort === "name" ? "list.menu.sortNameOn" : "list.menu.sortName"), icon: sort === "name" ? "check" : undefined, onAction: () => setSort("name")},
    {id: "sort-changed", label: t(sort === "changed" ? "list.menu.sortChangedOn" : "list.menu.sortChanged"), icon: sort === "changed" ? "check" : undefined, onAction: () => setSort("changed")},
  ];

  const total = profiles.data?.length ?? 0;
  const searching = query.trim() !== "";

  return (
    <div data-screen="profiles-list" className="flex flex-col gap-4">
      <PageHeader
        icon="profiles"
        title={s("nav.profiles")}
        subtitle={s("pages.profiles.subtitle")}
        helpKey="profiles"
        actions={actions}
        onSearch={setQuery}
        onCreate={() => dialog.open("add")}
        createLabel={t("list.create")}
      />
      <OnboardingCard />

      {profiles.isError && !profiles.data ? (
        <SectionError error={profiles.error} onRetry={() => void profiles.refetch()} />
      ) : profiles.isPending ? (
        <div role="status" aria-label={t("list.loading")} className="flex flex-col gap-2">
          <ListRowSkeleton />
          <ListRowSkeleton />
          <ListRowSkeleton />
        </div>
      ) : total === 0 ? (
        <SectionEmpty
          icon="profiles"
          title={t("list.empty")}
          description={t("list.emptyText")}
          action={
            <PrimaryButton onPress={() => dialog.open("add")}>
              <Icon name="plus" className="size-4" />
              {t("list.create")}
            </PrimaryButton>
          }
        />
      ) : (
        <>
          <p className="text-muted text-xs" role="status" aria-live="polite">
            {t("list.summary", {count: shown.length, sort: t(`list.sortBy.${sort}`)})}
          </p>
          {shown.length === 0 && searching ? (
            <SectionEmpty icon="search" title={t("list.searchEmpty")} description={t("list.searchEmptyText")} />
          ) : (
            <RowList aria-label={t("list.label")}>
              {shown.map((profile) => (
                <ProfileListRow key={profile.id} profile={profile} isNew={profile.id === newId} />
              ))}
            </RowList>
          )}
        </>
      )}

      <ProfileDialogs />
    </div>
  );
}
