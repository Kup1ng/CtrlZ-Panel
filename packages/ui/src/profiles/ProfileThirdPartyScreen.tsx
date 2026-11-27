"use client";

// Spec p2 9.3, WF "Filters" (T-148, T-149, T-150): the 12 3rd Party lists on a page of their own, under the Advanced Mode banner. Turning on a
// second list shows the many-lists warning (open question 4). A list has one mode, so its card has a switch and the info button and no menu.

import {Alert} from "@heroui/react";
import {useCatalogFilters, useProfileFilters} from "@ctrlz/api-client/hooks/filters.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {useTranslations} from "next-intl";

import {CardGrid} from "../data/CardGrid.tsx";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {FilterGridSkeleton, ScreenStack, useSortedFilters} from "./FilterGridShell.tsx";
import {FilterKindNav, FilterTile} from "./FilterTile.tsx";
import {cardOf, manyListsOn, onCount, thirdPartyFilters} from "./filtersModel.ts";
import {useProfileFrame} from "./ProfileFrameContext.tsx";
import {profileHref, thirdPartyHref} from "./profileRoutes.ts";
import {useFilterChanges} from "./useFilterChanges.ts";

export function ProfileThirdPartyScreen({profileId}: {profileId: string}) {
  const t = useTranslations("profiles");
  const format = useAppFormat();
  const {profile, readOnly} = useProfileFrame();
  const catalog = useCatalogFilters();
  const rows = useProfileFilters(profileId);
  const changes = useFilterChanges(profileId, rows.data);
  const help = useUrlDialog("helpPane");
  const lists = thirdPartyFilters(catalog.data);
  const sorted = useSortedFilters(lists);
  const label = t("thirdParty.gridLabel", {name: profile.name});

  if (catalog.isError || rows.isError) {
    return (
      <ScreenStack screen="profile-third-party">
        <SectionError error={catalog.error ?? rows.error} onRetry={() => void Promise.all([catalog.refetch(), rows.refetch()])} />
      </ScreenStack>
    );
  }
  if (!catalog.data || !rows.data) {
    return (
      <ScreenStack screen="profile-third-party">
        <FilterGridSkeleton label={t("filters.loading")} />
      </ScreenStack>
    );
  }

  const on = onCount(lists, rows.data);
  return (
    <ScreenStack screen="profile-third-party">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium" aria-live="polite">
          {t("thirdParty.summary", {on: format.number(on), total: format.number(lists.length)})}
        </h2>
        <FilterKindNav current="third-party" nativeHref={profileHref(profileId, "filters")} thirdPartyHref={thirdPartyHref(profileId)} />
      </div>

      <Alert status="warning" data-testid="advanced-mode">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Title>{t("thirdParty.advanced.title")}</Alert.Title>
          <Alert.Description>{t("thirdParty.advanced.text")}</Alert.Description>
        </Alert.Content>
      </Alert>

      {/* The live region stays in the page and only its content changes, so a reader hears it when the second list goes on. */}
      <div role="status" data-testid="many-lists" className="empty:sr-only">
        {manyListsOn(on) ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t("thirdParty.many.title")}</Alert.Title>
              <Alert.Description>{t("thirdParty.many.text")}</Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}
      </div>

      {sorted.length === 0 ? (
        <SectionEmpty icon="filters" title={t("thirdParty.empty")} />
      ) : (
        <CardGrid label={label} columns="compact">
          {sorted.map(({filter, name}) => (
            <FilterTile
              key={filter.id}
              card={cardOf(filter, rows.data)}
              name={name}
              readOnly={readOnly}
              onToggle={(enabled) => changes.toggle(filter, enabled)}
              onMode={(mode) => changes.setMode(filter, mode)}
              onInfo={() => help.open(`filter.${filter.id}`)}
            />
          ))}
        </CardGrid>
      )}
      <p className="text-sm">
        <Link href={profileHref(profileId, "filters")} className="text-muted underline">
          {t("thirdParty.back")}
        </Link>
      </p>
    </ScreenStack>
  );
}
