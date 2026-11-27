"use client";

// Spec p2 9.3, WF "Filters" (T-144 to T-148, T-150, T-537): the card grid of the 20 Native filters, a switch and a mode menu on each card,
// the explanation of each filter in `helpPane=filter.<id>`, and the link to the 3rd Party page. Everything is written at once: P2 has no
// preview (T-147; the preview is P5's).

import {useCatalogFilters, useProfileFilters} from "@ctrlz/api-client/hooks/filters.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useTranslations} from "next-intl";

import {CardGrid} from "../data/CardGrid.tsx";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {FilterGridSkeleton, ScreenStack, useSortedFilters} from "./FilterGridShell.tsx";
import {FilterKindNav, FilterTile} from "./FilterTile.tsx";
import {cardOf, nativeFilters, onCount} from "./filtersModel.ts";
import {NewDomainsNotice} from "./NewDomainsNotice.tsx";
import {useProfileFrame} from "./ProfileFrameContext.tsx";
import {profileHref, thirdPartyHref} from "./profileRoutes.ts";
import {useFilterChanges} from "./useFilterChanges.ts";

export function ProfileFiltersScreen({profileId}: {profileId: string}) {
  const t = useTranslations("profiles");
  const format = useAppFormat();
  const {profile, readOnly} = useProfileFrame();
  const catalog = useCatalogFilters();
  const rows = useProfileFilters(profileId);
  const changes = useFilterChanges(profileId, rows.data);
  const help = useUrlDialog("helpPane");
  const native = nativeFilters(catalog.data);
  const sorted = useSortedFilters(native);
  const label = t("filters.gridLabel", {name: profile.name});

  if (catalog.isError || rows.isError) {
    return (
      <ScreenStack screen="profile-filters">
        <SectionError error={catalog.error ?? rows.error} onRetry={() => void Promise.all([catalog.refetch(), rows.refetch()])} />
      </ScreenStack>
    );
  }
  if (!catalog.data || !rows.data) {
    return (
      <ScreenStack screen="profile-filters">
        <FilterGridSkeleton label={t("filters.loading")} />
      </ScreenStack>
    );
  }

  return (
    <ScreenStack screen="profile-filters">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium" aria-live="polite">
          {t("filters.summary", {on: format.number(onCount(native, rows.data)), total: format.number(native.length)})}
        </h2>
        <FilterKindNav current="native" nativeHref={profileHref(profileId, "filters")} thirdPartyHref={thirdPartyHref(profileId)} />
      </div>
      {sorted.length === 0 ? (
        <SectionEmpty icon="filters" title={t("filters.empty")} description={t("filters.emptyText")} />
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
      <NewDomainsNotice isOpen={changes.notice} onClose={changes.closeNotice} />
    </ScreenStack>
  );
}
