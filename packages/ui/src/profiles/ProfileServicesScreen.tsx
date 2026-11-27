"use client";

// Spec p2 9.4 and 9.5, WF "Services" and "Destinations" (T-162 to T-166, T-521): the profile's services as cards grouped by category, each
// category with a remove-all (confirmed), `+` for Choose Service (`serviceDialog=choose`), and the Destinations dialog of one service
// (`serviceDialog=destination:<slug>`), which is where a Redirect gets its target.

import {AlertDialog, Button, Chip, SearchField, Skeleton, toast} from "@heroui/react";
import {useProfileLocations} from "@ctrlz/api-client/hooks/profiles.ts";
import {
  useBatchProfileServices,
  useCatalogServices,
  useProfileServices,
  useRemoveProfileService,
  useSetProfileService,
  type ServiceAction,
  type Target,
} from "@ctrlz/api-client/hooks/services.ts";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useLocale, useTranslations} from "next-intl";
import {useCallback, useEffect, useMemo, useRef, useState} from "react";

import type {Action} from "../controls/threeState.ts";
import {CardGrid} from "../data/CardGrid.tsx";
import {DestinationsDialog} from "../destinations/DestinationsDialog.tsx";
import {parseServiceDialog, serviceDialogValue} from "../dialog/dialogValues.ts";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {useErrorText} from "../feedback/errorText.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {ChooseServiceDialog} from "./ChooseServiceDialog.tsx";
import {catalogName} from "./filtersModel.ts";
import {useProfileFrame} from "./ProfileFrameContext.tsx";
import {ServiceCard} from "./ServiceCard.tsx";
import {useServiceDestinations} from "./useServiceDestinations.ts";
import {cardLimits, CARDS_PER_STEP, groupProfileServices, UNKNOWN_CATEGORY, type ServiceGroup, type ServiceItem} from "./servicesModel.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

const fold = (text: string) => normalizeFaSearch(text).toLocaleLowerCase();

export function ProfileServicesScreen({profileId}: {profileId: string}) {
  const t = useTranslations("services");
  const p = useTranslations("profiles");
  const c = useTranslations("common");
  const locale = useLocale();
  const format = useAppFormat();
  const errorText = useErrorText();
  const {profile, readOnly} = useProfileFrame();
  const catalog = useCatalogServices();
  const own = useProfileServices(profileId);
  const locations = useProfileLocations(profileId);
  const set = useSetProfileService();
  const remove = useRemoveProfileService();
  const batch = useBatchProfileServices();
  const dialog = useUrlDialog("serviceDialog");
  const parsed = parseServiceDialog(dialog.value);
  const [query, setQuery] = useState("");
  const [confirming, setConfirming] = useState<ServiceGroup | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  // How many cards each category draws (default one step), and the card that is to take focus once the next step is on the page.
  const [drawn, setDrawn] = useState<ReadonlyMap<string, number>>(new Map());
  const focusAt = useRef<{category: string; index: number} | null>(null);
  const root = useRef<HTMLDivElement>(null);

  // Until the profile's locations arrive (or when they fail to) Redirect is not taken away: the dialog says what is missing.
  const hasDestination = locations.data ? locations.data.locations.length > 0 || locations.data.auto_random : true;

  // Every service of the profile by category, and the ones a search keeps. Remove all acts on the whole category, never on what a search left.
  const everything = useMemo(
    () =>
      catalog.data && own.data
        ? groupProfileServices({
            categories: catalog.data.categories,
            catalogue: catalog.data.services,
            rows: own.data,
            locale,
            query: "",
            fold,
            compare: format.compare,
            unknownCategory: {id: UNKNOWN_CATEGORY, name_fa: t("card.notInCatalogue"), name_en: t("card.notInCatalogue")},
          })
        : [],
    [catalog.data, own.data, locale, format, t],
  );
  const groups = useMemo(
    () =>
      query.trim() === ""
        ? everything
        : everything.flatMap((g) => {
            const q = fold(query.trim());
            const items = g.items.filter((i) => fold(i.name).includes(q) || fold(i.row.slug).includes(q));
            return items.length > 0 ? [{...g, items}] : [];
          }),
    [everything, query],
  );

  const limits = useMemo(() => cardLimits(groups, drawn), [groups, drawn]);
  const limitOf = (id: string) => limits.get(id) ?? 0;

  // The services that are drawn and limited to some regions ask for their own set (T-166), but only once their card has come near the screen: the
  // route is `user-read`, 300 a minute for the whole page, and a card that is never scrolled to has no use for the answer (S3-r3-2).
  const candidates = useMemo(
    () =>
      groups.flatMap((g) =>
        g.items
          .slice(0, limits.get(g.category.id) ?? 0)
          .filter((i) => i.service?.region_limited)
          .map((i) => i.row.slug),
      ),
    [groups, limits],
  );
  const [seen, setSeen] = useState<ReadonlySet<string>>(new Set());
  useEffect(() => {
    const want = new Set(candidates);
    if (want.size === 0 || typeof IntersectionObserver === "undefined" || !root.current) return;
    const observer = new IntersectionObserver(
      (entries) => {
        const hit = entries.filter((e) => e.isIntersecting).map((e) => e.target as HTMLElement);
        if (hit.length === 0) return;
        for (const el of hit) observer.unobserve(el);
        const slugs = hit.map((el) => el.dataset.service ?? "");
        setSeen((prev) => (slugs.every((slug) => prev.has(slug)) ? prev : new Set([...prev, ...slugs])));
      },
      {rootMargin: "200px"},
    );
    for (const el of root.current.querySelectorAll<HTMLElement>("[data-service]")) {
      if (want.has(el.dataset.service ?? "")) observer.observe(el);
    }
    return () => observer.disconnect();
  }, [candidates]);
  const asked = useMemo(() => candidates.filter((slug) => seen.has(slug)), [candidates, seen]);
  const ownDestination = useServiceDestinations(profileId, asked);

  // The card that was the first of the step just drawn takes focus, so a keyboard user is not left on a button that has gone.
  useEffect(() => {
    const at = focusAt.current;
    if (!at) return;
    focusAt.current = null;
    const cards = root.current?.querySelectorAll<HTMLElement>(`[data-category="${CSS.escape(at.category)}"] [role="listitem"]`);
    cards?.[at.index]?.querySelector<HTMLElement>("input, button")?.focus();
  }, [drawn]);

  const fail = (error: unknown) => toast.danger(errorText(error));
  // `mutateAsync` and not `mutate` with callbacks: one mutation serves every card, and TanStack runs the per-call callbacks of the latest call only,
  // so a second press before the first answered would have dropped the first one's toast.
  const apply = (slug: string, name: string, enabled: boolean, action: ServiceAction, target?: Target) =>
    void set.mutateAsync({profileId, slug, enabled, action, ...(target ? {target} : {})}).catch((error: unknown) => toast.danger(`${t("card.failed", {name})} ${errorText(error)}`));

  // The four handlers every card gets are the same functions for the life of the page, so a card re-renders only for its own row. They read the
  // latest props and mutations through a ref that is set after each render, and a press is the only caller, so it is always set by then.
  const live = useRef<{
    toggle: (i: ServiceItem, on: boolean) => void;
    act: (i: ServiceItem, a: Action) => void;
    open: (i: ServiceItem) => void;
    drop: (i: ServiceItem) => void;
  } | null>(null);
  useEffect(() => {
    live.current = {
      // A Redirect is written with its destination: the API takes a Redirect without one for a different state, and refuses it.
      toggle: (item, enabled) => apply(item.row.slug, item.name, enabled, item.row.action, item.row.action === "redirect" ? item.row.target : undefined),
      act: (item, action) => {
        // A Redirect needs a destination, so it is chosen first and written with it; the others are written at once.
        if (action === "redirect") dialog.open(serviceDialogValue({kind: "destination", slug: item.row.slug}));
        else if (action === "block" || action === "bypass") apply(item.row.slug, item.name, item.row.enabled, action);
      },
      open: (item) => dialog.open(serviceDialogValue({kind: "destination", slug: item.row.slug})),
      drop: (item) => void remove.mutateAsync({profileId, slug: item.row.slug}).then(() => toast.success(t("card.removed", {name: item.name})), fail),
    };
  });
  const onToggle = useCallback((item: ServiceItem, enabled: boolean) => live.current?.toggle(item, enabled), []);
  const onAction = useCallback((item: ServiceItem, action: Action) => live.current?.act(item, action), []);
  const onOpenDestination = useCallback((item: ServiceItem) => live.current?.open(item), []);
  const onRemove = useCallback((item: ServiceItem) => live.current?.drop(item), []);

  const target = parsed?.kind === "destination" ? own.data?.find((r) => r.slug === parsed.slug) : undefined;
  const targetName = target ? (everything.flatMap((g) => g.items).find((i) => i.row.slug === target.slug)?.name ?? target.slug) : "";

  if (catalog.isError || own.isError) {
    return (
      <div data-screen="profile-services">
        <SectionError error={catalog.error ?? own.error} onRetry={() => void Promise.all([catalog.refetch(), own.refetch()])} />
      </div>
    );
  }
  if (!catalog.data || !own.data) {
    return (
      <div data-screen="profile-services" role="status" aria-label={t("page.loading")} className="flex flex-col gap-3">
        <Skeleton className="h-9 w-48" />
        <CardGrid label={t("page.loading")}>
          {Array.from({length: 6}, (_, i) => (
            <Skeleton key={i} className="h-40 w-full" />
          ))}
        </CardGrid>
      </div>
    );
  }

  const addButton = (
    <PrimaryButton size="sm" isDisabled={readOnly} aria-label={t("page.addAria", {name: profile.name})} onPress={() => dialog.open(serviceDialogValue({kind: "choose"}))}>
      <Icon name="plus" className="size-4" />
      {t("page.add")}
    </PrimaryButton>
  );

  return (
    <div data-screen="profile-services" ref={root} className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium" aria-live="polite">
          {p("services.title")} <span className="text-muted font-normal">{t("page.summary", {count: own.data.length})}</span>
        </h2>
        {own.data.length === 0 && !readOnly ? null : addButton}
      </div>

      {own.data.length === 0 ? (
        <SectionEmpty icon="services" title={t("page.emptyTitle")} description={t("page.emptyText")} action={readOnly ? undefined : addButton} />
      ) : (
        <>
          <SearchField aria-label={t("page.searchLabel")} value={query} onChange={setQuery} className="max-w-sm">
            <SearchField.Group>
              <SearchField.SearchIcon>
                <Icon name="search" className="size-4" />
              </SearchField.SearchIcon>
              <SearchField.Input placeholder={t("page.search")} />
              <SearchField.ClearButton />
            </SearchField.Group>
          </SearchField>
          {groups.length === 0 ? (
            <p className="text-muted py-3 text-sm" role="status">
              {t("page.noMatch")}
            </p>
          ) : (
            <div className="flex flex-col gap-6" role="group" aria-label={t("page.sections")}>
              {groups.map((group) => {
                const categoryName = catalogName(group.category, locale);
                return (
                  <section key={group.category.id} data-category={group.category.id} aria-label={categoryName} className="flex flex-col gap-2">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="flex items-center gap-2 text-sm font-medium">
                        {categoryName}
                        <Chip size="sm" variant="soft">
                          <Chip.Label>{format.number(group.items.length)}</Chip.Label>
                        </Chip>
                      </h3>
                      <Button
                        size="sm"
                        variant="ghost"
                        isDisabled={readOnly}
                        aria-label={t("category.removeAllAria", {category: categoryName})}
                        onPress={() => setConfirming(everything.find((g) => g.category.id === group.category.id) ?? group)}
                      >
                        {t("category.removeAll")}
                      </Button>
                    </div>
                    {limitOf(group.category.id) > 0 ? (
                      <CardGrid label={t("page.gridLabel", {category: categoryName})} columns="wide">
                        {group.items.slice(0, limitOf(group.category.id)).map((item) => (
                          <ServiceCard
                            key={item.row.slug}
                            item={item}
                            readOnly={readOnly}
                            hasDestination={hasDestination && (ownDestination.get(item.row.slug) ?? true)}
                            onToggle={onToggle}
                            onAction={onAction}
                            onOpenDestination={onOpenDestination}
                            onRemove={onRemove}
                          />
                        ))}
                      </CardGrid>
                    ) : null}
                    {group.items.length > limitOf(group.category.id) ? (
                      <Button
                        size="sm"
                        variant="tertiary"
                        className="self-center"
                        aria-label={t("category.showMoreAria", {category: categoryName, count: Math.min(CARDS_PER_STEP, group.items.length - limitOf(group.category.id))})}
                        onPress={() => {
                          const from = limitOf(group.category.id);
                          setDrawn((prev) => new Map(prev).set(group.category.id, from + CARDS_PER_STEP));
                          focusAt.current = {category: group.category.id, index: from};
                        }}
                      >
                        {t("category.showMore", {count: Math.min(CARDS_PER_STEP, group.items.length - limitOf(group.category.id))})}
                      </Button>
                    ) : null}
                  </section>
                );
              })}
            </div>
          )}
        </>
      )}

      <ChooseServiceDialog profileId={profileId} isOpen={parsed?.kind === "choose" && !readOnly} onClose={dialog.close} />

      <DestinationsDialog
        isOpen={parsed?.kind === "destination" && target !== undefined && !readOnly}
        onClose={() => {
          setSaveError(null);
          dialog.close();
        }}
        source={{profileId, slugs: target ? [target.slug] : []}}
        subject={targetName}
        value={target?.target}
        isSaving={set.isPending}
        error={saveError}
        onSave={(next) => {
          if (!target) return;
          setSaveError(null);
          void set.mutateAsync({profileId, slug: target.slug, enabled: target.enabled, action: "redirect", target: next}).then(
            () => dialog.close(),
            (error: unknown) => setSaveError(error),
          );
        }}
      />

      <AlertDialog.Backdrop isOpen={confirming !== null} onOpenChange={(open) => !open && !batch.isPending && setConfirming(null)}>
        <AlertDialog.Container placement="center">
          <AlertDialog.Dialog className="sm:max-w-[400px]">
            <AlertDialog.CloseTrigger aria-label={c("close")} />
            {confirming ? (
              <>
                <AlertDialog.Header>
                  <AlertDialog.Icon status="danger">
                    <Icon name="trash" className="size-5" />
                  </AlertDialog.Icon>
                  <AlertDialog.Heading>{t("category.confirmTitle", {category: catalogName(confirming.category, locale)})}</AlertDialog.Heading>
                </AlertDialog.Header>
                <AlertDialog.Body>
                  <p>{t("category.confirmText", {count: confirming.items.length})}</p>
                </AlertDialog.Body>
                <AlertDialog.Footer>
                  <Button slot="close" variant="tertiary" isDisabled={batch.isPending}>
                    {c("cancel")}
                  </Button>
                  <Button
                    variant="danger"
                    isPending={batch.isPending}
                    onPress={() => {
                      const slugs = confirming.items.map((i) => i.row.slug);
                      batch.mutate(
                        {profileId, op: "delete", slugs},
                        {
                          onSuccess: () => {
                            toast.success(t("category.removedAll", {count: slugs.length}));
                            setConfirming(null);
                          },
                          onError: (error) => {
                            fail(error);
                            setConfirming(null);
                          },
                        },
                      );
                    }}
                  >
                    {t("category.confirm")}
                  </Button>
                </AlertDialog.Footer>
              </>
            ) : null}
          </AlertDialog.Dialog>
        </AlertDialog.Container>
      </AlertDialog.Backdrop>
    </div>
  );
}
