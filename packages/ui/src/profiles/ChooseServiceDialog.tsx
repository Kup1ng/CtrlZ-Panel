"use client";

import {Alert, Button, Checkbox, Chip, Description, Label, ListBox, ListLayout, SearchField, Skeleton, toast, Virtualizer} from "@heroui/react";
import {useBatchProfileServices, useCatalogServices, useProfileServices, type CatalogService} from "@ctrlz/api-client/hooks/services.ts";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {ServiceLogo} from "@ctrlz/icons/ServiceLogo.tsx";
import {useLocale, useTranslations} from "next-intl";
import {useMemo, useState, type ReactNode} from "react";

import {ThreeStateControl} from "../controls/ThreeStateControl.tsx";
import type {Action} from "../controls/threeState.ts";
import {DestinationsFields, useDestinationDraft, useTargetName, withLocation} from "../destinations/DestinationsDialog.tsx";
import {EMPTY_DRAFT, targetFits} from "../destinations/destinations.ts";
import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {useWriteErrorText} from "../feedback/useWriteErrorText.ts";
import {catalogName} from "./filtersModel.ts";
import {categoryCheck, chooseGroups, riskyOf, selectionNeverProxied, toggleCategory, type ChooseGroup} from "./servicesModel.ts";
import {TargetMark} from "./TargetMark.tsx";
import {useSelectionLocations} from "./useSelectionLocations.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec p2 9.4, WF "Services" (T-164, T-165, T-166, T-521): Choose Service, `serviceDialog=choose`.
//
//   search, then the categories with a count and a check box, each opening to its services; at the bottom the three-state action and Add.
//
// The services the profile already has are not listed, and the count of a category drops by them. A category holds up to 320 services (Video),
// so its services are a virtualised `ListBox`: a few rows are in the page at any time (FE 8.10). Redirect asks for a destination in a second
// step that offers only the locations every selected service can reach, and is not offered at all when one of them is never proxied. A
// service with the risk flag asks Enable Anyway in a third step before anything is written.
//
// The three steps are one dialog and one state, which is gone when the dialog closes: nothing of it is a URL parameter but the dialog itself.

const ROW_HEIGHT = 52;
// The height of a list of 1 to 6 rows, as classes the stylesheet knows: a short category is not padded and a long one scrolls inside itself.
const LIST_HEIGHT = ["h-[52px]", "h-[104px]", "h-[156px]", "h-[208px]", "h-[260px]", "h-[312px]"] as const;

type Step = "choose" | "destination" | "risk";

export function ChooseServiceDialog({profileId, isOpen, onClose}: {profileId: string; isOpen: boolean; onClose: () => void}) {
  // Mounted only while open, so each opening starts with nothing selected and the first step.
  return isOpen ? <ChooseServiceContent profileId={profileId} onClose={onClose} /> : null;
}

const fold = (text: string) => normalizeFaSearch(text).toLocaleLowerCase();

function ChooseServiceContent({profileId, onClose}: {profileId: string; onClose: () => void}) {
  const t = useTranslations("services");
  const c = useTranslations("common");
  const locale = useLocale();
  const format = useAppFormat();
  const targetName = useTargetName();
  const catalog = useCatalogServices();
  const own = useProfileServices(profileId);
  const batch = useBatchProfileServices();
  const writeText = useWriteErrorText();

  const [step, setStep] = useState<Step>("choose");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  // A search opens every category by itself; `shut` holds the ones the person closed meanwhile, and is forgotten when the search changes.
  const [shut, setShut] = useState<ReadonlySet<string>>(new Set());
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [action, setAction] = useState<Action>("block");
  const [error, setError] = useState<unknown>(null);
  // The destination was taken back because the selection changed under it (see below), and the person is told once.
  const [dropped, setDropped] = useState(false);
  // The names of the services of the refused request, in the order sent: a field `/slugs/3` of the answer is the fourth of them.
  const [errorNames, setErrorNames] = useState<readonly string[]>([]);
  const destination = useDestinationDraft();

  const services = catalog.data?.services;
  const categories = catalog.data?.categories;
  const groups = useMemo(
    () =>
      services && categories && own.data
        ? chooseGroups({categories, catalogue: services, inProfile: new Set(own.data.map((r) => r.slug)), locale, query, fold, compare: format.compare})
        : [],
    [services, categories, own.data, locale, query, format],
  );

  const slugs = useMemo(() => [...selected], [selected]);
  const chosen = useMemo(() => (services ?? []).filter((s) => selected.has(s.slug)), [services, selected]);
  const neverProxied = services ? selectionNeverProxied(selected, services) : undefined;
  const risky = services ? riskyOf(selected, services) : [];
  // The catalogue's own order (by category, then slug) is the partition of the locations calls: a tick then changes one part and not every chunk after it.
  const order = useMemo(
    () =>
      new Map(
        [...(services ?? [])]
          .sort((a, b) => (a.category_id === b.category_id ? (a.slug < b.slug ? -1 : 1) : a.category_id < b.category_id ? -1 : 1))
          .map((s, i) => [s.slug, i] as const),
      ),
    [services],
  );
  const where = useSelectionLocations(profileId, slugs, true, order);
  const target = destination.target;
  // The answer for the selection that is on screen. Until it settles, what was chosen is neither kept nor taken away.
  const answered = !where.isPending && !where.error;
  const fits = target !== null && targetFits(target, where);
  const redirectReady = action !== "redirect" || (target !== null && answered && fits && neverProxied === undefined);

  // A Redirect that the selection cannot take any more goes back to Block (T-521, T-166): a service that is never proxied came in, or the chosen
  // destination left the set that every selected service can reach. The API would refuse the batch (`iranian_name`, `location_not_allowed`), so the
  // screen does not offer it. State set while rendering, as React documents it, and it settles at once because the action is no longer redirect.
  if (action === "redirect" && (neverProxied !== undefined || (answered && !fits))) {
    setAction("block");
    if (neverProxied === undefined) {
      destination.setDraft(EMPTY_DRAFT);
      setDropped(true);
    }
  }

  const submit = (confirmedRisk: boolean) => {
    if (slugs.length === 0 || !redirectReady) return;
    if (!confirmedRisk && risky.length > 0) {
      setStep("risk");
      return;
    }
    setError(null);
    const names = slugs.map((slug) => {
      const service = services?.find((x) => x.slug === slug);
      return service ? catalogName(service, locale) : slug;
    });
    batch
      .mutateAsync(
        action === "redirect" && target
          ? {profileId, op: "set", slugs, enabled: true, action, target}
          : {profileId, op: "set", slugs, enabled: true, action: action === "inherit" ? "block" : action},
      )
      .then(
        () => {
          toast.success(t("choose.added", {count: slugs.length}));
          onClose();
        },
        (e: unknown) => {
          setError(e);
          setErrorNames(names);
          setStep("choose");
        },
      );
  };

  const pickAction = (next: Action) => {
    setDropped(false);
    if (next === "redirect" && target === null) {
      setStep("destination");
      return;
    }
    setAction(next);
  };

  const searching = query.trim() !== "";
  const expanded = (id: string) => (searching ? !shut.has(id) : open.has(id));
  const toggleOpen = (id: string) => {
    const flip = (current: ReadonlySet<string>) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    };
    if (searching) setShut(flip);
    else setOpen(flip);
  };
  const setCategory = (group: ChooseGroup, keys: ReadonlySet<string>) =>
    setSelected((prev) => {
      const next = new Set(prev);
      for (const s of group.services) next.delete(s.slug);
      for (const k of keys) next.add(k);
      return next;
    });

  let title = t("choose.title");
  let body: ReactNode;
  let footer: ReactNode;

  if (step === "destination") {
    title = t("choose.destinationTitle");
    body = where.isPending ? (
      <div role="status" className="flex flex-col gap-2">
        <Skeleton className="h-9 w-full" />
        <Skeleton className="h-9 w-full" />
        <Skeleton className="h-9 w-full" />
      </div>
    ) : where.error ? (
      <SectionError error={where.error} />
    ) : (
      <DestinationsFields
        draft={destination.draft}
        onChange={destination.setDraft}
        source={{locations: where.locations, autoRandom: where.autoRandom}}
        subject={t("choose.actionSubject")}
      />
    );
    footer = (
      <div className="flex w-full flex-wrap items-center justify-end gap-2">
        <Button variant="tertiary" onPress={() => setStep("choose")}>
          {t("choose.backToChoose")}
        </Button>
        <PrimaryButton
          isDisabled={target === null}
          onPress={() => {
            setAction("redirect");
            setStep("choose");
          }}
        >
          {t("choose.useDestination")}
        </PrimaryButton>
      </div>
    );
  } else if (step === "risk") {
    title = t("risk.title");
    body = (
      <div className="flex flex-col gap-3">
        <Alert status="warning">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("risk.text")}</Alert.Description>
          </Alert.Content>
        </Alert>
        <ul className="flex flex-col gap-1 text-sm">
          {risky.map((s) => (
            <li key={s.slug} className="flex items-center gap-2">
              <ServiceLogo slug={s.slug} name={catalogName(s, locale)} className="size-8" />
              <span className="min-w-0 truncate">{catalogName(s, locale)}</span>
            </li>
          ))}
        </ul>
      </div>
    );
    footer = (
      <div className="flex w-full flex-wrap items-center justify-end gap-2">
        <Button variant="tertiary" isDisabled={batch.isPending} onPress={() => setStep("choose")}>
          {t("risk.back")}
        </Button>
        <PrimaryButton isPending={batch.isPending} onPress={() => submit(true)}>
          {t("risk.enableAnyway")}
        </PrimaryButton>
      </div>
    );
  } else {
    body = (
      <div className="flex flex-col gap-3">
        <SearchField
          aria-label={t("choose.searchLabel")}
          value={query}
          onChange={(next) => {
            setQuery(next);
            setShut(new Set());
          }}
        >
          <SearchField.Group>
            <SearchField.SearchIcon>
              <Icon name="search" className="size-4" />
            </SearchField.SearchIcon>
            <SearchField.Input placeholder={t("choose.search")} />
            <SearchField.ClearButton />
          </SearchField.Group>
        </SearchField>
        {catalog.isError || own.isError ? (
          <SectionError error={catalog.error ?? own.error} onRetry={() => void Promise.all([catalog.refetch(), own.refetch()])} />
        ) : !services || !own.data ? (
          <div role="status" aria-label={t("choose.loading")} className="flex flex-col gap-2">
            {Array.from({length: 5}, (_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : groups.length === 0 ? (
          query.trim() === "" ? (
            <SectionEmpty icon="services" title={t("choose.allAdded")} description={t("choose.allAddedText")} />
          ) : (
            <p className="text-muted py-3 text-sm" role="status">
              {t("choose.noMatch")}
            </p>
          )
        ) : (
          <ul aria-label={t("choose.categories")} className="flex flex-col gap-1">
            {groups.map((group) => {
              const name = catalogName(group.category, locale);
              const groupSlugs = group.services.map((s) => s.slug);
              const check = categoryCheck(selected, groupSlugs);
              const isOpen = expanded(group.category.id);
              return (
                <li key={group.category.id} data-category={group.category.id} className="flex flex-col">
                  <div className="flex items-center gap-1">
                    <Checkbox
                      // While a search runs the category holds only what it found, and the name says so.
                      aria-label={searching ? t("choose.selectMatching", {category: name}) : t("choose.selectCategory", {category: name})}
                      isSelected={check === "all"}
                      isIndeterminate={check === "some"}
                      onChange={() => setSelected((prev) => toggleCategory(prev, groupSlugs))}
                    >
                      <Checkbox.Content>
                        <Checkbox.Control>
                          <Checkbox.Indicator />
                        </Checkbox.Control>
                      </Checkbox.Content>
                    </Checkbox>
                    <Button
                      variant="ghost"
                      className="min-w-0 flex-1 justify-between"
                      aria-expanded={isOpen}
                      // One name for both states, and it starts with the text on the button (WCAG 2.5.3); `aria-expanded` says open or shut.
                      aria-label={t("choose.toggle", {category: name, count: group.services.length})}
                      onPress={() => toggleOpen(group.category.id)}
                    >
                      <span className="truncate">{name}</span>
                      <span className="flex items-center gap-2">
                        <Chip size="sm" variant="soft">
                          <Chip.Label>{t("choose.count", {count: group.services.length})}</Chip.Label>
                        </Chip>
                        <Icon name="chevron" className={isOpen ? "size-4 rotate-90" : "size-4 rtl:rotate-180"} />
                      </span>
                    </Button>
                  </div>
                  {isOpen ? <CategoryList group={group} name={name} selected={selected} onChange={(keys) => setCategory(group, keys)} locale={locale} /> : null}
                </li>
              );
            })}
          </ul>
        )}
        {error ? <SectionError error={error} text={writeText(error, errorNames)} /> : null}
      </div>
    );
    footer = (
      <div className="flex w-full flex-col gap-3">
        <ThreeStateControl
          value={action}
          onChange={pickAction}
          subject={t("choose.actionSubject")}
          redirectAllowed={neverProxied === undefined}
          hasDestination={where.hasDestination}
          destination={action === "redirect" ? <TargetMark target={target} /> : undefined}
          destinationName={action === "redirect" && target ? targetName(withLocation(target, where.locations)) : undefined}
          onOpenDestination={() => setStep("destination")}
          noSharedText={t("choose.noShared")}
          isDisabled={batch.isPending}
        />
        {where.error ? (
          // The answer failed, so the set is unknown and Redirect stays as it was; Add waits for a Redirect that cannot be checked.
          <div className="flex flex-wrap items-center gap-2" role="status">
            <p className="text-muted flex min-w-0 flex-1 items-start gap-1 text-xs">
              <Icon name="warning" className="mt-0.5 size-3.5 shrink-0" />
              <span>{t("choose.locationsFailed")}</span>
            </p>
            <Button size="sm" variant="tertiary" onPress={where.retry}>
              {t("choose.retryLocations")}
            </Button>
          </div>
        ) : null}
        {neverProxied ? <p className="text-muted text-xs">{t("choose.neverProxied", {name: catalogName(neverProxied, locale)})}</p> : null}
        {dropped && action !== "redirect" ? (
          <p className="text-muted text-xs" role="status">
            {t("choose.destinationDropped")}
          </p>
        ) : null}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-muted min-w-0 flex-1 text-xs" role="status">
            {chosen.length > 0 ? t("choose.selected", {count: chosen.length}) : t("choose.nothing")}
          </p>
          <div className="flex items-center gap-2">
            <Button variant="tertiary" isDisabled={batch.isPending} onPress={onClose}>
              {c("cancel")}
            </Button>
            <PrimaryButton isDisabled={slugs.length === 0 || !redirectReady} isPending={batch.isPending} onPress={() => submit(false)}>
              {slugs.length > 0 ? t("choose.addCount", {count: slugs.length}) : t("choose.add")}
            </PrimaryButton>
          </div>
        </div>
      </div>
    );
  }

  return (
    <DialogFrame isOpen onClose={onClose} isLocked={batch.isPending} title={title} footer={footer}>
      {body}
    </DialogFrame>
  );
}

function CategoryList({group, name, selected, onChange, locale}: {group: ChooseGroup; name: string; selected: ReadonlySet<string>; onChange: (keys: ReadonlySet<string>) => void; locale: string}) {
  const t = useTranslations("services");
  const keys = useMemo(() => new Set(group.services.filter((s) => selected.has(s.slug)).map((s) => s.slug)), [group.services, selected]);
  const height = LIST_HEIGHT[Math.min(group.services.length, LIST_HEIGHT.length) - 1]!;
  return (
    <Virtualizer layout={ListLayout} layoutOptions={{rowHeight: ROW_HEIGHT}}>
      <ListBox
        aria-label={t("choose.list", {category: name})}
        items={group.services}
        selectionMode="multiple"
        selectedKeys={keys}
        onSelectionChange={(next) => onChange(next === "all" ? new Set(group.services.map((s) => s.slug)) : new Set([...next].map(String)))}
        className={["overflow-y-auto", height].join(" ")}
      >
        {(s: CatalogService) => {
          const label = catalogName(s, locale);
          const note = [s.risk_flag ? t("choose.riskFlag") : null, s.region_limited ? t("choose.regionLimited") : null].filter(Boolean).join(" · ");
          return (
            <ListBox.Item id={s.slug} textValue={label}>
              <ServiceLogo slug={s.slug} name={label} className="size-8" />
              <div className="flex min-w-0 flex-1 flex-col">
                <Label className="truncate">{label}</Label>
                {note ? <Description className="truncate">{note}</Description> : null}
              </div>
              <ListBox.ItemIndicator />
            </ListBox.Item>
          );
        }}
      </ListBox>
    </Virtualizer>
  );
}
