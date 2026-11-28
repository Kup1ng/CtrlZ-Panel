"use client";

import {Button, Description, FieldError, Input, Label, Radio, RadioGroup, SearchField, Spinner, TextField, ToggleButton, ToggleButtonGroup} from "@heroui/react";
import {Segment} from "@heroui-pro/react";
import {useProfileLocations, type LocationRef} from "@ctrlz/api-client/hooks/profiles.ts";
import type {Target} from "@ctrlz/api-client/hooks/services.ts";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Flag} from "@ctrlz/icons/Flag.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useMemo, useState, type ReactNode} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {useWriteErrorText} from "../feedback/useWriteErrorText.ts";
import {
  draftOf,
  draftProblems,
  EMPTY_DRAFT,
  filterGroups,
  groupLocations,
  targetOf,
  type CountryGroup,
  type DestinationDraft,
} from "./destinations.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec p2 9.5, WF "Destinations". One dialog for the services (`serviceDialog=destination:<slug>`), the rules (a step of the rule dialog)
// and the Default Rule (`profileDialog=default-rule`): pill tabs Proxies and IP or Hostname.
//
//   Proxies: search; Auto and Random when the set holds at least two locations; the countries with a flag and a way to open their
//            cities; a label-only location by its label.
//   IP or Hostname: A (an IPv4, an IPv6, or both) or CNAME (a host name).
//
// The data is `GET /profiles/{id}/locations` (T-063): the set that every Endpoint using the profile can reach, and `slugs` narrows it to
// what a service (or a selection of services) can reach. A selection of more than 100 services is the caller's: it passes the
// intersection as `locations` (see `intersectLocations`) and no `profileId`.
//
// `DestinationsFields` is the body, controlled, for a step of another dialog. `DestinationsDialog` is the frame with Save.

export type DestinationsFieldsProps = {
  draft: DestinationDraft;
  onChange: (draft: DestinationDraft) => void;
  /** Where the locations come from: the API (with the profile and the services), or a set the caller already holds. */
  source: {profileId: string; slugs?: readonly string[]} | {locations: readonly LocationRef[]; autoRandom: boolean};
  /** The service, rule or option the destination is for. In the names of the controls. */
  subject: string;
};

const fold = (s: string) => normalizeFaSearch(s).toLocaleLowerCase();

function useLocationSet(source: DestinationsFieldsProps["source"]) {
  const remote = "profileId" in source;
  const query = useProfileLocations(remote ? source.profileId : undefined, remote ? (source.slugs ?? []) : [], {enabled: remote});
  if (!remote) return {locations: source.locations, autoRandom: source.autoRandom, isPending: false, error: null as unknown, refetch: () => undefined};
  return {
    locations: query.data?.locations ?? [],
    autoRandom: query.data?.auto_random ?? false,
    isPending: query.isPending,
    error: query.error as unknown,
    refetch: () => void query.refetch(),
  };
}

export function useDestinationDraft(target?: Target | null, locations: readonly LocationRef[] = []) {
  // The draft starts from the row's own destination. A location given by key is found by key in the set once the set has arrived.
  const [draft, setDraft] = useState<DestinationDraft>(() => draftOf(target, locations));
  return {draft, setDraft, target: targetOf(draft), problems: draftProblems(draft)};
}

// The anatomy of HeroUI 3.2: the control and the label are both inside Radio.Content, which is the clickable label, and a description is a
// sibling of it. (The control as a sibling of the content, as this first had it, drew the dot above the text.)
function ProxyRadio({value, name, hint, flag}: {value: string; name: string; hint?: string; flag?: ReactNode}) {
  return (
    <Radio value={value} className="destination-option w-full">
      <Radio.Content className="flex w-full min-w-0 items-center gap-2 py-1">
        <Radio.Control>
          <Radio.Indicator />
        </Radio.Control>
        {flag}
        <span className="min-w-0 flex-1 truncate text-sm">{name}</span>
      </Radio.Content>
      {hint ? <Description className="ps-7 text-xs">{hint}</Description> : null}
    </Radio>
  );
}

function CountryRow({group, open, onToggle, subject}: {group: CountryGroup; open: boolean; onToggle: () => void; subject: string}) {
  const t = useTranslations("services");
  const hasCities = group.cities.length > 0;
  return (
    <li className="flex flex-col">
      <div className="flex items-center gap-1">
        {group.whole ? (
          <ProxyRadio value={`loc:${group.whole.id}`} name={group.name} flag={group.country ? <Flag code={group.country} /> : undefined} />
        ) : (
          <div className="flex min-w-0 flex-1 items-center gap-2 px-1 py-2">
            {group.country ? <Flag code={group.country} /> : null}
            <span className="truncate text-sm">{group.name}</span>
          </div>
        )}
        {hasCities ? (
          <Button
            isIconOnly
            size="sm"
            variant="ghost"
            aria-expanded={open}
            aria-label={open ? t("destinations.hideCities", {country: group.name}) : t("destinations.showCities", {country: group.name})}
            onPress={onToggle}
          >
            <Icon name="chevron" className={open ? "size-4 rotate-90" : "size-4 rtl:rotate-180"} />
          </Button>
        ) : null}
      </div>
      {hasCities && open ? (
        <ul aria-label={t("destinations.cities", {country: group.name})} className="ms-8 flex flex-col">
          {group.cities.map((city) => (
            <li key={city.id}>
              <ProxyRadio value={`loc:${city.id}`} name={city.city ?? ""} />
            </li>
          ))}
        </ul>
      ) : null}
      <span className="sr-only">{subject}</span>
    </li>
  );
}

export function DestinationsFields({draft, onChange, source, subject}: DestinationsFieldsProps) {
  const t = useTranslations("services");
  const format = useAppFormat();
  const set = useLocationSet(source);
  const [query, setQuery] = useState("");
  // A country is open by the person's press (`open`), or by itself while a search runs or it holds the chosen city. The second kind can be
  // closed too: `shut` holds those, and is forgotten when the search changes. Without it "Hide cities" would do nothing there.
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const [shut, setShut] = useState<ReadonlySet<string>>(new Set());
  const groups = useMemo(() => groupLocations(set.locations, format.regionName, {compare: format.compare}), [set.locations, format]);
  const shown = useMemo(() => filterGroups(groups, query, fold), [groups, query]);
  const problems = draftProblems(draft);
  const patch = (next: Partial<DestinationDraft>) => onChange({...draft, ...next});
  const radioValue = draft.proxy === null ? "" : draft.proxy.kind === "location" ? `loc:${draft.proxy.id}` : draft.proxy.kind;

  return (
    <div className="flex flex-col gap-4">
      <Segment
        aria-label={t("destinations.tabsLabel")}
        selectedKey={draft.tab}
        onSelectionChange={(key) => patch({tab: key === "ip" ? "ip" : "proxies"})}
        className="self-start"
      >
        <Segment.Item id="proxies">{t("destinations.proxies")}</Segment.Item>
        <Segment.Item id="ip">{t("destinations.ip")}</Segment.Item>
      </Segment>

      {draft.tab === "proxies" ? (
        set.isPending ? (
          <p className="text-muted flex items-center gap-2 text-sm" role="status">
            <Spinner size="sm" />
            {t("destinations.loading")}
          </p>
        ) : set.error ? (
          <SectionError error={set.error} onRetry={set.refetch} />
        ) : set.locations.length === 0 && !set.autoRandom ? (
          <div className="flex flex-col gap-1 py-4 text-center" role="status">
            <p className="text-sm font-medium">{t("destinations.none")}</p>
            <p className="text-muted text-xs">{t("destinations.noneText")}</p>
          </div>
        ) : (
          <>
            <SearchField
              aria-label={t("destinations.searchLabel")}
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
                <SearchField.Input placeholder={t("destinations.search")} />
                <SearchField.ClearButton />
              </SearchField.Group>
            </SearchField>
            <RadioGroup
              aria-label={t("destinations.title", {subject})}
              value={radioValue}
              onChange={(value) => {
                if (value === "auto" || value === "random") patch({proxy: {kind: value}});
                else if (value.startsWith("loc:")) patch({proxy: {kind: "location", id: value.slice(4)}});
              }}
              className="flex flex-col gap-1"
            >
              {set.autoRandom && query.trim() === "" ? (
                <>
                  <ProxyRadio value="auto" name={t("destinations.auto")} hint={t("destinations.autoText")} />
                  <ProxyRadio value="random" name={t("destinations.random")} hint={t("destinations.randomText")} />
                </>
              ) : null}
              {shown.length === 0 ? (
                <p className="text-muted py-3 text-sm" role="status">
                  {t("destinations.noMatch")}
                </p>
              ) : (
                <ul aria-label={t("destinations.list")} className="flex flex-col">
                  {shown.map((group) => {
                    const forced = query.trim() !== "" || group.cities.some((city) => radioValue === "loc:" + city.id);
                    const flip = (current: ReadonlySet<string>) => {
                      const next = new Set(current);
                      if (next.has(group.key)) next.delete(group.key);
                      else next.add(group.key);
                      return next;
                    };
                    return group.label ? (
                      <li key={group.key}>
                        <ProxyRadio value={`loc:${group.label.id}`} name={group.name} flag={<Icon name="globe" className="size-4" />} />
                      </li>
                    ) : (
                      <CountryRow
                        key={group.key}
                        group={group}
                        subject={subject}
                        // A search that matched a city opens its country, or the match would be hidden behind a closed row.
                        open={forced ? !shut.has(group.key) : open.has(group.key)}
                        onToggle={() => (forced ? setShut(flip) : setOpen(flip))}
                      />
                    );
                  })}
                </ul>
              )}
            </RadioGroup>
          </>
        )
      ) : (
        <div className="flex flex-col gap-3">
          <ToggleButtonGroup
            aria-label={t("destinations.type")}
            selectionMode="single"
            disallowEmptySelection
            size="sm"
            selectedKeys={[draft.record]}
            onSelectionChange={(keys) => patch({record: [...keys][0] === "cname" ? "cname" : "a"})}
            className="self-start"
          >
            <ToggleButton id="a">{t("destinations.recordA")}</ToggleButton>
            <ToggleButton id="cname">
              <ToggleButtonGroup.Separator />
              {t("destinations.recordCname")}
            </ToggleButton>
          </ToggleButtonGroup>
          {draft.record === "a" ? (
            <>
              <TextField isInvalid={!!problems.v4} value={draft.v4} onChange={(v4) => patch({v4})} aria-label={t("destinations.ipv4")}>
                <Label>{t("destinations.ipv4")}</Label>
                <Input dir="ltr" inputMode="decimal" autoComplete="off" spellCheck={false} placeholder={t("destinations.ipv4Example")} />
                {problems.v4 ? <FieldError>{t(`destinations.${problems.v4}`)}</FieldError> : null}
              </TextField>
              <TextField isInvalid={!!problems.v6} value={draft.v6} onChange={(v6) => patch({v6})} aria-label={t("destinations.ipv6")}>
                <Label>{t("destinations.ipv6")}</Label>
                <Input dir="ltr" autoComplete="off" spellCheck={false} />
                {problems.v6 ? <FieldError>{t(`destinations.${problems.v6}`)}</FieldError> : null}
              </TextField>
              <p className="text-muted text-xs">{t("destinations.needOne")}</p>
            </>
          ) : (
            <TextField isInvalid={!!problems.host} value={draft.host} onChange={(host) => patch({host})} aria-label={t("destinations.host")}>
              <Label>{t("destinations.host")}</Label>
              <Input dir="ltr" autoComplete="off" spellCheck={false} />
              {problems.host ? <FieldError>{t(`destinations.${problems.host}`)}</FieldError> : null}
            </TextField>
          )}
        </div>
      )}
    </div>
  );
}

/** A destination named only by its location id, with the place that the set knows for that id, so that it can be shown in words. */
export function withLocation(target: Target, locations: readonly LocationRef[]): Target {
  if (target.kind !== "location" || target.location || !target.location_id) return target;
  const place = locations.find((l) => l.id === target.location_id);
  if (!place) return target;
  return {...target, location: {...(place.country ? {country: place.country} : {}), ...(place.city ? {city: place.city} : {}), ...(place.label ? {label: place.label} : {})}};
}

/** The words that name a target, for a row that shows where it goes: "Germany, Frankfurt", "Auto", "203.0.113.7". */
export function useTargetName() {
  const t = useTranslations("services");
  const format = useAppFormat();
  return (target: Target | null | undefined): string => {
    if (!target) return t("destinations.label.unknown");
    switch (target.kind) {
      case "auto":
        return t("destinations.label.auto");
      case "random":
        return t("destinations.label.random");
      case "ip":
        return [target.ipv4, target.ipv6].filter(Boolean).join(", ");
      case "host":
        return target.host ?? "";
      case "location": {
        const k = target.location;
        if (!k) return t("destinations.label.unknown");
        if (k.label && !k.country) return k.label;
        return [k.country ? format.regionName(k.country) : "", k.city ?? ""].filter(Boolean).join(", ");
      }
    }
  };
}

export type DestinationsDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  source: DestinationsFieldsProps["source"];
  subject: string;
  /** What the row has now. */
  value?: Target | null;
  /** Saves the destination. Returns when the write has ended; a rejection is shown in the dialog. */
  onSave: (target: Target) => Promise<unknown> | void;
  isSaving?: boolean;
  /** An error of the save, shown above the footer. */
  error?: unknown;
  /** Words the caller owes the reader before they save, drawn above the fields and told what is picked now (the Default Rule's D42 and location-change notices, T-523, T-178). */
  notice?: (picked: Target | null) => ReactNode;
};

/**
 * The dialog of the three screens. It starts from the row's own destination each time it opens (the draft is made again when
 * `isOpen` turns true), and the Save button is in the frame's fixed footer while the list scrolls inside.
 */
export function DestinationsDialog({isOpen, onClose, source, subject, value, onSave, isSaving = false, error, notice}: DestinationsDialogProps) {
  const t = useTranslations("services");
  const c = useTranslations("common");
  const name = useTargetName();
  const writeText = useWriteErrorText();
  // The set is read here as well as in the fields (the same query, so one request): a destination chosen by id is named from it in the footer.
  const set = useLocationSet(source);
  const known = "locations" in source ? source.locations : set.locations;
  const {draft, setDraft, target} = useDestinationDraft(value, known);
  // Made again on each opening: a draft left by the last visit is not the row's destination any more.
  const [wasOpen, setWasOpen] = useState(isOpen);
  if (isOpen !== wasOpen) {
    setWasOpen(isOpen);
    if (isOpen) setDraft(draftOf(value, known));
  }
  return (
    <DialogFrame
      isOpen={isOpen}
      onClose={onClose}
      isLocked={isSaving}
      title={t("destinations.title", {subject})}
      footer={
        <div className="flex w-full flex-wrap items-center justify-between gap-2">
          <p className="text-muted min-w-0 flex-1 text-xs" role="status">
            {target ? t("destinations.selected", {name: name(withLocation(target, set.locations))}) : t("destinations.nothingSelected")}
          </p>
          <div className="flex items-center gap-2">
            <Button variant="tertiary" isDisabled={isSaving} onPress={onClose}>
              {c("cancel")}
            </Button>
            <PrimaryButton isDisabled={!target || isSaving} onPress={() => target && void onSave(target)}>
              {isSaving ? c("saving") : t("destinations.save")}
            </PrimaryButton>
          </div>
        </div>
      }
    >
      <div className="flex flex-col gap-4">
        {notice ? notice(target) : null}
        <DestinationsFields draft={draft} onChange={setDraft} source={source} subject={subject} />
        {error ? <SectionError error={error} text={writeText(error)} /> : null}
      </div>
    </DialogFrame>
  );
}

export {EMPTY_DRAFT};
