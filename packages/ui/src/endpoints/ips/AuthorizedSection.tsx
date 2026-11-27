"use client";

import {copyPlainText} from "@ctrlz/api-client/clipboard.ts";
import {useAuthorizedIps, usePatchAuthorizedIp, type AuthorizedIP} from "@ctrlz/api-client/hooks/clients.ts";
import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Checkbox, Chip, Dropdown, Label, SearchField, Skeleton, Switch, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useCallback, useEffect, useMemo, useState} from "react";

import {SelectionBar} from "../../controls/SelectionBar.tsx";
import {useListSelection} from "../../controls/useListSelection.ts";
import {ListRow, ListRowSkeleton} from "../../data/ListRow.tsx";
import {Tech} from "../../data/Tech.tsx";
import {VirtualRows} from "../../data/VirtualRows.tsx";
import {needsMore, type Window} from "../../data/virtualWindow.ts";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {useMediaQuery} from "../clients/useMediaQuery.ts";
import {MAX_BATCH_IDS} from "../endpointModel.ts";
import {Cancelled, useGuardedWrite} from "../useGuardedWrite.tsx";
import {DeleteAuthorizedDialog} from "./AuthorizedDialogs.tsx";
import {emptiesRequire, protectionOf, type Protection} from "./ipModel.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// The Authorized IPs of an Endpoint (spec p3 5, 10; T-262, T-263): when each was added or last seen, the address or subnet, its city and
// ISP when known, a search, a copy button, add, and delete one or several. Two addresses are protected: the one this browser reaches the panel
// from, and, while Require Authorized IPs is on, the last one left. Their delete is off and says why in words next to the address.

const PITCH = {wide: 84, narrow: 116} as const;
const GAP = 8;

export function AuthorizedSection({endpoint, onAdd}: {endpoint: Endpoint; onAdd: () => void}) {
  const t = useTranslations("endpoints");
  const format = useAppFormat();
  const sel = useListSelection();
  const patch = usePatchAuthorizedIp();
  const guarded = useGuardedWrite();
  const [queryText, setQueryText] = useState("");
  const [q, setQ] = useState("");
  const [deleting, setDeleting] = useState<AuthorizedIP[] | null>(null);
  const wide = useMediaQuery("(min-width: 1280px)");

  useEffect(() => {
    const timer = setTimeout(() => setQ(queryText.trim()), 250);
    return () => clearTimeout(timer);
  }, [queryText]);

  const list = useAuthorizedIps(endpoint.id, q ? {q} : {});
  const rows = list.rows;
  const complete = !list.hasNextPage && !list.isError;
  const requireOn = endpoint.require_authorized_ips;
  // Only an unfiltered, fully loaded list knows the Endpoint's whole count; a search or an unread page leaves "the last one" to the server.
  const total = q || !complete ? Number.POSITIVE_INFINITY : rows.length;
  const pitch = (wide ? PITCH.wide : PITCH.narrow) + GAP;

  const loadedIds = useMemo(() => rows.map((r) => r.id), [rows]);
  const protectionById = useMemo(() => new Map(rows.map((r) => [r.id, protectionOf(r, requireOn, total, true)])), [rows, requireOn, total]);
  const {reconcile} = sel;
  useEffect(() => {
    reconcile([], true);
  }, [q, reconcile]);
  useEffect(() => {
    if (!list.isPending && !list.isError) reconcile(loadedIds, false);
  }, [loadedIds, list.isPending, list.isError, reconcile]);

  const fetchNext = list.fetchNextPage;
  const hasNext = list.hasNextPage;
  const fetching = list.isFetchingNextPage;
  const onWindow = useCallback(
    (w: Window) => {
      if (needsMore(w, rows.length, hasNext) && !fetching) void fetchNext();
    },
    [rows.length, hasNext, fetching, fetchNext],
  );

  const selected = rows.filter((r) => sel.isSelected(r.id)).slice(0, MAX_BATCH_IDS);
  const toggle = useCallback((id: string) => sel.toggle(id, loadedIds), [sel, loadedIds]);

  async function setCleanup(row: AuthorizedIP, on: boolean) {
    try {
      await guarded.run((extra) => patch.mutateAsync({endpointId: endpoint.id, ipId: row.id, cleanupOptIn: on, ...(extra.lock_passwords ? {lockPasswords: extra.lock_passwords} : {})}), [endpoint], {takesAll: endpoint.require_authorized_ips && on, reset: patch.reset});
    } catch (error) {
      if (!(error instanceof Cancelled)) toast.danger(t("ips.authorized.cleanupFailed"));
    }
  }

  async function copy(row: AuthorizedIP) {
    try {
      await copyPlainText(row.cidr);
      toast.success(t("ips.authorized.copied"));
    } catch {
      toast.danger(t("ips.authorized.copyFailed"));
    }
  }

  const noRows = !list.isPending && !list.isError && rows.length === 0;
  let body;
  if (list.isError && rows.length === 0) body = <SectionError error={list.error} onRetry={() => void list.refetch()} />;
  else if (list.isPending)
    body = (
      <div role="status" aria-label={t("ips.authorized.loading")} className="flex flex-col gap-2">
        <ListRowSkeleton />
        <ListRowSkeleton />
      </div>
    );
  else if (noRows && q) body = <SectionEmpty icon="shield" title={t("ips.authorized.emptyFiltered")} />;
  else if (noRows)
    body = (
      <SectionEmpty
        icon="shield"
        title={t("ips.authorized.empty")}
        description={t("ips.authorized.emptyText")}
        action={
          <PrimaryButton onPress={onAdd}>
            <Icon name="plus" className="size-4" />
            {t("ips.authorized.add")}
          </PrimaryButton>
        }
      />
    );
  else
    body = (
      <VirtualRows
        label={t("ips.authorized.listLabel")}
        count={rows.length}
        pitch={pitch}
        className="authorized-list max-h-[60vh] min-h-40"
        onWindow={onWindow}
        footer={fetching ? <Skeleton className="mx-auto my-2 h-6 w-32" /> : null}
        renderRow={(index, place) => {
          const row = rows[index]!;
          return (
            <div key={row.id} role="none" data-index={place.index} style={{...place.style, height: pitch - GAP}}>
              <AuthorizedRow
                row={row}
                protection={protectionById.get(row.id) ?? null}
                selecting={sel.selecting}
                selected={sel.isSelected(row.id)}
                onToggle={toggle}
                onCopy={copy}
                onDelete={(r) => setDeleting([r])}
                onCleanup={setCleanup}
                format={format}
              />
            </div>
          );
        }}
      />
    );

  return (
    <section aria-labelledby="authorized-title" className="flex flex-col gap-3" data-testid="authorized-section">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1">
          <h2 id="authorized-title" className="text-base font-medium">
            {t("ips.authorized.title")}
          </h2>
          <p className="text-muted text-sm">{requireOn ? t("ips.authorized.requireOn") : t("ips.authorized.text")}</p>
        </div>
        <PrimaryButton size="sm" onPress={onAdd}>
          <Icon name="plus" className="size-4" />
          {t("ips.authorized.add")}
        </PrimaryButton>
        <Dropdown>
          <Button isIconOnly size="sm" variant="outline" aria-label={t("ips.authorized.menu")}>
            <Icon name="more" className="size-4" />
          </Button>
          <Dropdown.Popover placement="bottom end">
            <Dropdown.Menu aria-label={t("ips.authorized.menu")} disabledKeys={rows.length === 0 ? ["select"] : []} onAction={() => sel.enter()}>
              <Dropdown.Item id="select" textValue={t("ips.authorized.select")}>
                <Icon name="check" className="size-4 shrink-0" />
                <Label>{t("ips.authorized.select")}</Label>
              </Dropdown.Item>
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown>
      </div>
      <SearchField aria-label={t("ips.authorized.searchLabel")} value={queryText} onChange={setQueryText} className="max-w-sm">
        <SearchField.Group>
          <SearchField.SearchIcon>
            <Icon name="search" className="size-4" />
          </SearchField.SearchIcon>
          <SearchField.Input placeholder={t("ips.authorized.search")} />
          <SearchField.ClearButton />
        </SearchField.Group>
      </SearchField>

      {sel.selecting ? (
        <SelectionBar
          count={selected.length}
          total={rows.length}
          onClear={sel.exit}
          actions={[{id: "delete", label: t("ips.authorized.deleteSelected"), icon: "trash", variant: "danger", isDisabled: selected.length === 0, onPress: () => setDeleting(selected)}]}
        />
      ) : null}

      {body}

      {deleting ? (
        <DeleteAuthorizedDialog
          endpoint={endpoint}
          rows={deleting}
          wouldEmpty={emptiesRequire(requireOn, total, true, deleting.length)}
          onClose={() => setDeleting(null)}
          onDone={sel.exit}
        />
      ) : null}
      {guarded.dialogs}
    </section>
  );
}

function AuthorizedRow({
  row,
  protection,
  selecting,
  selected,
  onToggle,
  onCopy,
  onDelete,
  onCleanup,
  format,
}: {
  row: AuthorizedIP;
  protection: Protection;
  selecting: boolean;
  selected: boolean;
  onToggle: (id: string) => void;
  onCopy: (row: AuthorizedIP) => void;
  onDelete: (row: AuthorizedIP) => void;
  onCleanup: (row: AuthorizedIP, on: boolean) => void;
  format: ReturnType<typeof useAppFormat>;
}) {
  const t = useTranslations("endpoints");
  const why = protection === "current" ? t("ips.authorized.currentWhy") : protection === "last" ? t("ips.authorized.lastWhy") : null;
  const place = [row.city, row.isp].filter(Boolean).join(" · ");
  const seen = row.last_seen_at ? t("ips.authorized.lastSeen", {when: format.relative(row.last_seen_at)}) : t("ips.authorized.added", {when: format.dateTime(row.created_at)});
  const reasonId = `why-${row.id}`;

  return (
    <ListRow
      className="h-full! min-h-0!"
      roomy
      icon={<Icon name="shield" className="size-5" />}
      title={
        <span className="flex min-w-0 items-center gap-2">
          <Tech className="truncate text-sm">{row.cidr}</Tech>
          {protection === "current" ? (
            <Chip size="sm" variant="soft" color="accent">
              <Chip.Label>{t("ips.authorized.currentChip")}</Chip.Label>
            </Chip>
          ) : null}
          {protection === "last" ? (
            <Chip size="sm" variant="soft" color="warning">
              <Chip.Label>{t("ips.authorized.lastChip")}</Chip.Label>
            </Chip>
          ) : null}
        </span>
      }
      subtitle={
        <>
          <span>{t(`ips.authorized.source.${row.source}`)}</span>
          {place ? <span> · {place}</span> : null}
          <span> · {seen}</span>
          {why ? (
            <span id={reasonId} className="sr-only">
              {" "}
              {why}
            </span>
          ) : null}
        </>
      }
      isHighlighted={selected}
      leading={
        selecting ? (
          <Checkbox aria-label={t("ips.authorized.selectAria", {cidr: row.cidr})} isSelected={selected} isDisabled={protection !== null} onChange={() => onToggle(row.id)}>
            <Checkbox.Content>
              <Checkbox.Control>
                <Checkbox.Indicator />
              </Checkbox.Control>
            </Checkbox.Content>
          </Checkbox>
        ) : undefined
      }
      onPress={selecting && protection === null ? () => onToggle(row.id) : undefined}
      counters={
        row.source === "manual" && !selecting ? (
          <Switch size="sm" isSelected={row.cleanup_opt_in} onChange={(on) => onCleanup(row, on)} aria-label={t("ips.authorized.cleanupAria", {cidr: row.cidr})}>
            <Switch.Control>
              <Switch.Thumb />
            </Switch.Control>
            <Switch.Content>
              <Label className="text-xs">{t("ips.authorized.cleanup")}</Label>
            </Switch.Content>
          </Switch>
        ) : undefined
      }
      trailing={
        selecting ? undefined : (
          <div className="flex items-center gap-1">
            <Button isIconOnly size="sm" variant="ghost" aria-label={t("ips.authorized.copyAria", {cidr: row.cidr})} onPress={() => onCopy(row)}>
              <Icon name="copy" className="size-4" />
            </Button>
            <Button
              isIconOnly
              size="sm"
              variant="ghost"
              isDisabled={protection !== null}
              aria-label={t("ips.authorized.deleteAria", {cidr: row.cidr})}
              aria-describedby={why ? reasonId : undefined}
              onPress={() => onDelete(row)}
            >
              <Icon name="trash" className="size-4" />
            </Button>
          </div>
        )
      }
    />
  );
}
