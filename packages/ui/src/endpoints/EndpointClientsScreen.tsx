"use client";

// /endpoints/[id]/clients (spec p3 10, T-257 to T-259): the clients of an Endpoint grouped by group name, a Custom Client dialog
// (`deviceDialog=client`), selection and delete, delete the ones quiet for N days (with their number shown first), delete all. The list is
// a window of rows over cursor pages (FE 8.10): 1,000 clients are about twenty rows of the page.

import {useClients, type Client} from "@ctrlz/api-client/hooks/clients.ts";
import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Dropdown, Label, SearchField, Skeleton} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useCallback, useEffect, useMemo, useState} from "react";

import {SelectionBar} from "../controls/SelectionBar.tsx";
import {useListSelection} from "../controls/useListSelection.ts";
import {ListRowSkeleton} from "../data/ListRow.tsx";
import {VirtualRows} from "../data/VirtualRows.tsx";
import {needsMore, type Window} from "../data/virtualWindow.ts";
import {useDeviceDialog} from "../dialog/useDeviceDialog.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {ClientDeleteDialog, type DeleteMode} from "./clients/ClientDeleteDialog.tsx";
import {ClientDialog} from "./clients/ClientDialog.tsx";
import {ClientRow} from "./clients/ClientRow.tsx";
import {itemsOf} from "./clients/clientsModel.ts";
import {useMediaQuery} from "./clients/useMediaQuery.ts";
import {useEndpointFrame} from "./EndpointFrameContext.tsx";
import {MAX_BATCH_IDS} from "./endpointModel.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Row heights: the wrapper has a fixed height so the window can place rows by index. A narrow page draws a row in two lines and needs more.
const PITCH = {wide: 84, narrow: 116} as const;
const GAP = 8;
// A group header is one line of text, so its slot is not the height of a client row (it left a blank band around the text). It sits at the
// foot of its slot, close to the clients it names, with room above it that parts it from the group before.
const HEADER_SLOT = 52;

export function EndpointClientsScreen({endpointId}: {endpointId: string}) {
  void endpointId;
  const t = useTranslations("endpoints");
  const format = useAppFormat();
  const {endpoint} = useEndpointFrame();
  const devices = useDeviceDialog();
  const profiles = useProfiles();
  const sel = useListSelection();
  const [queryText, setQueryText] = useState("");
  const [q, setQ] = useState("");
  const [editing, setEditing] = useState<Client | null>(null);
  const [deleting, setDeleting] = useState<DeleteMode | null>(null);
  const wide = useMediaQuery("(min-width: 1280px)");

  useEffect(() => {
    const timer = setTimeout(() => setQ(queryText.trim()), 250);
    return () => clearTimeout(timer);
  }, [queryText]);

  const list = useClients(endpoint.id, q ? {q} : {});
  const everything = useClients(endpoint.id, {});
  const clients = list.clients;
  const items = useMemo(() => itemsOf(clients, format.compare), [clients, format.compare]);
  const loadedIds = useMemo(() => clients.map((x) => x.id), [clients]);
  const profileName = useCallback((id: string) => profiles.data?.find((p) => p.id === id)?.name ?? "…", [profiles.data]);
  const pitch = (wide ? PITCH.wide : PITCH.narrow) + GAP;
  const pitchOf = useCallback((index: number) => (items[index]?.kind === "header" ? HEADER_SLOT : pitch), [items, pitch]);

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
      if (needsMore(w, items.length, hasNext) && !fetching) void fetchNext();
    },
    [items.length, hasNext, fetching, fetchNext],
  );

  // The server gives no group order, so rows move as pages arrive; the focus follows the key and the header counts only what is loaded.
  const keyOf = useCallback((index: number) => items[index]?.key ?? "", [items]);
  const toggle = useCallback((id: string) => sel.toggle(id, loadedIds), [sel, loadedIds]);
  const onEdit = useCallback((c: Client) => setEditing(c), []);
  const onDelete = useCallback((c: Client) => setDeleting({kind: "ids", clients: [c]}), []);
  const selected = clients.filter((x) => sel.isSelected(x.id)).slice(0, MAX_BATCH_IDS);

  const total = everything.count;
  const noClients = !list.isPending && !list.isError && clients.length === 0;

  let body;
  if (list.isError && clients.length === 0) body = <SectionError error={list.error} onRetry={() => void list.refetch()} />;
  else if (list.isPending)
    body = (
      <div role="status" aria-label={t("clients.loading")} className="flex flex-col gap-2">
        <ListRowSkeleton />
        <ListRowSkeleton />
        <ListRowSkeleton />
      </div>
    );
  else if (noClients && q) body = <SectionEmpty icon="users" title={t("clients.emptyFiltered")} />;
  else if (noClients)
    body = (
      <SectionEmpty
        icon="users"
        title={t("clients.empty")}
        description={t("clients.emptyText")}
        action={
          <PrimaryButton onPress={() => devices.open("client", endpoint.id)}>
            <Icon name="plus" className="size-4" />
            {t("clients.add")}
          </PrimaryButton>
        }
      />
    );
  else
    body = (
      <VirtualRows
        label={t("clients.listLabel")}
        count={items.length}
        pitch={pitch}
        pitchOf={pitchOf}
        className="client-list max-h-[70vh] min-h-72"
        onWindow={onWindow}
        footer={fetching ? <Skeleton className="mx-auto my-2 h-6 w-32" /> : null}
        keyOf={keyOf}
        renderRow={(index, place) => {
          const item = items[index]!;
          return (
            <div
              key={item.key}
              role={item.kind === "header" ? "listitem" : "none"}
              aria-posinset={item.kind === "header" ? place.index + 1 : undefined}
              aria-setsize={item.kind === "header" ? place.count : undefined}
              data-index={place.index}
              data-key={item.key}
              style={{...place.style, height: pitchOf(index) - GAP}}
              className={item.kind === "header" ? "flex items-end px-2 pb-1" : ""}
            >
              {item.kind === "header" ? (
                <h2 className="flex min-w-0 items-baseline gap-2">
                  <bdi dir="auto" className="truncate text-base font-medium">
                    {item.name ?? t("clients.ungrouped")}
                  </bdi>
                  <span className="text-muted shrink-0 text-xs">{t(hasNext ? "clients.groupCountSoFar" : "clients.groupCount", {count: item.count})}</span>
                </h2>
              ) : (
                <ClientRow
                  client={item.client}
                  profileName={profileName}
                  selecting={sel.selecting}
                  selected={sel.isSelected(item.client.id)}
                  onToggle={toggle}
                  onEdit={onEdit}
                  onDelete={onDelete}
                  className="h-full! min-h-0!"
                />
              )}
            </div>
          );
        }}
      />
    );

  return (
    <div data-screen="endpoint-clients" className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <SearchField aria-label={t("clients.searchLabel")} value={queryText} onChange={setQueryText} className="min-w-48 flex-1 sm:max-w-sm">
          <SearchField.Group>
            <SearchField.SearchIcon>
              <Icon name="search" className="size-4" />
            </SearchField.SearchIcon>
            <SearchField.Input placeholder={t("clients.search")} />
            <SearchField.ClearButton />
          </SearchField.Group>
        </SearchField>
        <p className="text-muted text-sm tabular-nums" data-testid="client-count" role="status">
          {total === undefined ? "" : t("clients.count", {count: total})}
        </p>
        <div className="ms-auto flex items-center gap-2">
          <PrimaryButton size="sm" onPress={() => devices.open("client", endpoint.id)}>
            <Icon name="plus" className="size-4" />
            {t("clients.add")}
          </PrimaryButton>
          <Dropdown>
            <Button isIconOnly size="sm" variant="outline" aria-label={t("clients.menu.label")}>
              <Icon name="more" className="size-4" />
            </Button>
            <Dropdown.Popover placement="bottom end">
              <Dropdown.Menu
                aria-label={t("clients.menu.label")}
                disabledKeys={[...(clients.length === 0 ? ["select"] : []), ...((total ?? 0) === 0 ? ["inactive", "all"] : [])]}
                onAction={(key) => {
                  if (key === "select") sel.enter();
                  else if (key === "inactive") setDeleting({kind: "inactive"});
                  else if (key === "all") setDeleting({kind: "all"});
                }}
              >
                <Dropdown.Item id="select" textValue={t("clients.menu.select")}>
                  <Icon name="check" className="size-4 shrink-0" />
                  <Label>{t("clients.menu.select")}</Label>
                </Dropdown.Item>
                <Dropdown.Item id="inactive" textValue={t("clients.menu.inactive")} variant="danger">
                  <Icon name="trash" className="size-4 shrink-0" />
                  <Label>{t("clients.menu.inactive")}</Label>
                </Dropdown.Item>
                <Dropdown.Item id="all" textValue={t("clients.menu.all")} variant="danger">
                  <Icon name="trash" className="size-4 shrink-0" />
                  <Label>{t("clients.menu.all")}</Label>
                </Dropdown.Item>
              </Dropdown.Menu>
            </Dropdown.Popover>
          </Dropdown>
        </div>
      </div>

      {sel.selecting ? (
        <>
          <SelectionBar
            count={selected.length}
            total={clients.length}
            onClear={sel.exit}
            actions={[{id: "delete", label: t("clients.selection.delete"), icon: "trash", variant: "danger", isDisabled: selected.length === 0, onPress: () => setDeleting({kind: "ids", clients: selected})}]}
          />
          {list.hasNextPage ? <p className="text-muted text-xs">{t("clients.selection.loaded")}</p> : null}
        </>
      ) : null}

      {body}

      {devices.dialog === "client" ? <ClientDialog key="new" endpoint={endpoint} client={null} onClose={devices.close} /> : null}
      {editing ? <ClientDialog key={editing.id} endpoint={endpoint} client={editing} onClose={() => setEditing(null)} /> : null}
      {deleting ? <ClientDeleteDialog endpoint={endpoint} mode={deleting} total={total} onClose={() => setDeleting(null)} onDone={sel.exit} /> : null}
    </div>
  );
}
