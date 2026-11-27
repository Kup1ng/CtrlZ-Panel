"use client";

// /endpoints (spec p3 10, WF "Endpoints"): the type chips with their counts and Not Configured, the groups as collapsible sections, a row for each
// Endpoint, the selection mode with the header bar (Move, Edit, Delete), Export CSV, sort and New group in the menu, and + for Add.
// The URL dialogs (add, edit, delete, the groups) are EndpointDialogs, drawn here and by the frames.

import {fetchEndpointsCsv, useEndpointTypes, useGroups, type Endpoint, type EndpointFilter} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Disclosure, Dropdown, Label, ToggleButton, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useEffect, useMemo, useState} from "react";

import {SelectionBar} from "../controls/SelectionBar.tsx";
import {useListSelection} from "../controls/useListSelection.ts";
import {downloadCsv} from "../data/download.ts";
import {ListRowSkeleton, RowList} from "../data/ListRow.tsx";
import {useDeviceDialog} from "../dialog/useDeviceDialog.ts";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {PageHeader, type HeaderAction} from "../shell/PageHeader.tsx";
import {EndpointBatchDialogsHost, type BatchDialog} from "./EndpointBatchHost.tsx";
import {MAX_BATCH_IDS, sectionsOf, type EndpointSection} from "./endpointModel.ts";
import {EndpointDialogs} from "./EndpointDialogs.tsx";
import {EndpointRow} from "./EndpointRow.tsx";
import {PartialListNotice} from "./PartialListNotice.tsx";
import {useTypeName} from "./EndpointTypeIcon.tsx";
import {useAllEndpoints} from "./useAllEndpoints.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

type Sort = "created" | "name";

export function EndpointsListScreen() {
  const t = useTranslations("endpoints");
  const s = useTranslations("shell");
  const format = useAppFormat();
  const devices = useDeviceDialog();
  const groupDialog = useUrlDialog("endpointGroupDialog");

  const [typeKey, setTypeKey] = useState<string | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);
  const [queryText, setQueryText] = useState("");
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<Sort>("created");
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  // The dialog of the selection bar and the Endpoints it was opened for. The target is fixed when the dialog opens: a page that arrives
  // later or a refetch must not add an Endpoint to a request the person has already read and confirmed (S5-r1-9).
  const [batch, setBatch] = useState<{dialog: Exclude<BatchDialog, null>; endpoints: Endpoint[]} | null>(null);
  const sel = useListSelection();

  // A search is asked for when the typing pauses, so each letter is not a request.
  useEffect(() => {
    const timer = setTimeout(() => setQ(queryText.trim()), 250);
    return () => clearTimeout(timer);
  }, [queryText]);

  const filter: EndpointFilter = {...(typeKey ? {type: typeKey} : {}), ...(notConfigured ? {status: "pending" as const} : {}), ...(q ? {q} : {}), sort};
  const narrowed = typeKey !== null || notConfigured || q !== "";
  const list = useAllEndpoints(filter);
  const types = useEndpointTypes();
  const groups = useGroups();
  const profiles = useProfiles();
  const typeName = useTypeName(types.data);
  const rows = list.endpoints;
  // The counts of the chips are the tenant's (the server does not narrow them by the filter), so while the next view's first page is on its
  // way the last ones stay, and the row of chips does not flash zeros (S5-r2-2).
  const [facets, setFacets] = useState<{byType: Record<string, number>; byStatus: {pending: number; active: number}} | null>(null);
  if (list.byType && list.byStatus && (facets?.byType !== list.byType || facets.byStatus !== list.byStatus)) setFacets({byType: list.byType, byStatus: list.byStatus});
  const byType = facets?.byType ?? {};
  const total = facets ? facets.byStatus.pending + facets.byStatus.active : 0;
  const pendingCount = facets?.byStatus.pending ?? 0;
  const profileName = (id: string) => profiles.data?.find((p) => p.id === id)?.name ?? "…";

  const sections = useMemo(() => sectionsOf(rows, groups.data ?? [], format.compare, !narrowed), [rows, groups.data, format.compare, narrowed]);
  const hasGroups = (groups.data?.length ?? 0) > 0;

  // The selection follows the list: a row that left it (a delete, a move into another view) leaves the selection, and another filter starts it over.
  const loadedIds = useMemo(() => rows.map((e) => e.id), [rows]);
  const filterSignature = `${typeKey ?? ""}|${notConfigured}|${q}`;
  const {reconcile} = sel;
  useEffect(() => {
    reconcile([], true);
  }, [filterSignature, reconcile]);
  useEffect(() => {
    if (!list.loading && !list.failed) reconcile(loadedIds, false);
  }, [loadedIds, list.loading, list.failed, reconcile]);

  const selected = sel.allMatching ? rows : rows.filter((e) => sel.isSelected(e.id));
  const actionable = selected.slice(0, MAX_BATCH_IDS);
  // What the open dialog sees of its Endpoints is the list as it is now (a hold that came in), for the ones it was opened for.
  const batchEndpoints = useMemo(() => (batch ? batch.endpoints.map((e) => rows.find((r) => r.id === e.id) ?? e) : []), [batch, rows]);
  const open = (dialog: Exclude<BatchDialog, null>) => setBatch({dialog, endpoints: actionable});

  async function exportCsv() {
    try {
      downloadCsv("endpoints", await fetchEndpointsCsv());
    } catch {
      toast.danger(t("list.exportFailed"));
    }
  }

  const sortLabel = (key: Sort) => {
    const label = t(key === "name" ? "list.menu.sortName" : "list.menu.sortDate");
    return sort === key ? t("list.menu.sortCurrent", {label}) : label;
  };
  const actions: HeaderAction[] = [
    {id: "export", label: t("list.menu.export"), icon: "download", onAction: () => void exportCsv()},
    ...(rows.length > 0 ? [{id: "select", label: t("list.menu.select"), icon: "check" as const, onAction: () => sel.enter()}] : []),
    {id: "sort-name", label: sortLabel("name"), onAction: () => setSort("name")},
    {id: "sort-created", label: sortLabel("created"), onAction: () => setSort("created")},
    {id: "new-group", label: t("list.menu.newGroup"), icon: "plus", onAction: () => groupDialog.open("create")},
  ];

  const toggleSection = (key: string) => setClosed((prev) => ({...prev, [key]: !prev[key]}));
  const chipTypes = (types.data ?? []).filter((x) => (byType[x.key] ?? 0) > 0 || x.key === typeKey);

  // The groups of the tenant, with their rows. A group with no Endpoint is drawn too, so it can be renamed or deleted (S5-r2-3).
  const sectionList = (
    <>
      {sections.map((section) => (
        <Section
          key={section.key}
          section={section}
          titled={hasGroups}
          isOpen={!closed[section.key]}
          onToggle={() => toggleSection(section.key)}
          onRename={(id) => groupDialog.open(`rename:${id}`)}
          onDelete={(id) => groupDialog.open(`delete:${id}`)}
        >
          {section.endpoints.map((endpoint) => {
            const type = types.data?.find((x) => x.key === endpoint.type);
            return (
              <EndpointRow
                key={endpoint.id}
                endpoint={endpoint}
                typeName={typeName(endpoint.type)}
                typeIcon={type?.icon}
                profileName={profileName}
                selecting={sel.selecting}
                selected={sel.isSelected(endpoint.id)}
                onToggle={() => sel.toggle(endpoint.id, loadedIds)}
                onEdit={() => devices.open("edit", endpoint.id)}
                onResolvers={() => devices.open("resolvers", endpoint.id)}
                onConfigure={() => devices.open("configure", endpoint.id)}
              />
            );
          })}
      </Section>
    ))}
    </>
  );

  let body;
  if (list.isError && rows.length === 0) body = <SectionError error={list.error} onRetry={() => void list.refetch()} />;
  else if (list.loading && rows.length === 0)
    body = (
      <div role="status" aria-label={t("list.loading")} className="flex flex-col gap-2">
        <ListRowSkeleton />
        <ListRowSkeleton />
        <ListRowSkeleton />
      </div>
    );
  else if (rows.length === 0)
    body = narrowed ? (
      <SectionEmpty icon="endpoints" title={t("list.emptyFiltered")} />
    ) : (
      <div className="flex flex-col gap-4">
        <SectionEmpty
          icon="endpoints"
          title={t("list.empty")}
          description={t("list.emptyText")}
          action={
            <PrimaryButton onPress={() => devices.open("add")}>
              <Icon name="plus" className="size-4" />
              {t("list.emptyAction")}
            </PrimaryButton>
          }
        />
        {hasGroups ? sectionList : null}
      </div>
    );
  else
    body = (
      <div className="flex flex-col gap-4">
        {list.failed ? <PartialListNotice error={list.error} onRetry={list.retry} /> : null}
        {sectionList}
      </div>
    );

  return (
    <div data-screen="endpoints-list" className="flex flex-col gap-4">
      <PageHeader
        icon="endpoints"
        title={s("nav.endpoints")}
        subtitle={s("pages.endpoints.subtitle")}
        helpKey="endpoints"
        actions={actions}
        onSearch={setQueryText}
        onCreate={() => devices.open("add")}
        createLabel={t("dialogs.add.title")}
      />

      {total > 0 || narrowed ? (
        <div role="group" aria-label={t("list.chipsLabel")} className="flex flex-wrap items-center gap-2" data-testid="endpoint-chips">
          <ToggleButton
            size="sm"
            aria-label={t("list.chipAria", {name: t("list.chipAll"), count: total})}
            isSelected={typeKey === null && !notConfigured}
            onChange={() => {
              setTypeKey(null);
              setNotConfigured(false);
            }}
          >
            {t("list.chipAll")}
            <span className="tabular-nums opacity-70">{format.number(total)}</span>
          </ToggleButton>
          {chipTypes.map((type) => (
            <ToggleButton
              key={type.key}
              size="sm"
              aria-label={t("list.chipAria", {name: typeName(type.key), count: byType[type.key] ?? 0})}
              isSelected={typeKey === type.key}
              onChange={(on) => {
                setTypeKey(on ? type.key : null);
                setNotConfigured(false);
              }}
            >
              {typeName(type.key)}
              <span className="tabular-nums opacity-70">{format.number(byType[type.key] ?? 0)}</span>
            </ToggleButton>
          ))}
          {pendingCount > 0 || notConfigured ? (
            <ToggleButton
              size="sm"
              aria-label={t("list.chipAria", {name: t("list.chipNotConfigured"), count: pendingCount})}
              isSelected={notConfigured}
              onChange={(on) => {
                setNotConfigured(on);
                setTypeKey(null);
              }}
            >
              {t("list.chipNotConfigured")}
              <span className="tabular-nums opacity-70">{format.number(pendingCount)}</span>
            </ToggleButton>
          ) : null}
        </div>
      ) : null}

      {sel.selecting ? (
        <>
          <SelectionBar
            count={selected.length}
            allMatching={sel.allMatching}
            total={rows.length}
            onSelectAll={list.loading || list.failed ? undefined : sel.selectAll}
            onClear={sel.exit}
            actions={[
              {id: "move", label: t("list.selection.move"), icon: "move", onPress: () => open("move")},
              {id: "edit", label: t("list.selection.edit"), icon: "edit", onPress: () => open("edit")},
              {id: "delete", label: t("list.selection.delete"), icon: "trash", variant: "danger", onPress: () => open("delete")},
            ]}
          />
          {selected.length > MAX_BATCH_IDS ? <p className="text-muted text-xs">{t("list.selection.overflow", {max: MAX_BATCH_IDS})}</p> : null}
        </>
      ) : null}

      {body}

      <EndpointBatchDialogsHost dialog={batch?.dialog ?? null} endpoints={batchEndpoints} onClose={() => setBatch(null)} onDone={sel.exit} />
      <EndpointDialogs />
    </div>
  );
}

function Section({
  section,
  titled,
  isOpen,
  onToggle,
  onRename,
  onDelete,
  children,
}: {
  section: EndpointSection;
  titled: boolean;
  isOpen: boolean;
  onToggle: () => void;
  onRename: (id: string) => void;
  onDelete: (id: string) => void;
  children: React.ReactNode;
}) {
  const t = useTranslations("endpoints");
  const format = useAppFormat();
  const group = section.group;
  const name = group ? group.name : t("list.groups.ungrouped");
  if (!titled) return <RowList aria-label={t("list.listLabel")}>{children}</RowList>;
  return (
    <Disclosure isExpanded={isOpen} onExpandedChange={onToggle}>
      <div className="flex items-center gap-2">
        <Disclosure.Heading className="min-w-0 flex-1">
          <Button slot="trigger" variant="ghost" size="sm" aria-label={t("list.groups.toggleAria", {name})} className="w-full justify-start gap-2">
            <Disclosure.Indicator />
            <span className="truncate font-medium">{name}</span>
            <span className="text-muted text-xs font-normal">{t("list.groups.count", {count: section.endpoints.length})}</span>
            <span className="sr-only">{format.number(section.endpoints.length)}</span>
          </Button>
        </Disclosure.Heading>
        {group ? (
          <Dropdown>
            <Button isIconOnly size="sm" variant="ghost" aria-label={t("list.groups.actionsAria", {name})}>
              <Icon name="more" className="size-4" />
            </Button>
            <Dropdown.Popover placement="bottom end">
              <Dropdown.Menu
                aria-label={t("list.groups.actionsAria", {name})}
                onAction={(key) => (key === "rename" ? onRename(group.id) : onDelete(group.id))}
              >
                <Dropdown.Item id="rename" textValue={t("list.groups.rename")}>
                  <Icon name="edit" className="size-4 shrink-0" />
                  <Label>{t("list.groups.rename")}</Label>
                </Dropdown.Item>
                <Dropdown.Item id="delete" textValue={t("list.groups.delete")} variant="danger">
                  <Icon name="trash" className="size-4 shrink-0" />
                  <Label>{t("list.groups.delete")}</Label>
                </Dropdown.Item>
              </Dropdown.Menu>
            </Dropdown.Popover>
          </Dropdown>
        ) : null}
      </div>
      <Disclosure.Content>
        <Disclosure.Body className="pt-2">
          {section.endpoints.length > 0 ? (
            <RowList aria-label={name}>{children}</RowList>
          ) : (
            <p className="text-muted px-2 text-sm">{t("list.groups.empty")}</p>
          )}
        </Disclosure.Body>
      </Disclosure.Content>
    </Disclosure>
  );
}
