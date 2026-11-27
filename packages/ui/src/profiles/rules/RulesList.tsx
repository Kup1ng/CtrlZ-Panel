"use client";

import {AlertDialog, Button, buttonVariants, Chip, SearchField, ToggleButton, ToggleButtonGroup, toast} from "@heroui/react";
import {useInfiniteQuery} from "@tanstack/react-query";
import {newIdempotencyKey} from "@ctrlz/api-client/hooks/support.ts";
import {ruleListQuery, useDeleteRule, useFolders, usePatchRule, useRules, flattenRules, type Folder, type Rule} from "@ctrlz/api-client/hooks/rules.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {useTranslations} from "next-intl";
import {useCallback, useEffect, useMemo, useRef, useState} from "react";

import {SelectionBar, type BarAction} from "../../controls/SelectionBar.tsx";
import {useListSelection} from "../../controls/useListSelection.ts";
import {DenseRow, DenseRowSkeleton} from "../../data/DenseRow.tsx";
import {VirtualRows} from "../../data/VirtualRows.tsx";
import {needsMore, type Window} from "../../data/virtualWindow.ts";
import {useTargetName} from "../../destinations/DestinationsDialog.tsx";
import {parseRuleDialog, ruleDialogValue} from "../../dialog/dialogValues.ts";
import {useUrlDialog} from "../../dialog/useUrlDialog.ts";
import {useErrorText} from "../../feedback/errorText.ts";
import {useDebouncedValue} from "../../hooks/useDebouncedValue.ts";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {useProfileFrame} from "../ProfileFrameContext.tsx";
import {folderHref} from "../profileRoutes.ts";
import {BatchEditDialog} from "./BatchEditDialog.tsx";
import {FolderDialog} from "./FolderDialog.tsx";
import {MiniSelect} from "./MiniSelect.tsx";
import {RuleDialog} from "./RuleDialog.tsx";
import {RuleRow} from "./RuleRow.tsx";
import {
  ACTION_FILTERS,
  isFiltered,
  knownTotal,
  listQuery,
  NO_FILTER,
  parseGeo,
  SORTS,
  STATUS_FILTERS,
  selectionMembers,
  transferMembers,
  type ListFilter,
  type RuleView,
} from "./rulesModel.ts";
import {TransferDialog} from "./TransferDialog.tsx";
import {useBatchRunner} from "./useBatchRunner.tsx";
import {useRuleView} from "./useRuleView.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// Spec p2 9.6, WF "Rules" (T-179, T-190, T-191, T-196): the list of rules, as the top level of a profile (`/custom-rules`) and as the inside of a
// folder (`/custom-rules/<folderId>`). The folders come first on the top level, then the rules as low rows in a window of the page (10,000 rules
// make about 25 rows in the DOM), loaded by cursor pages as the window nears the end of what is there.
//
// A click on a row opens selection mode (check boxes, Select All as a selector over the CURRENT filter, a bar with Copy, Move, Edit, Delete, Enable
// and Disable). Hover, or the keyboard focus, gives one rule Copy, Move, Edit and Delete, the delete confirmed in the row. Search, status, action
// and sort go to the server; the large or small size is a browser setting.

const PITCH = {large: 56, small: 48} as const;
// A search goes to the server when typing pauses, not on each key (the user-read rate class is shared with everything else the page asks).
const SEARCH_DELAY = 250;
const isCleared = (q: string) => q === "";

export type RulesListProps = {
  profileId: string;
  /** The folder whose page this is. Without it the list is the top level. */
  folder?: Folder;
};

type Transfer = {op: "copy" | "move"; rule?: Rule};

export function RulesList({profileId, folder}: RulesListProps) {
  const t = useTranslations("rules");
  const c = useTranslations("common");
  const format = useAppFormat();
  const targetNameNow = useTargetName();
  // The namer is made again on every render; the rows get one that stays the same and reads the latest, so a render of the list does not redraw them.
  const nameRef = useRef(targetNameNow);
  useEffect(() => {
    nameRef.current = targetNameNow;
  });
  const targetName = useCallback((target: Parameters<typeof targetNameNow>[0]) => nameRef.current(target), []);
  const errorText = useErrorText();
  const {profile, readOnly} = useProfileFrame();
  const dialog = useUrlDialog("ruleDialog");
  const parsed = parseRuleDialog(dialog.value);
  const [filter, setFilter] = useState<ListFilter>(NO_FILTER);
  const [view, setView] = useRuleView();
  // The box shows what is typed; the list asks for what was typed a moment ago.
  const searched = useDebouncedValue(filter.q, SEARCH_DELAY, isCleared);
  const applied = useMemo<ListFilter>(() => ({...filter, q: searched}), [filter, searched]);
  const query = useMemo(() => listQuery(applied, folder?.id), [applied, folder?.id]);
  const filtered = isFiltered(applied);
  const list = useRules(profileId, query, {keepPrevious: true});
  const folders = useFolders(profileId);
  const rules = list.rules;
  const nextFailed = list.isFetchNextPageError;
  const fetchNext = list.fetchNextPage;
  // A failed page or a failed refetch leaves the rows that are there (TanStack keeps the data and sets the status to error): only a list that
  // never arrived is an error block. The failures after it are said in a line over the rows or under them, each with its own Retry.
  const blocked = list.isError && !list.data;
  const refreshFailed = list.isError && !!list.data && !nextFailed;
  const loadedIds = useMemo(() => rules.map((r) => r.id), [rules]);
  const sel = useListSelection();
  const runner = useBatchRunner(profileId);
  const patchRule = usePatchRule();
  const deleteRule = useDeleteRule();
  const [confirming, setConfirming] = useState<string | null>(null);
  const [transfer, setTransfer] = useState<Transfer | null>(null);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const actionKey = useRef<string | null>(null);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(timer);
  }, []);

  // A new filter is a new list: the selection was of the old one (the selector would mean something else).
  const filterId = JSON.stringify(query);
  const lastFilter = useRef(filterId);
  useEffect(() => {
    if (lastFilter.current === filterId) return;
    lastFilter.current = filterId;
    sel.exit();
    setConfirming(null);
  }, [filterId, sel]);
  useEffect(() => {
    sel.reconcile(loadedIds, false);
  }, [loadedIds, sel]);

  const folderRows = useMemo(() => [...(folders.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)), [folders.data]);
  const shownFolders = useMemo(
    () => (folder ? [] : filtered ? [] : folderRows),
    [folder, filtered, folderRows],
  );
  // The count is known only for a list that has arrived (a pending, failed or previous-view list has no rows to count, and the top level
  // needs the folders to take their rules off the profile's).
  const settled = !list.isPending && !blocked && !list.isPlaceholderData && (folder !== undefined || filtered || folders.data !== undefined);
  const total = settled ? knownTotal({filtered, folder, profileRules: profile.counts.rules, folders: folders.data ?? [], loaded: rules.length, hasNext: list.hasNextPage}) : undefined;
  const hasMore = list.hasNextPage && !list.isPlaceholderData;

  // The next page is asked for when the window nears the end of what is loaded. The window is reported by the child's effect, which runs before this
  // component's own, so on the commit where a page lands the list's state is still the old one: the check is made from both places, the report of
  // the window and the effect that refreshes the state, and a page is asked for once for each size of the list (no second ask before it has landed).
  const more = useRef({list: filterId, hasNext: false, loaded: 0, busy: false, fetch: () => {}});
  const seen = useRef<Window | null>(null);
  const asked = useRef("");
  const askMore = useCallback(() => {
    const m = more.current;
    const key = `${m.list}:${m.loaded}`;
    if (!seen.current || m.busy || asked.current === key || !needsMore(seen.current, m.loaded, m.hasNext)) return;
    asked.current = key;
    m.fetch();
  }, []);
  useEffect(() => {
    // A failed page is answered by its own Retry; once that is gone the same size of list may be asked for again.
    if (nextFailed) asked.current = "";
    more.current = {list: filterId, hasNext: hasMore, loaded: rules.length, busy: list.isFetchingNextPage || nextFailed, fetch: () => void list.fetchNextPage()};
    askMore();
  });
  const onWindow = useCallback(
    (w: Window) => {
      seen.current = w;
      askMore();
    },
    [askMore],
  );

  // ---- the rule dialog's rule ----
  // An edit by address names a rule that may not be in the pages that are loaded (a reload, a link, a rule of another folder): it is then looked
  // for in the list of every rule, page after page, until it is found or the list ends.
  const wanted = parsed?.kind === "rule" ? parsed.ruleId : null;
  const inList = wanted ? rules.find((r) => r.id === wanted) : undefined;
  // The last rule that was found for the dialog stays for as long as the dialog is open: a refetch that no longer has it (deleted in another tab,
  // moved by a job) must not swap the form for "not found" and lose what was typed. "Not found" is the answer for an address that never found it.
  const [kept, setKept] = useState<Rule | null>(null);
  const keptNow = kept !== null && kept.id === wanted;
  const lookup = useInfiniteQuery({...ruleListQuery(profileId, {}), enabled: wanted !== null && inList === undefined && !keptNow && !list.isPending});
  const lookupBroken = lookup.isError && !lookup.isFetching;
  const lookupRules = useMemo(() => flattenRules(lookup.data), [lookup.data]);
  const foundNow = inList ?? lookupRules.find((r) => r.id === wanted);
  if (wanted === null ? kept !== null : foundNow !== undefined && kept !== foundNow) setKept(foundNow ?? null);
  const found = foundNow ?? (keptNow ? kept : undefined);
  // A page that failed stops the walk: it goes on only when the person asks again (the dialog says so and has a Retry), never by itself.
  useEffect(() => {
    if (wanted && !found && lookup.hasNextPage && !lookup.isFetchingNextPage && !lookupBroken) void lookup.fetchNextPage();
  }, [wanted, found, lookup, lookupBroken]);
  const retryLookup = () => void (lookup.hasNextPage ? lookup.fetchNextPage() : lookup.refetch());
  const dialogRule = wanted === null ? null : found ? found : lookupBroken ? "failed" : lookup.isSuccess && !lookup.hasNextPage ? false : undefined;

  // ---- handlers, the same functions for the life of the list ----
  const live = useRef<{
    press: (r: Rule) => void;
    select: (r: Rule, on: boolean) => void;
    toggle: (r: Rule, on: boolean) => void;
    copy: (r: Rule) => void;
    move: (r: Rule) => void;
    edit: (r: Rule) => void;
    ask: (r: Rule) => void;
    drop: (r: Rule) => void;
  } | null>(null);
  useEffect(() => {
    live.current = {
      press: (r) => (sel.selecting ? sel.toggle(r.id, loadedIds) : sel.enter(r.id)),
      select: (r) => sel.toggle(r.id, loadedIds),
      toggle: (r, enabled) => void patchRule.mutateAsync({profileId, ruleId: r.id, patch: {enabled}}).catch((e: unknown) => toast.danger(errorText(e))),
      copy: (r) => {
        actionKey.current = newIdempotencyKey();
        setTransfer({op: "copy", rule: r});
      },
      move: (r) => {
        actionKey.current = newIdempotencyKey();
        setTransfer({op: "move", rule: r});
      },
      edit: (r) => dialog.open(ruleDialogValue({kind: "rule", ruleId: r.id})),
      ask: (r) => setConfirming(r.id),
      drop: (r) => {
        setConfirming(null);
        void deleteRule.mutateAsync({profileId, ruleId: r.id}).then(
          () => toast.success(t("row.deleted", {pattern: parseGeo(r.pattern) ? t("row.geo.removed") : r.pattern})),
          (e: unknown) => toast.danger(errorText(e)),
        );
      },
    };
  });
  const onPress = useCallback((r: Rule) => live.current?.press(r), []);
  const onSelect = useCallback((r: Rule, on: boolean) => live.current?.select(r, on), []);
  const onSwitch = useCallback((r: Rule, on: boolean) => live.current?.toggle(r, on), []);
  const onCopy = useCallback((r: Rule) => live.current?.copy(r), []);
  const onMove = useCallback((r: Rule) => live.current?.move(r), []);
  const onEdit = useCallback((r: Rule) => live.current?.edit(r), []);
  const onAskDelete = useCallback((r: Rule) => live.current?.ask(r), []);
  const onCancelDelete = useCallback((r: Rule) => setConfirming((now) => (now === r.id ? null : now)), []);
  const onConfirmDelete = useCallback((r: Rule) => live.current?.drop(r), []);

  // ---- selection mode ----
  const target = sel.target();
  const selectedCount = sel.count(rules.length, total);
  const unknownCount = sel.allMatching && total === undefined;
  const selectionWords = unknownCount ? t("batch.everyMatching") : t("batch.rules", {count: selectedCount});
  const bulk = (op: "enable" | "disable") => {
    if (!target) return;
    void runner.run({op, ...selectionMembers(target, query)}, t(`batch.${op}Title`)).then(() => sel.exit(), (e: unknown) => toast.danger(errorText(e)));
  };
  const barActions: BarAction[] = [
    {id: "copy", label: t("batch.copy"), icon: "copy", onPress: () => { actionKey.current = newIdempotencyKey(); setTransfer({op: "copy"}); }},
    {id: "move", label: t("batch.move"), icon: "move", isDisabled: readOnly, onPress: () => { actionKey.current = newIdempotencyKey(); setTransfer({op: "move"}); }},
    {id: "edit", label: t("batch.edit"), icon: "edit", isDisabled: readOnly, onPress: () => { actionKey.current = newIdempotencyKey(); setEditing(true); }},
    {id: "enable", label: t("batch.enable"), icon: "check", isDisabled: readOnly, onPress: () => bulk("enable")},
    {id: "disable", label: t("batch.disable"), icon: "close", isDisabled: readOnly, onPress: () => bulk("disable")},
    {id: "delete", label: t("batch.delete"), icon: "trash", variant: "danger", isDisabled: readOnly, onPress: () => { actionKey.current = newIdempotencyKey(); setDeleting(true); }},
  ];

  const transferSubject = transfer?.rule ? (parseGeo(transfer.rule.pattern) ? t("row.geo.removed") : transfer.rule.pattern) : selectionWords;

  const addRule = (
    <PrimaryButton size="sm" isDisabled={readOnly} aria-label={t("list.addAria", {name: folder?.name ?? profile.name})} onPress={() => dialog.open(ruleDialogValue({kind: "rule", ruleId: null}))}>
      <Icon name="plus" className="size-4" />
      {t("list.add")}
    </PrimaryButton>
  );

  const toolbar = (
    <div className="flex flex-col gap-2" role="search" aria-label={t("list.toolbar")}>
      <div className="flex flex-wrap items-center gap-2">
        <SearchField aria-label={t("list.searchLabel")} value={filter.q} onChange={(q) => setFilter((f) => ({...f, q}))} className="min-w-48 flex-1">
          <SearchField.Group>
            <SearchField.SearchIcon>
              <Icon name="search" className="size-4" />
            </SearchField.SearchIcon>
            <SearchField.Input placeholder={t("list.search")} />
            <SearchField.ClearButton />
          </SearchField.Group>
        </SearchField>
        {folder ? null : (
          <Button variant="secondary" size="sm" isDisabled={readOnly} aria-label={t("list.addFolderAria", {name: profile.name})} onPress={() => dialog.open(ruleDialogValue({kind: "folder", folderId: null}))}>
            <SubIcon group="rules" name="folder" className="size-4" />
            {t("list.addFolder")}
          </Button>
        )}
        {addRule}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <MiniSelect
          label={t("filters.statusLabel")}
          className="w-36"
          value={filter.status || "all"}
          onChange={(v) => setFilter((f) => ({...f, status: v === "all" ? "" : (v as ListFilter["status"])}))}
          options={[{id: "all", label: t("filters.allStatuses"), textValue: t("filters.allStatuses")}, ...STATUS_FILTERS.map((s) => ({id: s, label: t(`filters.${s}`), textValue: t(`filters.${s}`)}))]}
        />
        <MiniSelect
          label={t("filters.actionLabel")}
          className="w-36"
          value={filter.action || "all"}
          onChange={(v) => setFilter((f) => ({...f, action: v === "all" ? "" : (v as ListFilter["action"])}))}
          options={[{id: "all", label: t("filters.allActions"), textValue: t("filters.allActions")}, ...ACTION_FILTERS.map((a) => ({id: a, label: t(`action.${a}`), textValue: t(`action.${a}`)}))]}
        />
        <MiniSelect
          label={t("filters.sortLabel")}
          className="w-40"
          value={filter.sort}
          onChange={(v) => setFilter((f) => ({...f, sort: v as ListFilter["sort"]}))}
          options={SORTS.map((s) => ({id: s, label: t(`filters.sort.${s}`), textValue: t(`filters.sort.${s}`)}))}
        />
        <ToggleButtonGroup
          aria-label={t("view.label")}
          selectionMode="single"
          disallowEmptySelection
          size="sm"
          className="ms-auto"
          selectedKeys={[view]}
          onSelectionChange={(keys) => {
            const next = [...keys][0];
            if (next === "large" || next === "small") setView(next as RuleView);
          }}
        >
          <ToggleButton id="large">{t("view.large")}</ToggleButton>
          <ToggleButton id="small">
            <ToggleButtonGroup.Separator />
            {t("view.small")}
          </ToggleButton>
        </ToggleButtonGroup>
      </div>
    </div>
  );

  const noRulesAtAll = !filtered && !list.isPending && !list.isPlaceholderData && rules.length === 0;
  const rowCount = rules.length;
  const title = folder ? folder.name : t("list.title");

  return (
    <div data-screen={folder ? "profile-folder" : "profile-rules"} className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium" aria-live="polite">
          {title}{" "}
          <span className="text-muted font-normal">
            {total !== undefined ? t("list.summary", {count: total}) : settled ? t("list.summaryLoaded", {count: format.number(rowCount)}) : null}
          </span>
        </h2>
      </div>

      {toolbar}

      {sel.selecting ? (
        <SelectionBar
          count={selectedCount}
          allMatching={sel.allMatching}
          total={total}
          countUnknown={unknownCount}
          onSelectAll={sel.selectAll}
          onClear={sel.exit}
          actions={barActions}
        />
      ) : null}

      {filtered && !folder ? <p className="text-muted text-xs">{t("list.searchingAll")}</p> : null}

      {blocked ? (
        <SectionError error={list.error} onRetry={() => void list.refetch()} />
      ) : list.isPending || (list.isPlaceholderData && rules.length === 0) ? (
        <div role="status" aria-label={t("list.loading")} className="flex flex-col gap-2">
          {Array.from({length: 6}, (_, i) => (
            <DenseRowSkeleton key={i} />
          ))}
        </div>
      ) : (
        <>
          {refreshFailed ? (
            <div className="flex flex-wrap items-center gap-2 text-xs" role="alert" data-refresh-failed="">
              <span>{t("list.refreshFailed")}</span>
              <Button size="sm" variant="tertiary" isPending={list.isFetching} onPress={() => void list.refetch()}>
                {c("retry")}
              </Button>
            </div>
          ) : null}

          {shownFolders.length > 0 ? (
            <ul aria-label={t("folder.listLabel")} className="flex flex-col gap-1.5" data-folders="">
              {shownFolders.map((f) => (
                <DenseRow
                  key={f.id}
                  leading={<SubIcon group="rules" name={f.kind === "do_not_log" ? "folder-magic" : "folder"} className="size-5" />}
                  title={
                    <span className="flex min-w-0 flex-col leading-tight">
                      <span className="truncate text-sm">{f.name}</span>
                      <span className="text-muted flex min-w-0 items-center gap-2 overflow-hidden whitespace-nowrap text-xs">
                        <span className="truncate">{f.kind === "do_not_log" ? t("folder.magicTag") : f.action ? t("folder.action", {action: t(`action.${f.action}`)}) : t("folder.noAction")}</span>
                        {f.location_unavailable ? (
                          <span className="inline-flex shrink-0 items-center gap-1 text-(--warning-text)">
                            <Icon name="warning" className="size-3" />
                            {t("row.unavailable")}
                          </span>
                        ) : null}
                      </span>
                    </span>
                  }
                  href={folderHref(profileId, f.id)}
                  tags={
                    <Chip size="sm" variant="soft">
                      <Chip.Label>{t("folder.rules", {count: f.rule_count})}</Chip.Label>
                    </Chip>
                  }
                  hoverActions={
                    readOnly ? undefined : (
                      <button type="button" aria-label={t("folder.edit", {name: f.name})} className={buttonVariants({variant: "ghost", size: "sm", isIconOnly: true})} onClick={() => dialog.open(ruleDialogValue({kind: "folder", folderId: f.id}))}>
                        <Icon name="edit" className="size-4" />
                      </button>
                    )
                  }
                />
              ))}
            </ul>
          ) : null}

          {noRulesAtAll && shownFolders.length === 0 ? (
            <SectionEmpty icon="rules" title={t("list.emptyTitle")} description={folder ? t("list.emptyFolderText") : t("list.emptyText")} action={readOnly ? undefined : addRule} />
          ) : rules.length === 0 && filtered ? (
            <p className="text-muted py-3 text-sm" role="status">
              {t("list.noMatch")}
            </p>
          ) : rules.length > 0 ? (
            <VirtualRows
              // Another search, status, sort or folder is another list, read from its first row.
              resetKey={filterId}
              label={t("list.listLabel", {name: folder?.name ?? profile.name})}
              count={rules.length}
              setSize={hasMore ? (total ?? -1) : rules.length}
              pitch={PITCH[view]}
              className={["h-[min(62dvh,42rem)] min-h-72 transition-opacity motion-reduce:transition-none", list.isPlaceholderData ? "pointer-events-none opacity-60" : ""].join(" ")}
              onWindow={onWindow}
              footer={
                list.isFetchingNextPage ? (
                  <p className="text-muted py-2 text-center text-xs" role="status">
                    {t("list.loadingMore")}
                  </p>
                ) : nextFailed ? (
                  <div className="flex items-center justify-center gap-2 py-2 text-xs" role="alert">
                    <span>{t("list.loadMoreFailed")}</span>
                    <Button size="sm" variant="tertiary" onPress={() => void fetchNext()}>
                      {c("retry")}
                    </Button>
                  </div>
                ) : null
              }
              renderRow={(index, place) => {
                const rule = rules[index]!;
                return (
                  <RuleRow
                    key={rule.id}
                    rule={rule}
                    place={place}
                    compact={view === "small"}
                    readOnly={readOnly}
                    selecting={sel.selecting}
                    selected={sel.isSelected(rule.id)}
                    confirming={confirming === rule.id}
                    showFolder={filtered && !folder}
                    folders={folders.data ?? NO_FOLDERS}
                    now={Math.floor(now / 60_000) * 60_000}
                    format={format}
                    targetName={targetName}
                    onPress={onPress}
                    onSelect={onSelect}
                    onSwitch={onSwitch}
                    onCopy={onCopy}
                    onMove={onMove}
                    onEdit={onEdit}
                    onAskDelete={onAskDelete}
                    onCancelDelete={onCancelDelete}
                    onConfirmDelete={onConfirmDelete}
                  />
                );
              }}
            />
          ) : null}
        </>
      )}

      <RuleDialog
        profileId={profileId}
        profileName={profile.name}
        isOpen={parsed?.kind === "rule" && !readOnly}
        onClose={dialog.close}
        rule={dialogRule}
        onRetry={retryLookup}
        folders={folders.data ?? NO_FOLDERS}
        defaultFolderId={folder?.id}
      />
      <FolderDialog profileId={profileId} isOpen={parsed?.kind === "folder" && !readOnly} onClose={dialog.close} folderId={parsed?.kind === "folder" ? parsed.folderId : null} folders={folders.data} />

      <TransferDialog
        isOpen={transfer !== null}
        onClose={() => setTransfer(null)}
        op={transfer?.op ?? "copy"}
        subject={transferSubject}
        profileId={profileId}
        onSubmit={async (draft) => {
          const members = transferMembers(draft, profileId);
          if (transfer?.rule) await runner.runOne(transfer.rule.id, {op: draft.op, ...members});
          else if (target) {
            await runner.run({op: draft.op, ...members, ...selectionMembers(target, query)}, t(`batch.${draft.op}Title`), actionKey.current ?? undefined);
            sel.exit();
          }
        }}
      />

      <BatchEditDialog
        isOpen={editing}
        onClose={() => setEditing(false)}
        profileId={profileId}
        subject={selectionWords}
        folders={folders.data ?? NO_FOLDERS}
        onSubmit={async (members) => {
          if (!target) return;
          await runner.run({op: "edit", ...members, ...selectionMembers(target, query)}, t("batch.editTitle"), actionKey.current ?? undefined);
          sel.exit();
        }}
      />

      <AlertDialog.Backdrop isOpen={deleting} onOpenChange={(open) => !open && !runner.isPending && setDeleting(false)}>
        <AlertDialog.Container placement="center">
          <AlertDialog.Dialog className="sm:max-w-[400px]">
            <AlertDialog.CloseTrigger aria-label={c("close")} />
            <AlertDialog.Header>
              <AlertDialog.Icon status="danger">
                <Icon name="trash" className="size-5" />
              </AlertDialog.Icon>
              <AlertDialog.Heading>{t("batch.deleteTitle", {subject: selectionWords})}</AlertDialog.Heading>
            </AlertDialog.Header>
            <AlertDialog.Body>
              <p>{t("batch.deleteText")}</p>
            </AlertDialog.Body>
            <AlertDialog.Footer>
              <Button slot="close" variant="tertiary" isDisabled={runner.isPending}>
                {c("cancel")}
              </Button>
              <Button
                variant="danger"
                isPending={runner.isPending}
                onPress={() => {
                  if (!target) return;
                  void runner.run({op: "delete", ...selectionMembers(target, query)}, t("batch.deleteJob"), actionKey.current ?? undefined).then(
                    () => {
                      setDeleting(false);
                      sel.exit();
                    },
                    (e: unknown) => {
                      toast.danger(errorText(e));
                      setDeleting(false);
                    },
                  );
                }}
              >
                {t("batch.deleteConfirm")}
              </Button>
            </AlertDialog.Footer>
          </AlertDialog.Dialog>
        </AlertDialog.Container>
      </AlertDialog.Backdrop>

      {runner.dialog}
    </div>
  );
}

const NO_FOLDERS: readonly Folder[] = [];
