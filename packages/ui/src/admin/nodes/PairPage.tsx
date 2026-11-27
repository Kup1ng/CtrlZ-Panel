"use client";

import {NODE_LIMIT, useNodes, type NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {pairGuardQueryOptions, pairGuardShape, samePairGuard} from "@ctrlz/api-client/admin/hooks/pairGuard.ts";
import {pairKeys, useDeletePair, usePairs, usePutGlobalPair, type PairView} from "@ctrlz/api-client/admin/hooks/pairs.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {toast} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useCallback, useEffect, useMemo, useState} from "react";

import {pushDialogParams, useUrlDialog, wasPushed} from "../../dialog/useUrlDialog.ts";
import {SectionError} from "../../feedback/SectionError.tsx";
import {PageHeader} from "../../shell/PageHeader.tsx";
import {stripDialogParam} from "../shared/dialogUrl.ts";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {keepRetry, restoreFocusLater} from "../shared/restoreFocus.ts";
import {ActionDialog} from "./ActionDialog.tsx";
import {PairFormDialog} from "./PairFormDialog.tsx";
import {PairGlobalCard} from "./PairGlobalCard.tsx";
import {PairNotes} from "./PairNotes.tsx";
import {PairsGrid, type PairActions} from "./PairsGrid.tsx";
import {PairWarningList} from "./PairWarningList.tsx";
import {byIdMap, noSlotFree, switchWarnings} from "./pairParts.ts";

// p4-nodes 10.1, T-341. The pair of nodes: which node of each pair is primary and which stands behind it, the node each pair advertises
// now, the global pair, and every change with the words SC 8a.9 asks of this page. A new pair and an edit are URL-bound dialogs
// (`?dialog=newPair`, `?dialog=editPair&pairId=`), so a link opens them and Back closes them; making a pair global and removing one are
// confirmations that hold no state worth a link. Every write is `admin-fresh`.

export function PairPage() {
  const t = useTranslations("nodes");
  const dialog = useUrlDialog("dialog");
  const pairParam = useUrlDialog("pairId");
  const nodesQuery = useNodes();
  const pairsQuery = usePairs();
  const nodes = useMemo<NodeView[]>(() => nodesQuery.data?.pages.flatMap((p) => p.items) ?? [], [nodesQuery.data]);
  const pairs = useMemo<PairView[]>(() => pairsQuery.data?.pages.flatMap((p) => p.items) ?? [], [pairsQuery.data]);
  const [switching, setSwitching] = useState<PairView | null>(null);
  const [removing, setRemoving] = useState<PairView | null>(null);

  const mode = dialog.value === "newPair" ? "create" : dialog.value === "editPair" ? "edit" : null;
  const editing = mode === "edit" ? pairs.find((p) => p.id === pairParam.value) : undefined;
  // A link to a pair that is not there (removed meanwhile, or typed by hand) opens nothing and leaves a clean address once the list is in.
  // Only a list that arrived whole can say the pair is gone: a failed or partial list says nothing, and the link stays (PG-r3-2).
  const stale = mode === "edit" && !editing && pairsQuery.isSuccess && !pairsQuery.hasNextPage;

  const closeDialog = useCallback(() => {
    const pushed = wasPushed("dialog");
    dialog.close();
    if (!pushed) stripDialogParam("pairId");
    restoreFocusLater(() => document.querySelector<HTMLElement>("[data-testid=pair-grid-anchor]"));
  }, [dialog]);

  const actions = useMemo<PairActions>(
    () => ({
      onEdit: (pair) => pushDialogParams({dialog: "editPair", pairId: pair.id}),
      onMakeGlobal: setSwitching,
      onRemove: setRemoving,
    }),
    [],
  );

  const global = pairs.find((p) => p.is_global);
  // The list is complete only when it has arrived and has no page left: "no global pair yet" is read from it (PG-r1-7).
  const pairsReady = pairsQuery.isSuccess && !pairsQuery.hasNextPage;
  const loadFailed = nodesQuery.isError && !nodesQuery.data ? nodesQuery.error : null;

  return (
    <>
      <PageHeader icon="pair" title={t("pages.pair.title")} subtitle={t("pages.pair.subtitle")} onCreate={() => dialog.open("newPair")} createLabel={t("pair.create")} />
      <div className="flex flex-col gap-8">
        {loadFailed ? (
          <SectionError error={loadFailed} onRetry={keepRetry(() => nodesQuery.refetch())} />
        ) : (
          <>
            <RefreshFailed error={nodesQuery.error} onRetry={() => nodesQuery.refetch()} />
            <PairGlobalCard pair={global} nodes={nodes} />
            <div data-testid="pair-grid-anchor" tabIndex={-1} className="outline-none">
              <PairsGrid nodes={nodes} actions={actions} />
            </div>
            <PairNotes noSlotFree={noSlotFree(nodes, NODE_LIMIT)} />
          </>
        )}
      </div>

      <PairFormDialog isOpen={(mode === "create" || (mode === "edit" && !stale)) && !loadFailed} mode={mode ?? "create"} pair={editing} nodes={nodes} pairs={pairs} pairsReady={pairsReady} onClose={closeDialog} />
      {stale ? <StaleLink onDone={closeDialog} /> : null}
      <SwitchDialog pair={switching} pairs={pairs} nodes={nodes} onClose={() => setSwitching(null)} />
      <RemoveDialog pair={removing} nodes={nodes} onClose={() => setRemoving(null)} />
    </>
  );
}

/** A link to a pair that does not exist: the address is cleaned and the admin told once. */
function StaleLink({onDone}: {onDone: () => void}) {
  const t = useTranslations("nodes");
  useEffect(() => {
    toast.info(t("pair.stale"));
    onDone();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return null;
}

function pairName(pair: PairView, byId: Map<string, NodeView>) {
  return {primary: byId.get(pair.primary_node_id)?.name ?? "", fallback: byId.get(pair.fallback_node_id)?.name ?? ""};
}

function SwitchDialog({pair, pairs, nodes, onClose}: {pair: PairView | null; pairs: readonly PairView[]; nodes: readonly NodeView[]; onClose: () => void}) {
  const t = useTranslations("nodes");
  const put = usePutGlobalPair();
  const queryClient = useQueryClient();
  const byId = byIdMap(nodes);
  // Kept while the dialog closes, so the text does not empty during the fade.
  const [last, setLast] = useState<PairView | null>(null);
  if (pair && pair !== last) setLast(pair);
  const shown = pair ?? last;
  const names = shown ? pairName(shown, byId) : {primary: "", fallback: ""};
  return (
    <ActionDialog
      open={pair !== null}
      onClose={onClose}
      status="warning"
      icon={<Icon name="pair" className="size-5" />}
      title={t("pair.switch.title", {primary: names.primary, fallback: names.fallback})}
      confirmLabel={t("pair.switch.confirm")}
      // The warnings name the nodes of this pair as the page saw them, and the fresh-code dialog can stay open for minutes (PG-r1-14).
      guard={pair ? {options: pairGuardQueryOptions(), pick: (data) => pairGuardShape(data.pairs, data.nodes, [pair.primary_node_id, pair.fallback_node_id], pair.id), seen: pairGuardShape(pairs, nodes, [pair.primary_node_id, pair.fallback_node_id], pair.id), same: samePairGuard} : undefined}
      onStale={() => Promise.all([queryClient.invalidateQueries({queryKey: pairKeys.all}), queryClient.invalidateQueries({queryKey: ["admin", "nodes"]})])}
      run={() => put.mutateAsync(pair!.id)}
      onDone={() => toast.success(t("pair.switch.done"))}
      testId="pair-switch-confirm"
    >
      <p className="text-sm">{t("pair.switch.text")}</p>
      {shown ? <PairWarningList warnings={switchWarnings(shown, nodes)} testId="pair-switch-warnings" /> : null}
      <p className="text-muted text-xs">{t("pair.switch.free")}</p>
    </ActionDialog>
  );
}

function RemoveDialog({pair, nodes, onClose}: {pair: PairView | null; nodes: readonly NodeView[]; onClose: () => void}) {
  const t = useTranslations("nodes");
  const remove = useDeletePair();
  const byId = byIdMap(nodes);
  const [last, setLast] = useState<PairView | null>(null);
  if (pair && pair !== last) setLast(pair);
  const shown = pair ?? last;
  const names = shown ? pairName(shown, byId) : {primary: "", fallback: ""};
  return (
    <ActionDialog
      open={pair !== null}
      onClose={onClose}
      status="danger"
      icon={<Icon name="trash" className="size-5" />}
      title={t("pair.remove.title", {primary: names.primary, fallback: names.fallback})}
      confirmLabel={t("pair.remove.confirm")}
      run={() => remove.mutateAsync(pair!.id)}
      onDone={() => toast.success(t("pair.remove.done"))}
      testId="pair-remove-confirm"
    >
      <p className="text-sm">{t("pair.remove.text")}</p>
    </ActionDialog>
  );
}
