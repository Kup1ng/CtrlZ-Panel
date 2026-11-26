"use client";

import {nodeHealth, type NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {usePairs, type PairView} from "@ctrlz/api-client/admin/hooks/pairs.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Chip} from "@heroui/react";
import type {DataGridColumn} from "@heroui-pro/react";
import {useTranslations} from "next-intl";
import {useMemo} from "react";

import {gridState, PagedGrid} from "../shared/PagedGrid.tsx";
import {HealthChip} from "./HealthChip.tsx";
import {PairAnswering} from "./PairAnswering.tsx";
import {advertisedNode, byIdMap, revokedMembers} from "./pairParts.ts";

// T-341. Every pair: its two nodes with their state, the node whose address is advertised, whether it is the global pair, and the three
// things the admin can do (edit, make global, remove). In v1 no Endpoint has a pair of its own (D30), so the global pair is the one a
// client uses and every other pair is free to be removed; the global pair is not (`pair_in_use`), and its Remove says why.

export type PairActions = {onEdit: (pair: PairView) => void; onMakeGlobal: (pair: PairView) => void; onRemove: (pair: PairView) => void};

export function PairsGrid({nodes, actions}: {nodes: readonly NodeView[]; actions: PairActions}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const pairs = usePairs();
  const grid = gridState(pairs);
  const byId = useMemo(() => byIdMap(nodes), [nodes]);

  const columns = useMemo<DataGridColumn<PairView>[]>(() => {
    const nodeLine = (role: "primary" | "fallback", id: string) => {
      const node = byId.get(id);
      return (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1" data-testid={`pair-${role}-${id}`}>
          <span className="text-muted w-14 shrink-0 text-xs">{t(`pair.global.${role}`)}</span>
          {node ? (
            <>
              <Link href={`/nodes/${node.id}`} className="text-sm font-medium underline-offset-2 hover:underline" aria-label={t("nodes.openRow", {name: node.name})}>
                {node.name}
              </Link>
              <HealthChip health={nodeHealth(node)} />
            </>
          ) : (
            <span className="text-muted text-sm">{t("pair.advertised.unknown")}</span>
          )}
        </div>
      );
    };
    return [
      {
        id: "pair",
        isRowHeader: true,
        header: t("pair.grid.columns.pair"),
        minWidth: 280,
        cell: (p) => (
          <div className="flex flex-col gap-2">
            {nodeLine("primary", p.primary_node_id)}
            {nodeLine("fallback", p.fallback_node_id)}
          </div>
        ),
      },
      {
        id: "answering",
        header: t("pair.grid.columns.answering"),
        minWidth: 200,
        cell: (p) => (
          <div data-testid={`advertised-${p.id}`}>
            <PairAnswering advertised={advertisedNode(p, byId)} revoked={revokedMembers(p, byId).map((n) => n.name)} />
          </div>
        ),
      },
      {
        id: "scope",
        header: t("pair.grid.columns.scope"),
        minWidth: 190,
        cell: (p) => (
          <div className="flex flex-col items-start gap-1">
            {p.is_global ? (
              <Chip size="sm" variant="soft" color="accent" data-testid={`global-chip-${p.id}`}>
                <Icon name="check" className="size-3.5" />
                <Chip.Label>{t("pair.grid.global")}</Chip.Label>
              </Chip>
            ) : (
              <span className="text-muted text-sm">{t("pair.grid.unused")}</span>
            )}
            <time dateTime={p.created_at} className="text-muted text-xs">
              {t("pair.grid.made", {date: format.date(p.created_at)})}
            </time>
          </div>
        ),
      },
      {
        id: "actions",
        header: <span className="sr-only">{t("pair.grid.columns.actions")}</span>,
        minWidth: 220,
        align: "end",
        cell: (p) => {
          const names = {primary: byId.get(p.primary_node_id)?.name ?? "", fallback: byId.get(p.fallback_node_id)?.name ?? ""};
          return (
            <div className="flex flex-wrap justify-end gap-2">
              <Button size="sm" variant="tertiary" aria-label={t("pair.actions.editRow", names)} onPress={() => actions.onEdit(p)} data-testid={`pair-edit-${p.id}`}>
                <Icon name="edit" className="size-4" />
                {t("pair.actions.edit")}
              </Button>
              {p.is_global ? null : (
                <Button size="sm" variant="tertiary" aria-label={t("pair.actions.makeGlobalRow", names)} onPress={() => actions.onMakeGlobal(p)} data-testid={`pair-global-${p.id}`}>
                  <Icon name="check" className="size-4" />
                  {t("pair.actions.makeGlobal")}
                </Button>
              )}
              <Button
                size="sm"
                variant="tertiary"
                isDisabled={p.is_global}
                aria-label={p.is_global ? t("pair.actions.removeGlobalRow", names) : t("pair.actions.removeRow", names)}
                onPress={() => actions.onRemove(p)}
                data-testid={`pair-remove-${p.id}`}
              >
                <Icon name="trash" className="size-4" />
                {t("pair.actions.remove")}
              </Button>
            </div>
          );
        },
      },
    ];
  }, [t, format, byId, actions]);

  return (
    <section aria-labelledby="pairs-list" className="flex flex-col gap-2">
      <h2 id="pairs-list" className="text-base font-medium">
        {t("pair.grid.title")}
      </h2>
      <PagedGrid
        {...grid}
        label={t("pair.grid.label")}
        columns={columns}
        getRowId={(p) => p.id}
        minWidth="min-w-[46rem]"
        empty={{icon: "pair", title: t("pair.grid.empty.title"), description: t("pair.grid.empty.text")}}
      />
    </section>
  );
}
