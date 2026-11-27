"use client";

import type {NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {pairGuardQueryOptions, pairGuardShape, samePairGuard} from "@ctrlz/api-client/admin/hooks/pairGuard.ts";
import {pairKeys, useCreatePair, useUpdatePair, type PairView} from "@ctrlz/api-client/admin/hooks/pairs.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert, Button, Checkbox, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useQueryClient} from "@tanstack/react-query";
import {useMemo, useRef, useState} from "react";

import {Tech} from "../../data/Tech.tsx";
import {UrlModal} from "../../dialog/UrlModal.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {EditorActions} from "../../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {FieldSelect, type FieldOption} from "../shared/FieldSelect.tsx";
import {keepFocus} from "../shared/restoreFocus.ts";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useNameList} from "./pairNames.ts";
import {byIdMap, changeKind, offers, pairWarnings, refusals, type Change} from "./pairParts.ts";
import {PairWarningList} from "./PairWarningList.tsx";

// p4-nodes 9.2 and 10.1, T-341. One form for a new pair and for a pair that is edited (`POST /pairs`, `PUT /pairs/{id}`). Only an active
// node that no other pair holds can be chosen, and the others are in the list with the reason they are not offered. While the admin
// chooses, the page says what the change does (every warning of SC 8a.9 that names these two nodes) and refuses, with its reason, a
// change the table would not take. The write is `admin-fresh`, so the fresh-code dialog opens on `totp_fresh_required` and the call
// is repeated once. The first pair of all is made global in the same change (SC 8a.4, Valid table).

export function PairFormDialog({
  isOpen,
  mode,
  pair,
  nodes,
  pairs,
  pairsReady,
  onClose,
}: {
  isOpen: boolean;
  mode: "create" | "edit";
  pair: PairView | undefined;
  nodes: readonly NodeView[];
  pairs: readonly PairView[];
  /** The pairs list is in, all of it: only then does the page know whether a global pair exists (PG-r1-7). */
  pairsReady: boolean;
  onClose: () => void;
}) {
  const t = useTranslations("nodes");
  const open = mode === "create" || pair !== undefined;
  return (
    <UrlModal dialog={{isOpen, close: onClose}} isOpen={isOpen && open} title={mode === "create" ? t("pair.form.createTitle") : t("pair.form.editTitle")} className="sm:max-w-[520px]">
      {isOpen && open ? <Form key={pair?.id ?? "new"} mode={mode} pair={pair} nodes={nodes} pairs={pairs} pairsReady={pairsReady} onClose={onClose} /> : null}
    </UrlModal>
  );
}

function Form({mode, pair, nodes, pairs, pairsReady, onClose}: {mode: "create" | "edit"; pair: PairView | undefined; nodes: readonly NodeView[]; pairs: readonly PairView[]; pairsReady: boolean; onClose: () => void}) {
  const t = useTranslations("nodes");
  const list = useNameList();
  const create = useCreatePair();
  const update = useUpdatePair();
  const {write, pending} = useCheckedWrite();
  const queryClient = useQueryClient();
  const form = useAdminForm();
  const [primaryId, setPrimaryId] = useState<string | null>(pair?.primary_node_id ?? null);
  const [fallbackId, setFallbackId] = useState<string | null>(pair?.fallback_node_id ?? null);
  const [makeGlobal, setMakeGlobal] = useState(false);
  const busy = useRef(false);

  const hasGlobal = pairs.some((p) => p.is_global);
  // With no global pair yet the first pair has to be the global one (`global_pair_required`), so the box is ticked and cannot be cleared.
  // Until the list is in the page cannot tell, and a create sent then could switch the global pair of a deployment that has one: it waits.
  const forced = mode === "create" && pairsReady && !hasGlobal;
  const change: Change = {primaryId, fallbackId, editing: pair};
  const kind = changeKind(change);
  const offered = useMemo(() => offers(nodes, pairs, pair), [nodes, pairs, pair]);
  const freeCount = offered.filter((o) => o.reason === null).length;
  const warnings = useMemo(() => (primaryId && fallbackId ? pairWarnings(change, nodes, pairs) : []), [primaryId, fallbackId, nodes, pairs, pair]); // eslint-disable-line react-hooks/exhaustive-deps
  const refused = useMemo(() => refusals(change, nodes, pairs), [primaryId, fallbackId, nodes, pairs, pair]); // eslint-disable-line react-hooks/exhaustive-deps
  // "Choose both nodes" is what an empty form is, so it is not said in red before the admin has chosen; it only keeps the button off.
  const said = refused.filter((r) => r.id !== "missing");

  const options = (other: string | null): FieldOption[] =>
    offered.map(({node, reason, peerName}) => {
      const why =
        reason === "pending" ? t("pair.form.notOffered.pending") : reason === "revoked" ? t("pair.form.notOffered.revoked") : reason === "inPair" ? t("pair.form.notOffered.inPair", {peer: peerName ?? t("nodes.pair.unknownPeer")}) : null;
      return {
        id: node.id,
        textValue: why ? `${node.name} (${why})` : node.name,
        isDisabled: reason !== null || node.id === other,
        label: (
          <span className="flex min-w-0 flex-col">
            <span className="flex flex-wrap items-baseline gap-x-2">
              <bdi>{node.name}</bdi>
              {node.dns_advertised_ip ? <Tech className="text-muted text-xs">{node.dns_advertised_ip}</Tech> : null}
            </span>
            {why ? <span className="text-muted text-xs">{why}</span> : null}
          </span>
        ),
      };
    });

  async function submit() {
    if (busy.current || form.blocked || refused.length > 0 || !primaryId || !fallbackId || !pairsReady) return;
    busy.current = true;
    form.clear();
    try {
      // A pair is made or replaced, not edited in step with another admin, so there is no draft to merge. But the warnings and refusals the admin read
      // were worked out from the pairs and nodes at the moment of choosing, and the fresh-code dialog can stay open for minutes. Both a create and an
      // edit ask the server for the pairs and the nodes again before the repeated write and stop when what the warnings were made from moved: the
      // roles of the pairs that hold these nodes, whether a global pair exists (a forced make_global must not switch a global pair another admin
      // made meanwhile, PG-r2-5), and the withdrawn, held, behind and contact flags of the nodes (PG-r2-8).
      const ids = [primaryId, fallbackId, pair?.primary_node_id, pair?.fallback_node_id];
      const sent = await write(
        {options: pairGuardQueryOptions(), pick: (data) => pairGuardShape(data.pairs, data.nodes, ids, pair?.id), seen: pairGuardShape(pairs, nodes, ids, pair?.id), same: samePairGuard},
        () =>
          mode === "create"
            ? create.mutateAsync({primary_node_id: primaryId, fallback_node_id: fallbackId, ...(forced || makeGlobal ? {make_global: true} : {})})
            : update.mutateAsync({id: pair!.id, primary_node_id: primaryId, fallback_node_id: fallbackId}),
      );
      if (!sent) {
        // The list the warnings come from is asked again, and the form stays open on the choice the admin made.
        await Promise.all([queryClient.invalidateQueries({queryKey: pairKeys.all}), queryClient.invalidateQueries({queryKey: ["admin", "nodes"]})]);
        return;
      }
      toast.success(mode === "create" ? t("pair.saved.create") : t("pair.saved.edit"));
      onClose();
    } catch (error) {
      form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{mode === "create" ? t("pair.form.createText") : t("pair.form.editText")}</p>
      {!pairsReady ? (
        <Alert status="warning" data-testid="pair-not-loaded">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t("pair.form.notLoaded.title")}</Alert.Title>
            <Alert.Description>{t("pair.form.notLoaded.text")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      {freeCount < 2 && mode === "create" ? (
        <Alert status="warning" data-testid="pair-not-enough">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t("pair.form.notEnough.title")}</Alert.Title>
            <Alert.Description>{t("pair.form.notEnough.text")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      <FieldSelect name="primary_node_id" label={t("pair.form.primary")} placeholder={t("pair.form.pick")} options={options(fallbackId)} value={primaryId} onChange={setPrimaryId} isDisabled={pending} />
      <FieldSelect name="fallback_node_id" label={t("pair.form.fallback")} placeholder={t("pair.form.pick")} options={options(primaryId)} value={fallbackId} onChange={setFallbackId} isDisabled={pending} />
      {primaryId && fallbackId ? (
        <div className="flex">
          <Button
            variant="tertiary"
            size="sm"
            isDisabled={pending}
            aria-label={t("pair.form.swapRow", {primary: byIdMap(nodes).get(primaryId)?.name ?? "", fallback: byIdMap(nodes).get(fallbackId)?.name ?? ""})}
            onPress={() => {
              setPrimaryId(fallbackId);
              setFallbackId(primaryId);
            }}
            data-testid="pair-swap"
          >
            {t("pair.form.swap")}
          </Button>
        </div>
      ) : null}
      {mode === "create" ? (
        <div className="flex flex-col gap-1">
          <Checkbox name="make_global" isSelected={forced || makeGlobal} isDisabled={forced || pending} onChange={setMakeGlobal}>
            <Checkbox.Content>
              <Checkbox.Control>
                <Checkbox.Indicator />
              </Checkbox.Control>
              <span className="text-sm">{t("pair.form.makeGlobal")}</span>
            </Checkbox.Content>
          </Checkbox>
          <span className="text-muted text-xs ps-7">{forced ? t("pair.form.makeGlobalForced") : t("pair.form.makeGlobalHint")}</span>
        </div>
      ) : null}
      {said.length > 0 ? (
        <section role="alert" aria-label={t("pair.form.refusal.title")} className="flex flex-col gap-1.5 rounded-(--radius-box) border border-danger/40 p-3 text-sm" data-testid="pair-refusals">
          <span className="font-medium">{t("pair.form.refusal.title")}</span>
          <ul className="flex flex-col gap-1">
            {said.map((r) => (
              <li key={r.id} className="flex items-start gap-2" data-refusal={r.id}>
                <Icon name="error" className="mt-0.5 size-4 shrink-0" />
                <span>{t(`pair.form.refusal.${r.id}`, {names: list(r.names)})}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {kind !== "same" ? <PairWarningList warnings={warnings} testId="pair-form-warnings" /> : null}
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <EditorActions submitLabel={mode === "create" ? t("pair.form.submitCreate") : t("pair.form.submitEdit")} isPending={pending} isDisabled={refused.length > 0 || !pairsReady} retryIn={form.retryIn} onCancel={onClose} />
    </AuthForm>
  );
}
