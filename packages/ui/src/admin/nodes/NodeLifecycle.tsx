"use client";

import {useApproveNode, useRemoveNode, useRevokeNode, type NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {Link, useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {ActionDialog} from "./ActionDialog.tsx";
import {NodeCard} from "./NodeCard.tsx";
import {addressHolder, nodeActions, removeBlockedByPair} from "./nodeParts.ts";
import {ReplacementSteps} from "./ReplacementOrder.tsx";

// p4-nodes 4.2 step 5, 4.5, 10.1: approve, revoke and remove, each behind a confirmation and the fresh code. Removing shows its
// conditions first (a node in a pair is not removed, and a node a table the hub still signs holds is refused by the route), so a refusal
// is never the first the admin hears of it. A revoked node is terminal: the only thing left for it is removal.

type Which = "approve" | "revoke" | "remove";

export function NodeLifecycle({node, peerName, others}: {node: NodeView; peerName: string | undefined; /** The nodes the page has, for the address the approval would clash with. */ others?: readonly NodeView[] | undefined}) {
  const t = useTranslations("nodes");
  const router = useRouter();
  const can = nodeActions(node);
  const approve = useApproveNode();
  const revoke = useRevokeNode();
  const remove = useRemoveNode();
  const [asking, setAsking] = useState<Which | null>(null);
  const paired = removeBlockedByPair(node);
  const holder = node.status === "pending" ? addressHolder(node, others) : undefined;
  const close = (which: Which) => setAsking((current) => (current === which ? null : current));

  return (
    <NodeCard title={t("node.lifecycle.title")} description={t("node.lifecycle.text")} testId="node-lifecycle">
      <section aria-labelledby="remove-conditions" className="flex flex-col gap-2" data-testid="remove-conditions">
        <h3 id="remove-conditions" className="text-sm font-medium">
          {t("node.lifecycle.remove.conditionsTitle")}
        </h3>
        <ul className="flex flex-col gap-1.5 text-sm">
          <li className="flex items-start gap-2" data-met={!paired}>
            <Icon name={paired ? "warning" : "check"} className="mt-0.5 size-4 shrink-0" />
            <span>
              <span className="font-medium">{paired ? t("node.lifecycle.remove.unmet") : t("node.lifecycle.remove.met")}: </span>
              {t("node.lifecycle.remove.conditions.notPaired")}
              {paired ? <span className="text-muted block">{peerName ? t("node.lifecycle.remove.blocked", {peer: peerName}) : t("node.lifecycle.remove.blockedUnknown")}</span> : null}
            </span>
          </li>
          <li className="flex items-start gap-2" data-met="server">
            <Icon name="info" className="mt-0.5 size-4 shrink-0" />
            <span>
              <span className="font-medium">{t("node.lifecycle.remove.checkedByServer")}: </span>
              {t("node.lifecycle.remove.conditions.notInTable")}
            </span>
          </li>
        </ul>
      </section>
      <div className="flex flex-wrap gap-2">
        {can.approve ? (
          <PrimaryButton aria-label={t("node.lifecycle.approve.row", {name: node.name})} onPress={() => setAsking("approve")} data-testid="node-approve">
            <Icon name="check" className="size-4" />
            {t("node.lifecycle.approve.label")}
          </PrimaryButton>
        ) : null}
        {can.revoke ? (
          <Button variant="danger-soft" aria-label={t("node.lifecycle.revoke.row", {name: node.name})} onPress={() => setAsking("revoke")} data-testid="node-revoke">
            <Icon name="shield" className="size-4" />
            {t("node.lifecycle.revoke.label")}
          </Button>
        ) : null}
        <Button variant="danger-soft" isDisabled={paired} aria-label={t("node.lifecycle.remove.row", {name: node.name})} onPress={() => setAsking("remove")} data-testid="node-remove">
          <Icon name="trash" className="size-4" />
          {t("node.lifecycle.remove.label")}
        </Button>
      </div>

      <ActionDialog
        open={asking === "approve"}
        onClose={() => close("approve")}
        status="accent"
        icon={<Icon name="check" className="size-5" />}
        title={t("node.lifecycle.approve.title", {name: node.name})}
        confirmLabel={t("node.lifecycle.approve.confirm")}
        run={() => approve.mutateAsync(node.id)}
        onDone={() => toast.success(t("node.lifecycle.approve.done"))}
        testId="confirm-approve"
        blocked={holder !== undefined}
      >
        <p>{t("node.lifecycle.approve.text")}</p>
        {holder !== undefined ? (
          <div role="alert" className="flex flex-col gap-2 text-sm" data-testid="approve-address-clash">
            <p className="font-medium">{t("node.lifecycle.approve.addressTaken", {name: holder})}</p>
            <ReplacementSteps />
          </div>
        ) : null}
      </ActionDialog>
      <ActionDialog
        open={asking === "revoke"}
        onClose={() => close("revoke")}
        icon={<Icon name="shield" className="size-5" />}
        title={t("node.lifecycle.revoke.title", {name: node.name})}
        confirmLabel={t("node.lifecycle.revoke.confirm")}
        run={() => revoke.mutateAsync(node.id)}
        onDone={() => toast.success(t("node.lifecycle.revoke.done"))}
        testId="confirm-revoke"
      >
        <p>{t("node.lifecycle.revoke.text")}</p>
        <Link href="/runbook#compromise" className="text-sm underline underline-offset-2" data-testid="revoke-runbook-link">
          {t("node.lifecycle.revoke.runbook")}
        </Link>
      </ActionDialog>
      <ActionDialog
        open={asking === "remove"}
        onClose={() => close("remove")}
        icon={<Icon name="trash" className="size-5" />}
        title={t("node.lifecycle.remove.title", {name: node.name})}
        confirmLabel={t("node.lifecycle.remove.confirm")}
        run={() => remove.mutateAsync(node.id)}
        onDone={() => {
          toast.success(t("node.lifecycle.remove.done"));
          router.push("/nodes");
        }}
        testId="confirm-remove"
      >
        <p>{t("node.lifecycle.remove.text")}</p>
        <p className="text-muted text-sm" data-testid="remove-free-note">
          {t("node.lifecycle.remove.freeNote")}
        </p>
      </ActionDialog>
    </NodeCard>
  );
}
