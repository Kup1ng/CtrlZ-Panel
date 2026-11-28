"use client";

import {hubParts, useNodeDnsRequest, type NodeDnsRequestKind, type NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, buttonVariants, Chip, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {ActionDialog} from "./ActionDialog.tsx";
import {Facts, NodeCard, NotReported} from "./NodeCard.tsx";
import {drainKey, f3ConditionKey, flapUntilActive, nodeActions} from "./nodeParts.ts";
import {Tech} from "../../data/Tech.tsx";
import {answerState, type NodeLike} from "./pairParts.ts";
import type {PairView} from "@ctrlz/api-client/admin/hooks/pairs.ts";

// T-542, p4-nodes 10.1. The answer a node is in, the conditions of F3 that keep it out, its drain, and the three admin requests of the
// failover table (F4 hold, F5 release, F6 force failback; shared contract 8a.6). A request is accepted at once (202) and decided by the hub
// on its next tick, so the page says that and does not pretend the state has changed. The conditions, the time F3 is due and the drain come
// from NodeView (the hub writes them to node_dns_state, migration 0103); a node the hub has written nothing for says "not reported yet".

const KINDS: NodeDnsRequestKind[] = ["hold", "release", "force_failback"];
const KIND_ICON = {hold: "warning", release: "check", force_failback: "key"} as const;

/** `pairs` and `nodes` are the lists the page has, or undefined while they are not in: the answer is then "not reported yet" and not a guess. */
export function NodeFailover({node, pairs, nodes}: {node: NodeView; pairs?: readonly PairView[] | undefined; nodes?: readonly NodeLike[] | undefined}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const hub = hubParts(node);
  const can = nodeActions(node);
  const request = useNodeDnsRequest();
  const [asking, setAsking] = useState<NodeDnsRequestKind | null>(null);
  const active = node.status === "active";
  const revokedInPair = node.status === "revoked" && Boolean(node.pair_peer_id);
  const answer = answerState(node, pairs, nodes);
  const notReported = <NotReported text={t("notReported")} />;
  const flapping = flapUntilActive(node.dns_flap_until);
  // The buttons the node can take; the route decides in the end. A revoked node in its pair offers hold only (SC 8a.9): release and force failback would let failover return it while the hub still counts it as fit.
  const actions = (
    <div className="flex flex-wrap gap-2" data-testid="failover-actions">
      {KINDS.filter((kind) => !revokedInPair || kind === "hold").map((kind) => (
        <Button
          key={kind}
          variant={kind === "force_failback" ? "outline" : "secondary"}
          isDisabled={!can[kind]}
          aria-label={t(`node.failover.actions.${kind}.row`, {name: node.name})}
          onPress={() => setAsking(kind)}
          data-testid={`request-${kind}`}
        >
          <Icon name={KIND_ICON[kind]} className="size-4" />
          {t(`node.failover.actions.${kind}.label`)}
        </Button>
      ))}
    </div>
  );

  // F3 applies only to a withdrawn node, held or not: the hub writes no conditions for a node that is still in the answer (hubfail f3Unmet),
  // so an empty list of a held node that is not withdrawn must not read as "every condition is met".
  const unmet = !node.dns_withdrawn ? (
    <span data-testid="f3-not-needed">{t("node.failover.unmet.notNeeded")}</span>
  ) : hub.f3_unmet === undefined ? (
    notReported
  ) : hub.f3_unmet.length === 0 ? (
    <span data-testid="f3-none">{t("node.failover.unmet.none")}</span>
  ) : (
    <ul className="flex flex-col gap-1" data-testid="f3-unmet">
      {hub.f3_unmet.map((name) => {
        const key = f3ConditionKey(name);
        return (
          <li key={name} className="flex items-start gap-2" data-condition={name}>
            <Icon name="warning" className="mt-0.5 size-4 shrink-0" />
            <span>{key === "other" ? t.rich("node.failover.unmet.other", {name, tech: (c) => <Tech>{c}</Tech>}) : t(`node.failover.unmet.names.${key}`)}</span>
          </li>
        );
      })}
    </ul>
  );

  // The moment F3 acts if its conditions keep holding. The hub writes it only while none is unmet, so it is shown on its own row and only when there.
  const due = hub.f3_due_at !== undefined ? format.dateTime(hub.f3_due_at) : undefined;

  const drainName = hub.drain_state === undefined ? undefined : drainKey(hub.drain_state);
  const drain =
    hub.drain_state === undefined ? (
      notReported
    ) : drainName === "other" ? (
      t.rich("node.failover.drain.other", {name: hub.drain_state, tech: (c) => <Tech>{c}</Tech>})
    ) : (
      <span className="flex flex-col gap-0.5">
        <span data-drain={hub.drain_state}>{t(`node.failover.drain.states.${drainName as "none"}`)}</span>
        {/* The start is the hub's own clock of when the drain began; a node that is not draining has none worth showing. */}
        {hub.drain_since !== undefined && drainName !== "none" ? (
          <span className="text-muted text-xs" data-testid="drain-since">
            {t("node.failover.drain.since", {when: format.dateTime(hub.drain_since)})}
          </span>
        ) : null}
      </span>
    );

  return (
    <NodeCard title={t("node.failover.title")} description={t("node.failover.text")} testId="node-failover">
      {revokedInPair ? (
        // A revoked node is still in its pair and still advertised: the route changes only its status (SC 8a.9). So the page says to replace
        // it and offers the hold that SC 8a.9 gives as the remedy, instead of saying it takes no part in the answer (PG-r2-6, PG-r2-7).
        <div role="alert" className="border-danger/40 flex flex-col gap-2 rounded-(--radius-box) border p-4 text-sm" data-testid="failover-revoked-in-pair">
          <span className="flex items-start gap-2 font-medium">
            <Icon name="error" className="mt-0.5 size-4 shrink-0" />
            {t("node.failover.revokedInPair")}
          </span>
          <span className="text-muted">{t("node.failover.revokedHold")}</span>
          {actions}
          <Link href="/runbook#compromise" className={buttonVariants({variant: "secondary", size: "sm", className: "mt-1 self-start"})}>
            <Icon name="runbook" className="size-4" />
            {t("givenUp.runbook")}
          </Link>
        </div>
      ) : !active ? (
        <p className="text-muted text-sm" data-testid="failover-not-active">
          {t("node.failover.notActive")}
        </p>
      ) : (
        <>
          {!node.pair_peer_id ? (
            <p className="text-muted text-sm" data-testid="failover-no-pair">
              {t("node.failover.noPair")}
            </p>
          ) : null}
          <Facts
            rows={[
              {
                id: "answer",
                label: t("node.failover.answer"),
                value:
                  answer === "unknown" ? (
                    notReported
                  ) : (
                    <Chip size="sm" variant="soft" color={answer === "advertised" ? "success" : answer === "standby" || answer === "unpaired" ? "default" : "warning"} data-answer={answer}>
                      <Icon name={answer === "advertised" ? "check" : answer === "standby" || answer === "unpaired" ? "shield" : "warning"} className="size-3.5" />
                      <Chip.Label>{t(`node.failover.answerState.${answer}`)}</Chip.Label>
                    </Chip>
                  ),
              },
              {
                id: "last-failback",
                label: t("node.failover.lastFailback"),
                value: node.dns_last_failback_at ? format.dateTime(node.dns_last_failback_at) : "-",
              },
              {id: "unmet", label: t("node.failover.unmet.title"), value: unmet},
              ...(due !== undefined ? [{id: "f3-due", label: t("node.failover.unmet.dueTitle"), value: <span data-testid="f3-due-at">{due}</span>}] : []),
              {id: "drain", label: t("node.failover.drain.title"), value: drain},
              {id: "peer-views", label: t("node.failover.peerViews"), value: notReported},
              {
                id: "requests",
                label: t("node.failover.requests"),
                value: format.number(node.pending_requests),
              },
            ]}
          />
          {flapping ? (
            <p className="flex items-start gap-2 text-sm" data-testid="flap-until">
              <Icon name="warning" className="mt-0.5 size-4 shrink-0" />
              {t("node.failover.flapUntil", {when: format.dateTime(flapping)})}
            </p>
          ) : null}
          <div role="note" className="bg-surface-secondary flex flex-col gap-1 rounded-(--radius-box) p-4 text-sm" data-testid="hold-note">
            <span className="flex items-center gap-2 font-medium">
              <Icon name="shield" className="size-4" />
              {t("node.failover.holdNote.title")}
            </span>
            <span className="text-muted">{t("node.failover.holdNote.text")}</span>
            <Link href="/runbook#compromise" className={buttonVariants({variant: "secondary", size: "sm", className: "mt-2 self-start"})}>
              <Icon name="runbook" className="size-4" />
              {t("givenUp.runbook")}
            </Link>
          </div>
          {actions}
        </>
      )}
      {KINDS.map((kind) => (
        <ActionDialog
          key={kind}
          open={asking === kind}
          onClose={() => setAsking((current) => (current === kind ? null : current))}
          status="warning"
          icon={<Icon name={KIND_ICON[kind]} className="size-5" />}
          title={t(`node.failover.actions.${kind}.title`, {name: node.name})}
          confirmLabel={t(`node.failover.actions.${kind}.confirm`)}
          run={() => request.mutateAsync({id: node.id, kind})}
          onDone={() => toast.success(t("node.failover.sent"))}
          testId={`confirm-${kind}`}
        >
          {kind === "hold" && revokedInPair ? (
            // A held revoked node is still fit to the hub until it reads the revocation, so failover can clear the hold: say that, not "stays out".
            <p>{t("node.failover.revokedHoldDialog")}</p>
          ) : (
            <>
              <p>{t(`node.failover.actions.${kind}.text`)}</p>
              {kind === "hold" ? <p className="text-muted text-sm">{t("node.failover.holdNote.text")}</p> : null}
            </>
          )}
        </ActionDialog>
      ))}
    </NodeCard>
  );
}
