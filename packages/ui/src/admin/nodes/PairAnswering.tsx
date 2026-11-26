"use client";

import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import type {Advertised} from "./pairParts.ts";

// The node whose address the zone advertises for a pair, as words with an icon (never by colour alone): the primary when it answers, the
// fallback when the primary is withdrawn, nobody when both are, and "not known yet" when the node list has not reached the page. A revoked
// node is still advertised while it is in the pair (the route changes only its status), so it is marked as such and the page says to replace
// it now (PG-r2-6); `revoked` is the names of the revoked members of the pair.

export function PairAnswering({advertised, revoked = []}: {advertised: Advertised; revoked?: readonly string[]}) {
  const t = useTranslations("nodes");
  const revokedAnswer = (advertised.kind === "primary" || advertised.kind === "fallback") && advertised.node.status === "revoked";
  const look = revokedAnswer ? "error" : advertised.kind === "primary" ? "check" : advertised.kind === "fallback" ? "warning" : advertised.kind === "none" ? "error" : "info";
  const text =
    advertised.kind === "primary" || advertised.kind === "fallback"
      ? t(revokedAnswer ? "pair.advertised.revoked" : `pair.advertised.${advertised.kind}`, {name: advertised.node.name})
      : t(`pair.advertised.${advertised.kind}`);
  return (
    <span className="flex flex-col gap-1.5 text-sm">
      <span className="flex items-start gap-1.5" data-advertised={revokedAnswer ? "revoked" : advertised.kind}>
        <Icon name={look} className="mt-0.5 size-4 shrink-0" />
        <span>{text}</span>
      </span>
      {revoked.length > 0 ? (
        <span className="flex items-start gap-1.5" data-testid="pair-revoked-member" role="note">
          <Icon name="error" className="mt-0.5 size-4 shrink-0" />
          <span>
            {t("pair.advertised.revokedMember", {names: revoked.join(", ")})}{" "}
            <Link href="/runbook#compromise" className="underline underline-offset-2">
              {t("givenUp.runbook")}
            </Link>
          </span>
        </span>
      ) : null}
    </span>
  );
}
