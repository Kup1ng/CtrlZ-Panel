"use client";

import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Card} from "@heroui/react";
import {useTranslations} from "next-intl";

// T-341. What the panel cannot see when a pair changes, said on the page at all times and not only when a change is being made (SC 8a.9:
// the pair page says all three). F0, the first row of the failover table, reads no tracker of what each node has applied, so a changed
// pair can hand the answer to a node that is new, dead, held or behind. The cases, then the order that replaces a node when every slot is
// held. The sentences that name the nodes of one change are in the dialog; these are the rules.

const NOTES = ["withdrawn", "both", "oneAtATime", "noPeer"] as const;

export function PairNotes({noSlotFree}: {noSlotFree: boolean}) {
  const t = useTranslations("nodes");
  return (
    <Card className="max-w-3xl gap-4 p-6" data-testid="pair-notes">
      <Card.Header className="flex flex-col gap-1">
        <Card.Title className="text-base">{t("pair.notes.title")}</Card.Title>
        <Card.Description>{t("pair.notes.text")}</Card.Description>
      </Card.Header>
      <Card.Content className="flex flex-col gap-4">
        <ul className="flex flex-col gap-3">
          {NOTES.map((id) => (
            <li key={id} className="flex items-start gap-3" data-note={id}>
              <Icon name="info" className="mt-0.5 size-4 shrink-0" />
              <div className="flex min-w-0 flex-col gap-0.5">
                <span className="text-sm font-medium">{t(`pair.notes.items.${id}.title`)}</span>
                <span className="text-muted text-sm">{t(`pair.notes.items.${id}.text`)}</span>
              </div>
            </li>
          ))}
        </ul>
        {noSlotFree ? (
          <div role="note" className="bg-surface-secondary flex items-start gap-3 rounded-(--radius-box) p-4 text-sm" data-testid="pair-slots">
            <Icon name="warning" className="mt-0.5 size-4 shrink-0" />
            <div className="flex flex-col gap-0.5">
              <span className="font-medium">{t("pair.notes.slots.title")}</span>
              <span className="text-muted">{t("pair.notes.slots.text")}</span>
            </div>
          </div>
        ) : null}
        <p className="text-sm">
          <Link href="/runbook" className="underline underline-offset-2" data-testid="pair-runbook-link">
            {t("pair.notes.runbook")}
          </Link>
        </p>
      </Card.Content>
    </Card>
  );
}
