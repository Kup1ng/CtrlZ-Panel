"use client";

import type {NodeHealth} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Chip} from "@heroui/react";
import {useTranslations} from "next-intl";

import {HEALTH_LOOK, HUB_HEALTH_LOOK} from "./nodeParts.ts";

// A node's state as a word with an icon, so the colour is never the only thing that says it (spec 5.4, the design rules).

export function HealthChip({health}: {health: NodeHealth}) {
  const t = useTranslations("nodes");
  const look = HEALTH_LOOK[health];
  return (
    <Chip size="sm" variant="soft" color={look.color} data-health={health}>
      <Icon name={look.icon} className="size-3.5" />
      <Chip.Label>{t(`health.${health}`)}</Chip.Label>
    </Chip>
  );
}

/** What the hub says of a node, when it says anything. The words are not the same as the row's: the hub's view is its own. */
export function HubHealthChip({health}: {health: keyof typeof HUB_HEALTH_LOOK}) {
  const t = useTranslations("nodes");
  const look = HUB_HEALTH_LOOK[health];
  return (
    <Chip size="sm" variant="soft" color={look.color} data-hub-health={health}>
      <Icon name={look.icon} className="size-3.5" />
      <Chip.Label>{t(`hubHealth.${health}`)}</Chip.Label>
    </Chip>
  );
}
