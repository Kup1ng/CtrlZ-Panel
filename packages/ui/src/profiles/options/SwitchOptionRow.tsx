"use client";

import type {Options} from "@ctrlz/api-client/hooks/options.ts";
import {Switch} from "@heroui/react";
import {useTranslations} from "next-intl";

import {OptionRow} from "./OptionRow.tsx";
import {switchPatch, type OptionRow as RowName, type SwitchOption} from "./optionModel.ts";
import {useOptionWriter} from "./useOptionWriter.ts";

// The options that are one switch: Block DNS Exfiltration, DNS Rebind Protection, Disable DNSSEC, DNS64, CNAME Flattening, Safe Search and
// Restricted YouTube (T-201 to T-203, T-211 to T-214). It answers at once. Turning it off CLEARS the option instead of storing false
// (open question 3): with two profiles on one Endpoint the first one's set option wins, so "off" must mean "not set".

export function SwitchOptionRow({
  profileId,
  options,
  name,
  readOnly,
  onLearnMore,
}: {
  profileId: string;
  options: Options;
  name: SwitchOption;
  readOnly: boolean;
  onLearnMore: (name: RowName) => void;
}) {
  const t = useTranslations("rules");
  const writer = useOptionWriter(profileId);
  const title = t(`options.rows.${name}.name`);
  const on = options[name] === true;
  return (
    <OptionRow
      name={name}
      title={title}
      description={t(`options.rows.${name}.description`)}
      onLearnMore={onLearnMore}
      control={
        <>
          <span aria-hidden="true" className="text-muted text-xs">
            {on ? t("options.on") : t("options.off")}
          </span>
          <Switch
            isSelected={on}
            isDisabled={readOnly}
            // Read-only, not disabled, while the write runs: the switch has the focus, and a disabled control gives it up for good.
            isReadOnly={writer.isPending}
            aria-label={title}
            onChange={(next) => void writer.sendQuietly(switchPatch(name, next), t("options.failed", {name: title}))}
          >
            <Switch.Content>
              <Switch.Control>
                <Switch.Thumb />
              </Switch.Control>
            </Switch.Content>
          </Switch>
        </>
      }
    />
  );
}
