"use client";

import type {Options} from "@ctrlz/api-client/hooks/options.ts";
import {useProfileLocations} from "@ctrlz/api-client/hooks/profiles.ts";
import type {Target} from "@ctrlz/api-client/hooks/services.ts";
import {Alert} from "@heroui/react";
import {Flag} from "@ctrlz/icons/Flag.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useEffect, useState} from "react";

import {ThreeStateControl} from "../../controls/ThreeStateControl.tsx";
import {DestinationsDialog, useTargetName} from "../../destinations/DestinationsDialog.tsx";
import {parseProfileDialog} from "../../dialog/dialogValues.ts";
import {useUrlDialog} from "../../dialog/useUrlDialog.ts";
import {OptionRow} from "./OptionRow.tsx";
import {defaultActionOf, sameTarget, withLocation, type DefaultAction, type OptionRow as RowName} from "./optionModel.ts";
import {useOptionWriter} from "./useOptionWriter.ts";

// Default Rule (T-178, T-200, T-523): Block, Bypass or Redirect for a name that nothing else has decided. Block and Bypass answer at once.
// Redirect opens the Destinations dialog (`profileDialog=default-rule`, spec p2 9.5) because it is not a state without a place: the
// dialog says, before Save, what the Redirect does not touch (D42: Iranian names keep their state) and, when a Redirect is already set,
// that the new place applies to every undecided name at once. The row shows the flag and place of a saved Redirect on the button, as the
// service cards do.
//
// A Redirect with no shared destination (the location set is empty and no Auto or Random) is shown and disabled with its reason
// (T-166), through the same three-state control as the services.

export function DefaultRuleRow({profileId, options, readOnly, onLearnMore}: {profileId: string; options: Options; readOnly: boolean; onLearnMore: (name: RowName) => void}) {
  const t = useTranslations("rules");
  const dialog = useUrlDialog("profileDialog");
  const writer = useOptionWriter(profileId);
  const targetName = useTargetName();
  const locations = useProfileLocations(profileId);
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const title = t("options.rows.default_rule.name");
  const action = defaultActionOf(options);
  const stored = withLocation(options.default_rule?.target, locations.data?.locations);
  // A locked profile has every control off but the lock switch (T-140), and a link, a bookmark or Back to `?profileDialog=default-rule` must not
  // open the dialog with a live Save on it (S2-r1-5).
  const wanted = parseProfileDialog(dialog.value) === "default-rule";
  const open = !readOnly && wanted;
  // The parameter does not stay behind the guard: unlocking in the same page would open the dialog with no one asking, and so would an old
  // refusal's error shown in it (S2-r2-3).
  const closeDialog = dialog.close;
  useEffect(() => {
    if (readOnly && wanted) closeDialog();
  }, [readOnly, wanted, closeDialog]);
  if (!open && error !== null) setError(null);
  // While the set has not arrived Redirect is offered: a false "no destination" would be worse than a dialog that says it.
  const hasDestination = locations.data ? locations.data.locations.length > 0 || locations.data.auto_random : true;

  function change(next: DefaultAction) {
    if (next === "redirect") return dialog.open("default-rule");
    if (next !== action) void writer.sendQuietly({default_rule: {action: next}}, t("options.failed", {name: title}));
  }

  async function save(target: Target) {
    setSaving(true);
    setError(null);
    const failed = await writer.send({default_rule: {action: "redirect", target}});
    setSaving(false);
    if (failed === null) dialog.close();
    else setError(failed);
  }

  const where = action === "redirect" ? targetName(stored) : "";
  const flag = stored?.kind === "location" && stored.location?.country ? <Flag code={stored.location.country} /> : <Icon name="globe" className="size-4" />;

  /** What the dialog says before Save: D42 always (T-523), and the move of every undecided name when a saved Redirect would change place (T-178). */
  const notice = (drafted: Target | null) => {
    const picked = withLocation(drafted ?? undefined, locations.data?.locations);
    return (
      <div className="flex flex-col gap-2">
        <Alert status="warning" data-testid="d42-notice">
          <Alert.Indicator />
          <Alert.Content className="min-w-0">
            <Alert.Title>{t("options.defaultRule.d42Title")}</Alert.Title>
            <Alert.Description>{t("options.defaultRule.d42Text")}</Alert.Description>
          </Alert.Content>
        </Alert>
        {action === "redirect" && picked && !sameTarget(picked, stored) ? (
          <Alert status="warning" data-testid="location-change-notice">
            <Alert.Indicator />
            <Alert.Content className="min-w-0">
              <Alert.Title>{t("options.defaultRule.changeTitle")}</Alert.Title>
              <Alert.Description>{t("options.defaultRule.changeText", {from: targetName(stored), to: targetName(picked)})}</Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}
      </div>
    );
  };

  return (
    <OptionRow
      name="default_rule"
      title={title}
      description={t("options.rows.default_rule.description")}
      onLearnMore={onLearnMore}
      control={
        <ThreeStateControl
          value={action}
          onChange={(next) => next !== "inherit" && change(next)}
          subject={title}
          choices={["block", "bypass", "redirect"]}
          hasDestination={hasDestination}
          locationUnavailable={options.default_location_unavailable && action === "redirect"}
          destination={action === "redirect" ? flag : undefined}
          destinationName={where || undefined}
          onOpenDestination={() => dialog.open("default-rule")}
          isDisabled={readOnly}
        />
      }
    >
      {action === "redirect" ? (
        <p className="text-muted text-xs" data-testid="default-rule-where">
          {t("options.defaultRule.flag", {where})}
        </p>
      ) : null}
      <DestinationsDialog
        isOpen={open}
        onClose={() => {
          setError(null);
          dialog.close();
        }}
        source={{profileId}}
        subject={title}
        value={stored}
        onSave={save}
        isSaving={saving}
        error={error}
        notice={notice}
      />
    </OptionRow>
  );
}
