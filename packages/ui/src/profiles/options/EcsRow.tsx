"use client";

import type {Options} from "@ctrlz/api-client/hooks/options.ts";
import {ToggleButton, ToggleButtonGroup} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {CustomPairForm} from "./CustomPairForm.tsx";
import {OptionRow} from "./OptionRow.tsx";
import {customBody, ecsCustomProblems, ECS_MODES, type CustomDraft, type EcsMode, type OptionRow as RowName} from "./optionModel.ts";
import {useFocusBack} from "./useFocusBack.ts";
import {useOptionWriter} from "./useOptionWriter.ts";

// EDNS client subnet (T-210): No ECS (the default), Auto, and Custom with an IPv4 subnet and an IPv6 subnet. A unit, stored and merged
// as one (SC 6). No ECS and Auto answer at once; Custom opens its fields in place with Save. A subnet with bits set after its prefix
// is refused here and by the API (spec p2 3.7), and the text says what to write instead.

export function EcsRow({profileId, options, readOnly, onLearnMore}: {profileId: string; options: Options; readOnly: boolean; onLearnMore: (name: RowName) => void}) {
  const t = useTranslations("rules");
  const writer = useOptionWriter(profileId);
  const title = t("options.rows.ecs.name");
  const stored = options.ecs;
  const storedMode: EcsMode = stored?.mode ?? "none";
  const [picking, setPicking] = useState(false);
  // The fields start again from the stored values when this changes (Cancel). It must NOT follow the stored value: a write shows its new value
  // before the answer, and a refusal puts the old one back, and the form that sent it keeps its draft and its error through both.
  const [epoch, setEpoch] = useState(0);
  const shown: EcsMode = picking ? "custom" : storedMode;
  // Cancel closes the form with the focused button in it; the focus goes back to the mode group (S2-r1-3).
  // A Cancel with the stored mode already Custom leaves `shown` as it was and only starts the fields again, so the epoch counts as a close too (S2-r2-2).
  const groupRef = useFocusBack<HTMLDivElement>(shown === "custom", epoch);
  // The profile got locked: an unsaved draft is dropped, and the fields show what is stored, off (S2-r2-6).
  const [wasReadOnly, setWasReadOnly] = useState(readOnly);
  if (readOnly !== wasReadOnly) {
    setWasReadOnly(readOnly);
    if (readOnly) {
      setPicking(false);
      setEpoch((n) => n + 1);
    }
  }
  const initial: CustomDraft = {v4: stored?.mode === "custom" ? (stored.v4 ?? "") : "", v6: stored?.mode === "custom" ? (stored.v6 ?? "") : ""};

  function choose(next: EcsMode) {
    if (next === "custom") return setPicking(true);
    setPicking(false);
    if (next !== storedMode) void writer.sendQuietly({ecs: {mode: next}}, t("options.failed", {name: title}));
  }

  return (
    <OptionRow
      name="ecs"
      title={title}
      description={t("options.rows.ecs.description")}
      onLearnMore={onLearnMore}
      control={
        <ToggleButtonGroup
          ref={groupRef}
          aria-label={`${title}: ${t("options.ecs.group")}`}
          selectionMode="single"
          disallowEmptySelection
          size="sm"
          isDisabled={readOnly}
          selectedKeys={[shown]}
          onSelectionChange={(keys) => {
            const next = [...keys][0];
            if (typeof next === "string" && (ECS_MODES as readonly string[]).includes(next) && next !== shown) choose(next as EcsMode);
          }}
        >
          {ECS_MODES.map((mode, index) => (
            <ToggleButton key={mode} id={mode} aria-label={`${t(`options.ecs.mode.${mode}`)}: ${title}`}>
              {index > 0 ? <ToggleButtonGroup.Separator /> : null}
              {t(`options.ecs.mode.${mode}`)}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
      }
    >
      <p className="text-muted text-xs" aria-live="polite" data-testid="ecs-text">
        {t(`options.ecs.modeText.${shown}`)}
      </p>
      {shown === "custom" ? (
        <CustomPairForm
          key={epoch}
          subject={title}
          initial={initial}
          labels={{v4: t("options.ecs.v4"), v6: t("options.ecs.v6")}}
          placeholder={{v4: t("options.ecs.v4Example")}}
          rename={{"/ecs/v4": "v4", "/ecs/v6": "v6"}}
          v4InputMode="text"
          readOnly={readOnly}
          focusFirst={picking}
          validate={(draft) => {
            const problems = ecsCustomProblems(draft);
            if (problems.v4 || problems.v6 || problems.needOne) {
              return {
                ...(problems.v4 ? {v4: t(`options.ecs.${problems.v4}`)} : {}),
                ...(problems.v6 ? {v6: t(`options.ecs.${problems.v6}`)} : {}),
                ...(problems.needOne ? {form: t("options.ecs.needOne")} : {}),
              };
            }
            return null;
          }}
          onSave={async (draft) => {
            const error = await writer.send({ecs: {mode: "custom", ...customBody(draft)}});
            if (error === null) setPicking(false);
            return error;
          }}
          onCancel={() => {
            setPicking(false);
            setEpoch((n) => n + 1);
          }}
        />
      ) : null}
    </OptionRow>
  );
}
