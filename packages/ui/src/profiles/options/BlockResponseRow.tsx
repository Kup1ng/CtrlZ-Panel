"use client";

import type {Options} from "@ctrlz/api-client/hooks/options.ts";
import {ListBox, Select} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {CustomPairForm} from "./CustomPairForm.tsx";
import {OptionRow} from "./OptionRow.tsx";
import {BLOCK_MODES, blockCustomProblems, customBody, type BlockMode, type CustomDraft, type OptionRow as RowName} from "./optionModel.ts";
import {useFocusBack} from "./useFocusBack.ts";
import {useOptionWriter} from "./useOptionWriter.ts";

// Block Response (T-205): `0.0.0.0` and `::` (the default), NXDOMAIN, REFUSED, and Custom with two fields. Branded is listed and cannot be
// chosen until P4b builds the block page (open question 9). The three plain modes answer at once. Custom opens its two fields in
// place with Save; until it is saved the stored mode stays in force and Cancel puts the select back to it.

export function BlockResponseRow({profileId, options, readOnly, onLearnMore}: {profileId: string; options: Options; readOnly: boolean; onLearnMore: (name: RowName) => void}) {
  const t = useTranslations("rules");
  const writer = useOptionWriter(profileId);
  const title = t("options.rows.block_response.name");
  const stored = options.block_response;
  const storedMode: BlockMode = stored?.mode ?? "zero";
  const [picking, setPicking] = useState(false);
  // The fields start again from the stored values when this changes (Cancel). It must NOT follow the stored value: a write shows its new value
  // before the answer, and a refusal puts the old one back, and the form that sent it keeps its draft and its error through both.
  const [epoch, setEpoch] = useState(0);
  const shown: BlockMode = picking ? "custom" : storedMode;
  // Cancel closes the form with the focused button in it; the focus goes back to the select (S2-r1-3).
  // A Cancel with the stored mode already Custom leaves `shown` as it was and only starts the fields again, so the epoch counts as a close too (S2-r2-2).
  const selectRef = useFocusBack<HTMLDivElement>(shown === "custom", epoch);
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

  function choose(next: string) {
    if (!(BLOCK_MODES as readonly string[]).includes(next) || next === "branded") return;
    if (next === "custom") return setPicking(true);
    setPicking(false);
    if (next !== storedMode) void writer.sendQuietly({block_response: {mode: next as "zero" | "nxdomain" | "refused"}}, t("options.failed", {name: title}));
  }

  return (
    <OptionRow
      name="block_response"
      title={title}
      description={t("options.rows.block_response.description")}
      onLearnMore={onLearnMore}
      control={
        <Select ref={selectRef} aria-label={title} variant="secondary" isDisabled={readOnly} value={shown} onChange={(key) => typeof key === "string" && choose(key)} className="w-56">
          <Select.Trigger>
            <Select.Value />
            <Select.Indicator />
          </Select.Trigger>
          <Select.Popover>
            <ListBox aria-label={t("options.blockResponse.group")}>
              {BLOCK_MODES.map((mode) => (
                <ListBox.Item key={mode} id={mode} textValue={t(`options.blockResponse.mode.${mode}`)} isDisabled={mode === "branded"}>
                  {t(`options.blockResponse.mode.${mode}`)}
                  <ListBox.ItemIndicator />
                </ListBox.Item>
              ))}
            </ListBox>
          </Select.Popover>
        </Select>
      }
    >
      <p className="text-muted text-xs" aria-live="polite" data-testid="block_response-text">
        {t(`options.blockResponse.modeText.${shown}`)}
      </p>
      {shown === "custom" ? (
        <CustomPairForm
          key={epoch}
          subject={title}
          initial={initial}
          labels={{v4: t("options.blockResponse.v4"), v6: t("options.blockResponse.v6")}}
          placeholder={{v4: t("options.blockResponse.v4Example")}}
          rename={{"/block_response/v4": "v4", "/block_response/v6": "v6"}}
          readOnly={readOnly}
          focusFirst={picking}
          validate={(draft) => {
            const problems = blockCustomProblems(draft);
            if (problems.v4 || problems.v6 || problems.needOne) {
              return {
                ...(problems.v4 ? {v4: t("options.blockResponse.invalidV4")} : {}),
                ...(problems.v6 ? {v6: t("options.blockResponse.invalidV6")} : {}),
                ...(problems.needOne ? {form: t("options.blockResponse.needOne")} : {}),
              };
            }
            return null;
          }}
          onSave={async (draft) => {
            const error = await writer.send({block_response: {mode: "custom", ...customBody(draft)}});
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
