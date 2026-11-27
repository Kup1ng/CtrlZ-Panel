"use client";

// /profiles/[id]/options (spec p2 9.7, WF "Profile Options", package S2 of P2): the full-width rows of the profile's options, each with its
// icon, name, a description with Learn more and the control at the end; a value that needs more room opens in place with Save (T-215).
// The rows, in the order of Plan "Profile Options" without AI Malware (D5) and Compatibility Mode (D9):
//
//   Default Rule (three-state, Redirect through the Destinations dialog), Block DNS Exfiltration, DNS Rebind Protection, Disable DNSSEC,
//   Block, Redirect and Bypass TTL, Block Response, ECS, DNS64, CNAME Flattening, Safe Search, Restricted YouTube, Disable, Lock Profile.
//
// What the frame gives it (useProfileFrame): the profile, and `readOnly` while it is locked, which disables every control but the lock
// switch. The options are one query (`GET /options`), and a write shows its new value at once and takes it back on a refusal.

import {useProfileOptions} from "@ctrlz/api-client/hooks/options.ts";
import {Skeleton} from "@heroui/react";
import {useTranslations} from "next-intl";

import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {SectionError} from "../feedback/SectionError.tsx";
import {useProfileFrame} from "./ProfileFrameContext.tsx";
import {BlockResponseRow} from "./options/BlockResponseRow.tsx";
import {DefaultRuleRow} from "./options/DefaultRuleRow.tsx";
import {DisableRow} from "./options/DisableRow.tsx";
import {EcsRow} from "./options/EcsRow.tsx";
import {LockRow} from "./options/LockRow.tsx";
import {SwitchOptionRow} from "./options/SwitchOptionRow.tsx";
import {TtlOptionRow} from "./options/TtlOptionRow.tsx";
import type {OptionRow, SwitchOption} from "./options/optionModel.ts";
import {OPTION_ROWS, SWITCH_OPTIONS, TTL_OPTIONS} from "./options/optionModel.ts";

export function ProfileOptionsScreen({profileId}: {profileId: string}) {
  const t = useTranslations("rules");
  const {profile, readOnly} = useProfileFrame();
  const options = useProfileOptions(profileId);
  const help = useUrlDialog("helpPane");
  const learnMore = (name: OptionRow) => help.open(`option.${name}`);

  return (
    <div data-screen="profile-options" className="flex flex-col gap-3">
      <h2 className="sr-only">{t("options.title")}</h2>
      {options.isError && !options.data ? (
        <SectionError error={options.error} onRetry={() => void options.refetch()} />
      ) : !options.data ? (
        <div role="status" aria-label={t("options.loading")} className="flex flex-col gap-2">
          {OPTION_ROWS.slice(0, 5).map((row) => (
            <Skeleton key={row} className="h-[4.5rem] w-full rounded-(--radius-box)" />
          ))}
        </div>
      ) : (
        <ul aria-label={t("options.title")} className="flex flex-col gap-2">
          {OPTION_ROWS.map((row) => {
            const data = options.data;
            if ((SWITCH_OPTIONS as readonly string[]).includes(row)) {
              return <SwitchOptionRow key={row} profileId={profileId} options={data} name={row as SwitchOption} readOnly={readOnly} onLearnMore={learnMore} />;
            }
            if ((TTL_OPTIONS as readonly string[]).includes(row)) {
              return <TtlOptionRow key={row} profileId={profileId} options={data} name={row as (typeof TTL_OPTIONS)[number]} readOnly={readOnly} onLearnMore={learnMore} />;
            }
            switch (row) {
              case "default_rule":
                return <DefaultRuleRow key={row} profileId={profileId} options={data} readOnly={readOnly} onLearnMore={learnMore} />;
              case "block_response":
                return <BlockResponseRow key={row} profileId={profileId} options={data} readOnly={readOnly} onLearnMore={learnMore} />;
              case "ecs":
                return <EcsRow key={row} profileId={profileId} options={data} readOnly={readOnly} onLearnMore={learnMore} />;
              case "disable":
                return <DisableRow key={row} profile={profile} readOnly={readOnly} onLearnMore={learnMore} />;
              case "lock":
                return <LockRow key={row} onLearnMore={learnMore} />;
              default:
                return null;
            }
          })}
        </ul>
      )}
    </div>
  );
}
