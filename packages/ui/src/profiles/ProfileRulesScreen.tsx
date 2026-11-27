"use client";

// Spec p2 9.6, WF "Rules" (T-179 to T-181, T-184, T-186, T-189 to T-193, T-196, T-197): /profiles/[id]/custom-rules. The folders and the rules of one
// profile as a list in a window of the page, with selection mode, the rule dialog, the folder dialog, Copy, Move, group Edit and the jobs. The
// whole of it is `rules/RulesList`, which the folder page shares.

import {RulesList} from "./rules/RulesList.tsx";

export function ProfileRulesScreen({profileId}: {profileId: string}) {
  return <RulesList profileId={profileId} />;
}
