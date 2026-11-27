"use client";

import type {Profile} from "@ctrlz/api-client/hooks/profiles.ts";
import {createContext, useContext} from "react";

// What every screen under `/profiles/[id]` gets from the frame (ProfileFrame.tsx). A screen calls `useProfileFrame()` and never reads the
// profile itself: the frame has already loaded it, shown its 404, and put the lock banner above the page.
//
//   profile        the profile, as the list has it (name, kind, counts, lock, disabled_until)
//   locked         the profile is locked: EVERY write control of the screen is disabled (spec p2 9.3, 7.3). The API is the gate and
//                  answers 423 `profile_locked` to a write that slips through; the controls are disabled so nobody meets that.
//   readOnly       `locked` as the prop a control takes (`isDisabled={readOnly}`)
//   openLock/openUnlock  the state-only dialogs of the lock (the Options screen's Lock Profile row calls them)

export type ProfileFrameValue = {
  profile: Profile;
  locked: boolean;
  readOnly: boolean;
  openLock: () => void;
  openUnlock: () => void;
};

export const ProfileFrameContext = createContext<ProfileFrameValue | null>(null);

export function useProfileFrame(): ProfileFrameValue {
  const value = useContext(ProfileFrameContext);
  if (!value) throw new Error("useProfileFrame needs the ProfileFrame of /profiles/[id]");
  return value;
}
