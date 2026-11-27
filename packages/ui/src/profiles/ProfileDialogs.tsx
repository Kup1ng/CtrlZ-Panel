"use client";

import type {Profile} from "@ctrlz/api-client/hooks/profiles.ts";
import {useState} from "react";

import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {AddProfileDialog} from "./AddProfileDialog.tsx";
import {DeleteProfileDialog} from "./DeleteProfileDialog.tsx";
import {DuplicateProfileDialog} from "./DuplicateProfileDialog.tsx";
import {FollowedJob} from "./FollowedJob.tsx";
import {followJob, newFollowOwner} from "./followedJob.ts";
import type {JobTarget} from "./jobTarget.ts";
import {ImportProfileDialog} from "./ImportProfileDialog.tsx";

// Spec p2 9.2 (T-128, T-131, T-132, T-134): the URL dialogs that act on profiles, `profileDialog=add|import|duplicate|delete`, parsed with
// `parseProfileDialog`. Two mounts, so each dialog is drawn once:
//
//   the list page (no `profile`)  add and import, which belong to the list
//   ProfileFrame (`profile`)      duplicate and delete, which belong to the open profile
//
// `default-rule` (the Default Rule's destination step, spec p2 9.5 and 9.7) is the Options screen's, and `profileDialog=default-rule` is
// not drawn here. Export is the frame's own button, and the lock dialogs are state-only (FE 9) and live in the frame.
//
// A job started from Import or Duplicate is followed by `FollowedJob`, which holds the job in a small store (`followedJob.ts`) and not in
// state of this component: closing the job dialog does not stop it, and it carries over from a profile's page to the list. The profile the
// job made is the one `Job.profile_id` names, and it is marked as new when the job ends (T-136).

export function ProfileDialogs({profile}: {profile?: Profile}) {
  const dialog = useUrlDialog("profileDialog");
  // The job dialog a job opens is this mount's: another mount that finds it open closes it (followedJob.ts, S1-r2-1).
  const [owner] = useState(newFollowOwner);
  const onJob = (target: JobTarget) => followJob(target, owner);
  return (
    <>
      {profile ? (
        <>
          <DuplicateProfileDialog dialog={dialog} profile={profile} onJob={onJob} />
          <DeleteProfileDialog dialog={dialog} profile={profile} />
        </>
      ) : (
        <>
          <AddProfileDialog dialog={dialog} />
          <ImportProfileDialog dialog={dialog} onJob={onJob} />
        </>
      )}
      <FollowedJob owner={owner} />
    </>
  );
}
