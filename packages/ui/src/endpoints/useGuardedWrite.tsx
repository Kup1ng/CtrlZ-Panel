"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {MAX_LOCK_PASSWORDS, needsLockPasswords, tooManyLockPasswords, type LockPasswords} from "@ctrlz/api-client/hooks/lockPasswords.ts";
import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useProfiles, type Profile} from "@ctrlz/api-client/hooks/profiles.ts";
import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useCallback, useState, type ReactNode} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {LockPasswordsDialog} from "../locks/LockDialogs.tsx";
import {lockCandidates, slotsAreLocked, widenLockAsk} from "./endpointModel.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec p3 3.3 and 3.4. Two answers of an Endpoint write ask the person something and then repeat the request:
//
//   423 `profile_locked` on `/lock_passwords`   a locked profile would leave a device: ask for its lock password (state-only dialog)
//   409 `destinations_lost`                      the change makes some destinations of a profile unavailable: ask to confirm
//
// `run(send, endpoints)` calls `send({})` and, on either answer, asks and calls `send` again with `lock_passwords` or
// `confirm_destinations: true`, so a screen writes its mutation once. A wrong password stays in the dialog (401 under the field of its
// profile), and Cancel on either dialog ends the call with `Cancelled`, which is no failure to show. Passwords live in the dialog's state and in
// the variables of one mutation; nothing here reaches a URL, a query key or storage (FE 9, 14.4).

export type WriteExtra = {lock_passwords?: LockPasswords; confirm_destinations?: boolean};
export type Send<T> = (extra: WriteExtra) => Promise<T>;

/** The person closed the dialog that asked for a password or a confirmation. Not an error to show. */
export class Cancelled extends Error {
  constructor() {
    super("cancelled");
    this.name = "Cancelled";
  }
}

type Asking = {
  profiles: Profile[];
  /** The profiles are a guess: the person fills in the passwords they know and the others stay empty. */
  optional: boolean;
  /** The first answer was not enough and this asks again, with more profiles. */
  more: boolean;
  submit: (passwords: LockPasswords) => Promise<"again" | void>;
  cancel: () => void;
};
type Confirming = {ok: () => void; cancel: () => void};

/**
 * `takesAll`: the change takes every profile of the slots away (Soft or Hard Disabled, Delete, Rotate, Require on), so each locked one is needed.
 * `reset`: the `reset` of the mutation `send` calls. React Query keeps the last variables of a mutation while its observer is mounted, and
 * the variables carry the lock passwords, so it is called when the run ends, however it ends. The password dialog closing is not enough,
 * because the form that owns the mutation stays open (S5-r3-9). A form's own error text is state of the form, so a reset loses nothing it shows.
 */
export type RunOptions = {takesAll?: boolean; reset?: () => void};

export function useGuardedWrite(): {
  run: <T>(send: Send<T>, endpoints: readonly Pick<Endpoint, "profile_id" | "profile2_id">[], options?: RunOptions) => Promise<T>;
  dialogs: ReactNode;
} {
  const profiles = useProfiles();
  const [asking, setAsking] = useState<Asking | null>(null);
  const [confirming, setConfirming] = useState<Confirming | null>(null);

  const confirm = useCallback(
    () =>
      new Promise<void>((resolve, reject) => {
        setConfirming({
          ok: () => {
            setConfirming(null);
            resolve();
          },
          cancel: () => {
            setConfirming(null);
            reject(new Cancelled());
          },
        });
      }),
    [],
  );

  const run = useCallback(
    <T,>(send: Send<T>, endpoints: readonly Pick<Endpoint, "profile_id" | "profile2_id">[], options: RunOptions = {}): Promise<T> => {
      const all = profiles.data ?? [];
      const locked = all.filter((p) => p.locked);
      const first = lockCandidates(endpoints, all).slice(0, MAX_LOCK_PASSWORDS);
      // Only a change that takes every slot profile away needs every locked one. An edit of one slot needs the profile it removes, and the
      // server ignores the passwords it does not need, so that ask is optional with at least one filled (S5-r2-1).
      const exact = options.takesAll === true && slotsAreLocked(endpoints, all);
      // The profiles asked for so far, and the confirmation once given: a second ask does not make the person confirm again.
      const asked = new Set<string>();
      const sticky: WriteExtra = {};

      // The 423 names no profile (p3 3.3), so the first ask is a guess: the locked profiles of the slots, else the tenant's. When the
      // passwords sent are not enough (a locked profile in a schedule window or a client), the same dialog asks again with the others,
      // keeping what was typed, until a request is accepted or there is no profile left to ask for.
      function ask(list: Profile[], optional: boolean, more: boolean, extra: WriteExtra): Promise<T> {
        list.forEach((p) => asked.add(p.id));
        return new Promise<T>((resolve, reject) => {
          setAsking({
            profiles: list,
            optional,
            more,
            submit: async (passwords) => {
              try {
                resolve(await attempt({...extra, lock_passwords: passwords}));
              } catch (error) {
                // Cancel on the confirmation that followed: the call ends, and the password dialog goes with it.
                if (error instanceof Cancelled) return reject(error);
                // No list of 8 satisfies the change: the password dialog goes, and the screen that asked says so in its own words.
                if (tooManyLockPasswords(error)) return reject(error);
                if (needsLockPasswords(error)) {
                  const wider = widenLockAsk(locked, asked, new Set(passwords.map((x) => x.profile_id)), MAX_LOCK_PASSWORDS);
                  if (wider.length > 0) {
                    ask(wider, true, true, extra).then(resolve, reject);
                    return "again";
                  }
                }
                throw error;
              }
            },
            cancel: () => reject(new Cancelled()),
          });
        });
      }

      async function attempt(given: WriteExtra): Promise<T> {
        const extra = {...given, ...sticky};
        try {
          return await send(extra);
        } catch (error) {
          if (hasCode(error, "destinations_lost") && !extra.confirm_destinations) {
            await confirm();
            sticky.confirm_destinations = true;
            return attempt(extra);
          }
          if (needsLockPasswords(error) && !extra.lock_passwords && first.length > 0) return ask(first, !exact, false, extra);
          throw error;
        }
      }
      return attempt({}).finally(() => options.reset?.());
    },
    [confirm, profiles.data],
  );

  const dialogs = (
    <>
      <LockPasswordsDialog
        isOpen={asking !== null}
        profiles={asking?.profiles ?? []}
        optional={asking?.optional ?? false}
        more={asking?.more ?? false}
        onClose={() => {
          asking?.cancel();
          setAsking(null);
        }}
        onSubmit={(passwords) => asking!.submit(passwords)}
      />
      <ConfirmDestinationsDialog confirming={confirming} />
    </>
  );
  return {run, dialogs};
}

function ConfirmDestinationsDialog({confirming}: {confirming: Confirming | null}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  return (
    <DialogFrame
      isOpen={confirming !== null}
      onClose={() => confirming?.cancel()}
      title={t("dialogs.destinations.title")}
      footer={
        <>
          <Button variant="tertiary" onPress={() => confirming?.cancel()}>
            {c("cancel")}
          </Button>
          <PrimaryButton onPress={() => confirming?.ok()}>
            {t("dialogs.destinations.continue")}
          </PrimaryButton>
        </>
      }
    >
      <p className="text-sm">{t("dialogs.destinations.text")}</p>
    </DialogFrame>
  );
}
