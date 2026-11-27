"use client";

import {AlertDialog, Button, toast} from "@heroui/react";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useDeleteProfile, type Profile} from "@ctrlz/api-client/hooks/profiles.ts";
import {Link, useRouter} from "@ctrlz/i18n/navigation.ts";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {parseProfileDialog} from "../dialog/dialogValues.ts";
import {writePushed, type UrlDialog} from "../dialog/useUrlDialog.ts";
import {useErrorText} from "../feedback/errorText.ts";
import {endpointHref} from "../endpoints/endpointRoutes.ts";
import {profilesHref} from "./profileRoutes.ts";

// Spec p2 9.2, 3.3, WF "Profiles" (T-132). `profileDialog=delete`: a confirmation. A profile that an Endpoint (or a schedule window) still
// uses is 409 `profile_in_use` and cannot be deleted, so the dialog says that up front when it knows the Endpoints, names them as links,
// and keeps Delete off; when the page's copy was out of date and the API answers `profile_in_use` anyway, the same words appear.
// A locked profile is not deletable either (423): the header already disables the button, and a dialog opened by its address, or over a lock
// taken in another session, says so in its own words and keeps Delete off. What the dialog learned (`refused`, `failure`) is dropped
// whenever it is not open, so closing it with Back does not leave a refusal for the next time.

export function DeleteProfileDialog({dialog, profile}: {dialog: UrlDialog; profile: Profile}) {
  const t = useTranslations("profiles");
  const c = useTranslations("common");
  const errorText = useErrorText();
  const router = useRouter();
  const del = useDeleteProfile();
  const open = parseProfileDialog(dialog.value) === "delete";
  const [refused, setRefused] = useState(false);
  const [lockedNow, setLockedNow] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const busy = useRef(false);

  // State is set in the render, from what changed, which React allows: a closed dialog holds nothing from its last opening.
  if (!open && (refused || lockedNow || failure !== null)) {
    setRefused(false);
    setLockedNow(false);
    setFailure(null);
  }

  const locked = profile.locked === true || lockedNow;
  const inUse = !locked && (profile.endpoints.length > 0 || refused);
  const blocked = locked || inUse;

  async function confirm() {
    if (busy.current || blocked) return;
    busy.current = true;
    setFailure(null);
    try {
      await del.mutateAsync(profile.id);
      toast.success(t("dialogs.delete.done", {name: profile.name}));
      writePushed("profileDialog", false);
      router.replace(profilesHref);
    } catch (error) {
      if (hasCode(error, "profile_in_use")) setRefused(true);
      else if (hasCode(error, "profile_locked")) setLockedNow(true);
      else setFailure(error);
    } finally {
      busy.current = false;
    }
  }

  return (
    <AlertDialog.Backdrop
      isOpen={open}
      onOpenChange={(next) => {
        if (!next && !del.isPending) dialog.close();
      }}
      variant="opaque"
      isDismissable={!del.isPending}
    >
      <AlertDialog.Container placement="center">
        <AlertDialog.Dialog className="sm:max-w-[440px]">
          <AlertDialog.CloseTrigger aria-label={c("close")} />
          <AlertDialog.Header>
            <AlertDialog.Icon status="danger" />
            <AlertDialog.Heading>{t("dialogs.delete.title", {name: profile.name})}</AlertDialog.Heading>
          </AlertDialog.Header>
          <AlertDialog.Body>
            {locked ? (
              <div className="flex flex-col gap-2" data-testid="delete-locked">
                <p className="text-sm font-medium">{t("dialogs.delete.lockedTitle")}</p>
                <p className="text-sm">{t("dialogs.delete.lockedText")}</p>
              </div>
            ) : inUse ? (
              <div className="flex flex-col gap-2" data-testid="delete-in-use">
                <p className="text-sm font-medium">{t("dialogs.delete.inUseTitle")}</p>
                <p className="text-sm">{t("dialogs.delete.inUseText")}</p>
                {profile.endpoints.length > 0 ? (
                  <ul className="flex flex-col gap-1 text-sm">
                    {profile.endpoints.map((e) => (
                      <li key={e.id}>
                        <Link href={endpointHref(e.id, "clients")} className="underline underline-offset-2">
                          {e.name}
                        </Link>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ) : (
              <p className="text-sm">{t("dialogs.delete.text", {name: profile.name})}</p>
            )}
            {failure ? (
              <p role="alert" className="text-danger-soft-foreground mt-2 text-sm">
                {errorText(failure)}
              </p>
            ) : null}
          </AlertDialog.Body>
          <AlertDialog.Footer>
            <Button slot="close" variant="tertiary" isDisabled={del.isPending}>
              {c("cancel")}
            </Button>
            <Button variant="danger" isPending={del.isPending} isDisabled={blocked} onPress={() => void confirm()}>
              {t("dialogs.delete.submit")}
            </Button>
          </AlertDialog.Footer>
        </AlertDialog.Dialog>
      </AlertDialog.Container>
    </AlertDialog.Backdrop>
  );
}
