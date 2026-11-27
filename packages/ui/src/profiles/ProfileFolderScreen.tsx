"use client";

// Spec p2 9.6, WF "Rules" (T-188, T-195): /profiles/[id]/custom-rules/[folderId]. The folder page: back, the folder's name and count, edit, delete with a
// confirmation, Export Rules and Upload Folder, and the rules inside it (the same list as the top level, over this folder).

import {AlertDialog, Button, buttonVariants, Chip, Skeleton, toast} from "@heroui/react";
import {fetchFolderDocument, useDeleteFolder, useFolders} from "@ctrlz/api-client/hooks/rules.ts";
import {isUuid} from "@ctrlz/api-client/hooks/support.ts";
import {Link, useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {downloadJson} from "../data/download.ts";
import {parseRuleDialog, ruleDialogValue} from "../dialog/dialogValues.ts";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {useErrorText} from "../feedback/errorText.ts";
import {SectionError} from "../feedback/SectionError.tsx";
import {NotFoundView} from "../shell/NotFoundView.tsx";
import {useProfileFrame} from "./ProfileFrameContext.tsx";
import {profileHref} from "./profileRoutes.ts";
import {RulesList} from "./rules/RulesList.tsx";
import {UploadDialog} from "./rules/UploadDialog.tsx";

export function ProfileFolderScreen({profileId, folderId}: {profileId: string; folderId: string}) {
  const t = useTranslations("rules");
  const c = useTranslations("common");
  const errorText = useErrorText();
  const router = useRouter();
  const {profile, readOnly} = useProfileFrame();
  const folders = useFolders(profileId);
  const remove = useDeleteFolder();
  const dialog = useUrlDialog("ruleDialog");
  const parsed = parseRuleDialog(dialog.value);
  const [confirming, setConfirming] = useState(false);
  const [exporting, setExporting] = useState(false);
  // Set when the delete is done and the page is on its way back: the refreshed folder list no longer has this folder, and that must not show as a 404.
  const [leaving, setLeaving] = useState(false);

  // A folder id that is not a UUID is a page that does not exist, and so is one the profile does not have (the text never says which).
  if (!isUuid(folderId)) return <NotFoundView />;
  const folder = folders.data?.find((f) => f.id === folderId);
  // A failed refetch keeps the folders that were read: only a list that never arrived is an error page.
  if (folders.isError && !folders.data) {
    return (
      <div data-screen="profile-folder">
        <SectionError error={folders.error} onRetry={() => void folders.refetch()} />
      </div>
    );
  }
  if (!folders.data || (!folder && leaving)) {
    return (
      <div data-screen="profile-folder" role="status" aria-label={t("list.loading")} className="flex flex-col gap-3">
        <Skeleton className="h-9 w-48" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }
  if (!folder) return <NotFoundView />;

  const backHref = profileHref(profileId, "rules");

  const exportRules = async () => {
    setExporting(true);
    try {
      downloadJson(`${folder.name}-rules`, await fetchFolderDocument(profileId, folder.id));
    } catch (e) {
      toast.danger(errorText(e));
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Link href={backHref} className={buttonVariants({variant: "ghost", size: "sm"})}>
          <Icon name="chevron" flip className="size-4 rotate-180" />
          {t("folderPage.back")}
        </Link>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" isDisabled={readOnly} aria-label={t("folder.edit", {name: folder.name})} onPress={() => dialog.open(ruleDialogValue({kind: "folder", folderId: folder.id}))}>
            <Icon name="edit" className="size-4" />
            {c("edit")}
          </Button>
          <Button size="sm" variant="secondary" isPending={exporting} aria-label={t("folderPage.exportAria", {name: folder.name})} onPress={() => void exportRules()}>
            <Icon name="download" className="size-4" />
            {t("folderPage.export")}
          </Button>
          <Button size="sm" variant="secondary" isDisabled={readOnly} aria-label={t("folderPage.uploadAria", {name: folder.name})} onPress={() => dialog.open(ruleDialogValue({kind: "upload"}))}>
            <Icon name="upload" className="size-4" />
            {t("folderPage.upload")}
          </Button>
          <Button size="sm" variant="danger-soft" isDisabled={readOnly} aria-label={t("folderPage.deleteAria", {name: folder.name})} onPress={() => setConfirming(true)}>
            <Icon name="trash" className="size-4" />
            {c("delete")}
          </Button>
        </div>
      </div>

      <p className="text-muted flex flex-wrap items-center gap-2 text-xs" data-folder-info="">
        <SubIcon group="rules" name={folder.kind === "do_not_log" ? "folder-magic" : "folder"} className="size-4" />
        <Chip size="sm" variant="soft">
          <Chip.Label>{folder.kind === "do_not_log" ? t("folder.magicTag") : folder.action ? t("folder.action", {action: t(`action.${folder.action}`)}) : t("folder.noAction")}</Chip.Label>
        </Chip>
        {folder.location_unavailable ? (
          <span className="inline-flex items-center gap-1 text-(--warning-text)">
            <Icon name="warning" className="size-3.5" />
            {t("row.unavailable")}
          </span>
        ) : null}
      </p>

      <RulesList key={folder.id} profileId={profileId} folder={folder} />

      <UploadDialog isOpen={parsed?.kind === "upload" && !readOnly} onClose={dialog.close} profileId={profileId} folderId={folder.id} folderName={folder.name} />

      <AlertDialog.Backdrop isOpen={confirming} onOpenChange={(open) => !open && !remove.isPending && setConfirming(false)}>
        <AlertDialog.Container placement="center">
          <AlertDialog.Dialog className="sm:max-w-[400px]">
            <AlertDialog.CloseTrigger aria-label={c("close")} />
            <AlertDialog.Header>
              <AlertDialog.Icon status="danger">
                <Icon name="trash" className="size-5" />
              </AlertDialog.Icon>
              <AlertDialog.Heading>{t("folderPage.deleteTitle", {name: folder.name})}</AlertDialog.Heading>
            </AlertDialog.Header>
            <AlertDialog.Body>
              <p>{t("folderPage.deleteText", {count: folder.rule_count, profile: profile.name})}</p>
            </AlertDialog.Body>
            <AlertDialog.Footer>
              <Button slot="close" variant="tertiary" isDisabled={remove.isPending}>
                {c("cancel")}
              </Button>
              <Button
                variant="danger"
                isPending={remove.isPending}
                onPress={() =>
                  void remove.mutateAsync({profileId, folderId: folder.id}).then(
                    () => {
                      toast.success(t("folderPage.deleted", {name: folder.name}));
                      setConfirming(false);
                      setLeaving(true);
                      router.push(backHref);
                    },
                    (e: unknown) => {
                      toast.danger(errorText(e));
                      setConfirming(false);
                    },
                  )
                }
              >
                {t("folderPage.deleteConfirm")}
              </Button>
            </AlertDialog.Footer>
          </AlertDialog.Dialog>
        </AlertDialog.Container>
      </AlertDialog.Backdrop>
    </div>
  );
}
