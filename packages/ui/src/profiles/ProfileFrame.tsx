"use client";

import {Alert, Button, Dropdown, Label, Skeleton, toast} from "@heroui/react";
import {fetchProfileDocument, useProfile, useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {isUuid} from "@ctrlz/api-client/hooks/support.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {usePathname, useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useCallback, useMemo, useState, type ReactNode} from "react";

import {ReauthProvider} from "../auth/ReauthDialog.tsx";
import {downloadJson} from "../data/download.ts";
import {useDeviceDialog} from "../dialog/useDeviceDialog.ts";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {useErrorText} from "../feedback/errorText.ts";
import {SectionError} from "../feedback/SectionError.tsx";
import {LockProfileDialog, UnlockProfileDialog} from "../locks/LockDialogs.tsx";
import {FrameTabs} from "../screens/FrameTabs.tsx";
import {PageHeader} from "../shell/PageHeader.tsx";
import {NotFoundView} from "../shell/NotFoundView.tsx";
import {ProfileSwitcher} from "../shell/ProfileSwitcher.tsx";
import {EndpointDialogs} from "../endpoints/EndpointDialogs.tsx";
import {ProfileDialogs} from "./ProfileDialogs.tsx";
import {ProfileFrameContext, type ProfileFrameValue} from "./ProfileFrameContext.tsx";
import {endpointHref} from "../endpoints/endpointRoutes.ts";
import {PROFILE_TABS, profileHref, profileTabOf, switchProfileHref} from "./profileRoutes.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec p2 9.3, WF "Profiles" (the header of a profile). The layout of `/profiles/[id]/*`:
//
//   [switcher] [icon] name / last change            [Endpoint menu or Add Endpoint]
//   [Duplicate] [Delete] [Export] [Lock]
//   [Filters] [Services] [Rules] [Options]     pill tabs, links
//   the lock banner, when the profile is locked
//   the screen
//
// What it owns: the profile (one query, shared with the list), the 404 of an id that is not one or that the API does not know (the text
// never says which: spec 14.3), the lock banner and the read-only state of every screen under it, the state-only lock dialogs, and the
// URL dialogs that act on a profile (`profileDialog=duplicate|delete`, drawn by `ProfileDialogs`) and the Endpoint dialogs, since Add Endpoint of the header opens one (`EndpointDialogs`, with
// this profile as its default). A screen gets the profile and the lock
// from `useProfileFrame()`.

export function ProfileFrame({id, children}: {id: string; children: ReactNode}) {
  const t = useTranslations("profiles");
  const valid = isUuid(id);
  const query = useProfile(id);

  // An id that is not a UUID is a page that does not exist: no request carried it (support.ts).
  if (!valid || (query.isError && (query.error as {code?: string} | null)?.code === "not_found")) return <NotFoundView />;
  if (query.isError && !query.data) return <SectionError error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) {
    return (
      <div role="status" aria-label={t("frame.loading")} className="flex flex-col gap-3">
        <Skeleton className="h-10 w-1/2" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }
  return (
    <ReauthProvider>
      <ProfileFrameBody profile={query.data}>{children}</ProfileFrameBody>
    </ReauthProvider>
  );
}

function ProfileFrameBody({profile, children}: {profile: ProfileFrameValue["profile"]; children: ReactNode}) {
  const t = useTranslations("profiles");
  const format = useAppFormat();
  const router = useRouter();
  const pathname = usePathname();
  const errorText = useErrorText();
  const list = useProfiles();
  const profileDialog = useUrlDialog("profileDialog");
  const devices = useDeviceDialog();
  const [lockDialog, setLockDialog] = useState<"lock" | "unlock" | null>(null);
  const [exporting, setExporting] = useState(false);

  const locked = profile.locked;
  const tab = profileTabOf(pathname);
  const value = useMemo<ProfileFrameValue>(
    () => ({profile, locked, readOnly: locked, openLock: () => setLockDialog("lock"), openUnlock: () => setLockDialog("unlock")}),
    [profile, locked],
  );

  const exportProfile = useCallback(async () => {
    setExporting(true);
    try {
      downloadJson(`ctrlz-profile-${profile.name}`, await fetchProfileDocument(profile.id));
    } catch (error) {
      toast.danger(errorText(error));
    } finally {
      setExporting(false);
    }
  }, [profile.id, profile.name, errorText]);

  const subtitle = profile.disabled_until ? t("frame.disabledUntil", {when: format.dateTime(profile.disabled_until)}) : t("frame.subtitle", {when: format.relative(profile.updated_at)});
  const switcherProfiles = (list.data ?? [{id: profile.id, name: profile.name}]).map((p) => ({id: p.id, name: p.name}));

  return (
    <ProfileFrameContext value={value}>
      <PageHeader
        icon="profiles"
        title={profile.name}
        subtitle={subtitle}
        helpKey="profiles"
        leading={
          <ProfileSwitcher
            profiles={switcherProfiles}
            value={profile.id}
            onChange={(next) => router.push(switchProfileHref(pathname, next))}
          />
        }
      />

      <div className="profile-frame__actions flex flex-wrap items-center gap-2" data-testid="profile-actions">
        <EndpointMenu profile={profile} onAdd={() => devices.open("add")} />
        <Button size="sm" variant="outline" aria-label={t("frame.duplicateAria", {name: profile.name})} onPress={() => profileDialog.open("duplicate")}>
          <Icon name="copy" className="size-4" />
          {t("frame.duplicate")}
        </Button>
        <Button size="sm" variant="outline" aria-label={t("frame.deleteAria", {name: profile.name})} isDisabled={locked} onPress={() => profileDialog.open("delete")}>
          <Icon name="trash" className="size-4" />
          {t("frame.delete")}
        </Button>
        <Button size="sm" variant="outline" aria-label={t("frame.exportAria", {name: profile.name})} isPending={exporting} onPress={() => void exportProfile()}>
          <Icon name="download" className="size-4" />
          {t("frame.export")}
        </Button>
        {locked ? (
          <Button size="sm" variant="outline" aria-label={t("lock.banner.unlockAria", {name: profile.name})} onPress={value.openUnlock}>
            <Icon name="unlock" className="size-4" />
            {t("lock.banner.unlock")}
          </Button>
        ) : (
          <Button size="sm" variant="outline" aria-label={t("frame.lockAria", {name: profile.name})} onPress={value.openLock}>
            <Icon name="lock" className="size-4" />
            {t("lock.dialog.lock")}
          </Button>
        )}
      </div>

      {locked ? <LockBanner name={profile.name} message={profile.lock_message} onUnlock={value.openUnlock} /> : null}

      <FrameTabs
        label={t("frame.tabsLabel", {name: profile.name})}
        current={tab}
        tabs={PROFILE_TABS.map((id) => ({id, label: t(`frame.tabs.${id}`), href: profileHref(profile.id, id)}))}
      />

      <div className="profile-frame__content" data-locked={locked || undefined}>
        {children}
      </div>

      <ProfileDialogs profile={profile} />
      {/* Add Endpoint of the header opens `deviceDialog=add`, and the dialog starts on this profile (T-137). */}
      <EndpointDialogs defaultProfileId={profile.id} />
      <LockProfileDialog isOpen={lockDialog === "lock"} onClose={() => setLockDialog(null)} profile={profile} />
      <UnlockProfileDialog isOpen={lockDialog === "unlock"} onClose={() => setLockDialog(null)} profile={profile} />
    </ProfileFrameContext>
  );
}

function LockBanner({name, message, onUnlock}: {name: string; message?: string; onUnlock: () => void}) {
  const t = useTranslations("profiles");
  return (
    <Alert status="warning" role="status" className="profile-frame__lock">
      <Alert.Indicator />
      <Alert.Content className="min-w-0">
        <Alert.Title>{t("lock.banner.title")}</Alert.Title>
        <Alert.Description className="[overflow-wrap:anywhere]">
          {t("lock.banner.text")}
          {message ? (
            <>
              <br />
              <bdi>{t("lock.banner.message", {message})}</bdi>
            </>
          ) : null}
        </Alert.Description>
      </Alert.Content>
      <Button size="sm" variant="secondary" aria-label={t("lock.banner.unlockAria", {name})} onPress={onUnlock}>
        {t("lock.banner.unlock")}
      </Button>
    </Alert>
  );
}

/** Add Endpoint for a profile that has none, or the menu of the Endpoints that use it (P3 10, T-137). */
function EndpointMenu({profile, onAdd}: {profile: ProfileFrameValue["profile"]; onAdd: () => void}) {
  const t = useTranslations("profiles");
  if (profile.endpoints.length === 0) {
    return (
      <PrimaryButton size="sm" aria-label={t("frame.addEndpointAria", {name: profile.name})} onPress={onAdd}>
        <Icon name="plus" className="size-4" />
        {t("frame.addEndpoint")}
      </PrimaryButton>
    );
  }
  return (
    <Dropdown>
      <Button size="sm" variant="outline" aria-label={t("frame.endpointsAria", {name: profile.name})}>
        <Icon name="endpoints" className="size-4" />
        {t("frame.endpoints")}
        <Icon name="chevron" className="size-3.5 rotate-90" />
      </Button>
      <Dropdown.Popover placement="bottom start">
        <Dropdown.Menu aria-label={t("frame.endpointsAria", {name: profile.name})}>
          {profile.endpoints.map((e) => (
            <Dropdown.Item key={e.id} id={e.id} textValue={e.name} href={endpointHref(e.id, "clients")}>
              <Label>{e.name}</Label>
            </Dropdown.Item>
          ))}
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  );
}
