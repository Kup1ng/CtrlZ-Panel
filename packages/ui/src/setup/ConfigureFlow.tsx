"use client";

import {AlertDialog, Button, Skeleton} from "@heroui/react";
import {Segment} from "@heroui-pro/react";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useRef, useState, type RefObject} from "react";

import {ListRow, RowList} from "../data/ListRow.tsx";
import {useLeaveGuard} from "../dialog/useLeaveGuard.ts";
import {SectionError} from "../feedback/SectionError.tsx";
import {AppleBuilder} from "./AppleBuilder.tsx";
import {GeneratorBlock} from "./GeneratorBlock.tsx";
import {useGuide} from "./guide.ts";
import {
  PLATFORM_GROUPS,
  PLATFORMS,
  automaticOf,
  automaticPlatforms,
  platformOf,
  versionOf,
  type Platform,
} from "./platforms.ts";
import type {SetupNav, SetupSource} from "./setupSource.ts";
import {useSecretHold} from "./SecretHold.tsx";
import {ShareLinkPanel} from "./ShareLinkPanel.tsx";
import {Wizard} from "./Wizard.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Help Me Configure (spec p3 8.3, WF "Endpoints", T-241 to T-243): the four entries, the platform list, a platform's Automatic Setup and its
// step-by-step wizard. It does not know where it is drawn: the owner's dialog keeps `nav` (the platform and the step) in the address and
// the share page keeps it in state, and both pass the Resolver view, so the same steps give the same values in both places.
//
// A link that this flow makes (the setup link, the Apple profile link) is shown once and lives in state. So a step that would take its panel off the screen
// is refused while the call runs (the answer would land on nothing and leave a live link nobody saw) and asks first once the link is shown (S7-r2-2,
// S7-r2-9). That covers the Back button, the version picker and the start of the manual steps here, and the browser's Back through useLeaveGuard.
// The dialog's own close (the X, Escape) is locked while the call runs, and once the link is shown it asks the same question through `closeRef`: a close that
// went straight to the address would meet the guard's extra history entry on top and leave the dialog open or the history out of step (S7-r3-2).
//
// The entries are Automatic Setup (the platforms that have a generator or the Apple profile), Manual Setup (every platform), See Resolvers
// and Copy Setup Link. The share page has no Copy Setup Link (a link made from a link is not a thing) and its See Resolvers is its own view.

type Mode = "home" | "auto" | "manual" | "link";

export function ConfigureFlow({
  source,
  nav,
  onNavigate,
  onSeeResolvers,
  onDone,
  client = "",
  closeRef,
}: {
  source: SetupSource;
  nav: SetupNav;
  onNavigate: (next: SetupNav) => void;
  onSeeResolvers: () => void;
  onDone: () => void;
  /** The client the owner chose in Resolvers or at the top of the dialog: "" is the Endpoint itself. The share page has its link's own. */
  client?: string;
  /** Filled with the dialog's close request: the frame calls it for the X and Escape, and it asks first while a link is shown. */
  closeRef?: RefObject<(() => void) | null>;
}) {
  const t = useTranslations("setup");
  const c = useTranslations("common");
  const hold = useSecretHold();
  const [mode, setMode] = useState<Mode>("home");
  const [asking, setAsking] = useState<{go: () => void} | null>(null);
  const [leaving, setLeaving] = useState(false);
  const held = hold.pending || hold.shown;

  const guarded = (go: () => void) => {
    if (hold.pending) return;
    if (hold.shown) setAsking({go});
    else go();
  };

  // The browser's Back (and a swipe on a phone, a reload, a closed tab) while a link is made or shown. Only the owner's dialog is a place a Back
  // leaves: the share page is a page of its own, and Back there is the visitor's.
  useLeaveGuard(source.kind === "endpoint" && held && !leaving, () => {
    if (hold.shown && !hold.pending) setAsking({go: () => setLeaving(true)});
  });
  // The guard hands its extra history entry back once it ends, and the dialog closes only after that traversal, or the close would race it and the
  // address would be put back by the entry that is still on its way.
  const done = useRef(onDone);
  useEffect(() => {
    done.current = onDone;
  });
  useEffect(() => {
    if (!closeRef) return;
    closeRef.current = () => {
      if (source.kind === "endpoint" && hold.shown && !hold.pending) setAsking({go: () => setLeaving(true)});
      else if (!leaving) done.current();
    };
    return () => {
      closeRef.current = null;
    };
  }, [closeRef, source.kind, hold.shown, hold.pending, leaving]);
  useEffect(() => {
    if (!leaving) return;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      done.current();
    };
    window.addEventListener("popstate", finish, {once: true});
    const timer = setTimeout(finish, 400);
    return () => {
      window.removeEventListener("popstate", finish);
      clearTimeout(timer);
    };
  }, [leaving]);

  const platform = platformOf(nav.os);
  let flow;
  if (platform) {
    flow = <PlatformView key={platform.id} platform={platform} source={source} nav={nav} onNavigate={onNavigate} onDone={onDone} client={client} guard={guarded} busy={hold.pending} />;
  } else if (mode === "home") {
    flow = <Home source={source} onMode={setMode} onSeeResolvers={onSeeResolvers} />;
  } else if (mode === "link" && source.kind === "endpoint") {
    flow = (
      <div className="flex flex-col gap-3">
        <BackButton onPress={() => guarded(() => setMode("home"))} isDisabled={hold.pending} />
        <ShareLinkPanel endpointId={source.endpoint.id} endpointName={source.endpoint.name} initialClient={client} />
      </div>
    );
  } else {
    flow = <PickList source={source} mode={mode} onBack={() => setMode("home")} onNavigate={onNavigate} />;
  }

  return (
    <>
      {flow}
      <AlertDialog.Backdrop isOpen={asking !== null} onOpenChange={(open) => !open && setAsking(null)}>
        <AlertDialog.Container placement="center">
          <AlertDialog.Dialog className="sm:max-w-[400px]">
            <AlertDialog.CloseTrigger aria-label={c("close")} />
            <AlertDialog.Header>
              <AlertDialog.Icon status="warning">
                <Icon name="warning" className="size-5" />
              </AlertDialog.Icon>
              <AlertDialog.Heading>{t("leave.title")}</AlertDialog.Heading>
            </AlertDialog.Header>
            <AlertDialog.Body>
              <p>{t("leave.text")}</p>
            </AlertDialog.Body>
            <AlertDialog.Footer>
              <Button slot="close" variant="tertiary">
                {t("leave.keep")}
              </Button>
              <Button
                variant="danger"
                onPress={() => {
                  const go = asking?.go;
                  setAsking(null);
                  go?.();
                }}
              >
                {t("leave.go")}
              </Button>
            </AlertDialog.Footer>
          </AlertDialog.Dialog>
        </AlertDialog.Container>
      </AlertDialog.Backdrop>
    </>
  );
}

function PickList({source, mode, onBack, onNavigate}: {source: SetupSource; mode: Mode; onBack: () => void; onNavigate: (next: SetupNav) => void}) {
  const list = mode === "auto" ? automaticPlatforms().filter((p) => source.kind === "endpoint" || Object.values(p.automatic).some((a) => a.kind === "apple")) : [...PLATFORMS];
  return (
    <div className="flex flex-col gap-3">
      <BackButton onPress={onBack} />
      <PlatformList
        platforms={list}
        onPick={(p) => onNavigate({os: p.id, step: mode === "manual" ? 1 : null})}
        caption={mode === "auto" ? "configure.pickAutomatic" : "configure.pickManual"}
      />
    </div>
  );
}

function BackButton({onPress, isDisabled}: {onPress: () => void; isDisabled?: boolean}) {
  const t = useTranslations("setup");
  return (
    <Button variant="ghost" size="sm" onPress={onPress} isDisabled={isDisabled} className="self-start" data-testid="configure-back">
      <Icon name="chevron" className="size-4 rotate-180 rtl:rotate-0" />
      {t("configure.back")}
    </Button>
  );
}

function Home({source, onMode, onSeeResolvers}: {source: SetupSource; onMode: (mode: Mode) => void; onSeeResolvers: () => void}) {
  const t = useTranslations("setup");
  return (
    <div className="flex flex-col gap-3" data-testid="configure-home">
      <p className="text-muted text-sm">{t("configure.intro")}</p>
      <RowList aria-label={t("configure.intro")}>
        <ListRow icon={<Icon name="settings" className="size-5" />} title={t("configure.entries.automatic.title")} subtitle={t("configure.entries.automatic.text")} onPress={() => onMode("auto")} />
        <ListRow icon={<Icon name="rules" className="size-5" />} title={t("configure.entries.manual.title")} subtitle={t("configure.entries.manual.text")} onPress={() => onMode("manual")} />
        <ListRow icon={<Icon name="globe" className="size-5" />} title={t("configure.entries.resolvers.title")} subtitle={t("configure.entries.resolvers.text")} onPress={onSeeResolvers} />
        {source.kind === "endpoint" ? (
          <ListRow icon={<Icon name="link" className="size-5" />} title={t("configure.entries.link.title")} subtitle={t("configure.entries.link.text")} onPress={() => onMode("link")} />
        ) : null}
      </RowList>
    </div>
  );
}

function PlatformList({platforms, onPick, caption}: {platforms: readonly Platform[]; onPick: (platform: Platform) => void; caption: "configure.pickAutomatic" | "configure.pickManual"}) {
  const t = useTranslations("setup");
  return (
    <div className="flex flex-col gap-4" data-testid="platform-list">
      <p className="text-muted text-sm">{t(caption)}</p>
      {PLATFORM_GROUPS.map((group) => {
        const items = platforms.filter((p) => p.group === group);
        if (items.length === 0) return null;
        return (
          <section key={group} aria-label={t(`platforms.groups.${group}`)} className="flex flex-col gap-2">
            <h3 className="text-muted text-xs font-medium">{t(`platforms.groups.${group}`)}</h3>
            <ul className="grid grid-cols-2 gap-2">
              {items.map((p) => (
                <li key={p.id}>
                  <button
                    type="button"
                    onClick={() => onPick(p)}
                    data-platform={p.id}
                    className="bg-default hover:bg-default-hover focus-visible:ring-focus flex min-h-12 w-full items-center gap-2 rounded-(--radius-box) px-3 py-2 text-start outline-none focus-visible:ring-2"
                  >
                    <SubIcon group="setup" name={p.icon} className="size-5 shrink-0" />
                    <span className="min-w-0 text-sm">{t(`platforms.names.${p.id}`)}</span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

function PlatformView({
  platform,
  source,
  nav,
  onNavigate,
  onDone,
  client,
  guard,
  busy,
}: {
  platform: Platform;
  source: SetupSource;
  nav: SetupNav;
  onNavigate: (next: SetupNav) => void;
  onDone: () => void;
  client: string;
  /** Runs a step that takes the link panel off the screen: refused while the call runs, asked about once a link is shown. */
  guard: (go: () => void) => void;
  busy: boolean;
}) {
  const t = useTranslations("setup");
  const locale = useLocale();
  const guide = useGuide(locale, platform.id);
  // The version is in the address with the platform (platforms.ts parseSetupNav), so a reload or a shared link opens the steps that were on screen.
  const version = versionOf(platform, nav.version);
  const automatic = automaticOf(platform, version);
  // A generator needs a session; the share page can only offer the Apple profile of its own link.
  const offered = automatic && (automatic.kind === "apple" || source.kind === "endpoint") ? automatic : undefined;

  const back = () =>
    guard(() => {
      if (nav.step !== null && offered) onNavigate({os: platform.id, step: null, version});
      else onNavigate({os: null, step: null});
    });

  if (guide.status === "error") return <SectionError error={new Error("guide")} onRetry={guide.retry} />;
  if (guide.status === "loading") {
    return (
      <div role="status" aria-label={t("wizard.loading")} className="flex flex-col gap-3">
        <Skeleton className="h-8 w-1/2" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }
  const current = guide.guide.versions.find((v) => v.id === version) ?? guide.guide.versions[0]!;
  const steps = current.steps.length;
  const step = nav.step === null ? null : Math.min(Math.max(nav.step, 1), steps);
  const pickVersion = (id: string) => guard(() => onNavigate({os: platform.id, step: nav.step === null ? null : 1, version: id}));

  return (
    <div className="flex flex-col gap-4" data-testid="platform-view" data-platform={platform.id}>
      <div className="flex items-center justify-between gap-2">
        <BackButton onPress={back} isDisabled={busy} />
        <h3 className="flex min-w-0 items-center gap-2 text-sm font-medium">
          <SubIcon group="setup" name={platform.icon} className="size-5 shrink-0" />
          <span className="truncate">{t(`platforms.names.${platform.id}`)}</span>
        </h3>
      </div>

      {guide.guide.versions.length > 1 ? (
        <Segment aria-label={t("wizard.version")} selectedKey={current.id} onSelectionChange={(key) => pickVersion(String(key))} size="sm" className="max-w-full self-start" isDisabled={busy}>
          {guide.guide.versions.map((v) => (
            <Segment.Item key={v.id} id={v.id}>
              {v.name}
            </Segment.Item>
          ))}
        </Segment>
      ) : null}

      {step !== null ? (
        <Wizard
          version={current}
          step={step}
          onStep={(n) => onNavigate({os: platform.id, step: n, version: current.id})}
          view={source.view}
          endpointId={source.kind === "endpoint" ? source.endpoint.id : undefined}
          onDone={onDone}
        />
      ) : (
        <div className="flex flex-col gap-4" data-testid="automatic">
          {offered ? (
            <section aria-label={t("configure.entries.automatic.title")} className="flex flex-col gap-3">
              <h3 className="text-sm font-medium">{t("configure.entries.automatic.title")}</h3>
              <p className="text-muted text-xs">{t(offered.kind === "apple" ? "configure.appleIntro" : "configure.generatorIntro")}</p>
              {offered.kind === "apple" ? (
                source.kind === "endpoint" ? (
                  <AppleBuilder mode="owner" endpointId={source.endpoint.id} profileId={source.endpoint.profile_id} client={client} stale={source.endpoint.apple_profile_stale} />
                ) : (
                  <AppleBuilder mode="share" link={source.link} client={source.view.client} />
                )
              ) : source.kind === "endpoint" ? (
                <GeneratorBlock endpointId={source.endpoint.id} generator={offered.generator} client={client} />
              ) : null}
            </section>
          ) : (
            <p className="text-muted text-sm">{t("configure.noAutomatic")}</p>
          )}
          {/* The guide is the page's primary action unless a one-click setup is offered above it. */}
          {offered ? (
            <Button variant="secondary" fullWidth isDisabled={busy} onPress={() => guard(() => onNavigate({os: platform.id, step: 1, version: current.id}))}>
              <Icon name="rules" className="size-4" />
              {t("configure.startGuide")}
            </Button>
          ) : (
            <PrimaryButton fullWidth isDisabled={busy} onPress={() => guard(() => onNavigate({os: platform.id, step: 1, version: current.id}))}>
              <Icon name="rules" className="size-4" />
              {t("configure.startGuide")}
            </PrimaryButton>
          )}
        </div>
      )}
    </div>
  );
}
