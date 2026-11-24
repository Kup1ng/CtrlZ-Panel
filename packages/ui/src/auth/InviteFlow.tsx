"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Alert, Button, FieldError, Input, Label, Link, TextField} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useRef, useState} from "react";

import {Tech} from "../data/Tech.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../forms/FormError.tsx";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {useCarryAcrossLocaleSwitch} from "../shell/localeSwitch.ts";
import {replaceUrlAfterRouterMount} from "../shell/routerHistory.ts";
import {useApiForm} from "../forms/useApiForm.ts";
import {LoadingBlock} from "../forms/LoadingBlock.tsx";
import {AuthCard} from "./AuthCard.tsx";
import {authApi, type InviteInfo, type Locale} from "./authApi.ts";
import {useAuthHref} from "./authHref.ts";
import {hashOfHashChange} from "./inviteFragment.ts";
import {createLookupStart} from "./lookupStart.ts";
import {canonicalInvite, changeGrouped, groupCode, INVITE_LENGTH, INVITE_PLACEHOLDER, isFullInvite} from "./codes.ts";
import {RegisterConfirm, type Challenge} from "./RegisterConfirm.tsx";
import {useAuthConfig} from "./useAuthConfig.ts";

// Spec 10.5. The link is `/invite#<code>`. On mount the fragment is read and removed from the address bar
// at once: it never reaches a server, but it should not sit in the history entry, in a screenshot or in the
// referrer of the next page either. Without a fragment the visitor types the code, which is shown in groups
// and sent as its canonical text. The code lives in component state and nowhere else (no storage). The one time it
// is written into a URL again is the language switch, and only a code that came from a link: it goes into the other
// language's fragment, which that page removes at once (wp8-r20-1, wp8-r21-3). A code the visitor typed is never
// put in a URL, because a URL is recorded in the browser's global history and a typed code never was in one.

type Phase = "reading" | "code" | "looking" | "info" | "confirm" | "invalid";

export function InviteFlow() {
  const t = useTranslations("auth");
  const href = useAuthHref();
  const config = useAuthConfig();
  const [phase, setPhase] = useState<Phase>("reading");
  const [token, setToken] = useState("");
  const [info, setInfo] = useState<InviteInfo | null>(null);
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [notice, setNotice] = useState<unknown>(null);
  // Whether the code in `token` came from the link's fragment. The language switch carries only such a code in the
  // destination's fragment: it was in a URL already, so nothing new reaches the history, and the page that loads looks
  // it up again instead of the switch being held off (wp8-r20-1). A code the visitor typed stays out of every URL
  // (wp8-r21-3). Set when the fragment is taken, cleared when the visitor types over the code or starts again.
  const [fromLink, setFromLink] = useState(false);
  // Only a whole code, and not one the server called invalid. The confirm step still holds the switch
  // (RegisterConfirm): its challenge cannot be carried, and another SMS would be sent.
  useCarryAcrossLocaleSwitch(fromLink && phase !== "invalid" && phase !== "reading" && isFullInvite(token) ? token : null);
  const consumed = useRef(false);
  // Which link the page is on. The effect below starts one lookup per number (lookupStart.ts says why not a flag).
  const [linkSeq, setLinkSeq] = useState(0);
  const [lookupStart] = useState(createLookupStart);

  // The fragment is taken when the page loads, once however many times a development build runs the effect
  // (the second run would find it gone and show the empty field), and again when it changes without a load:
  // a link pasted into the address bar of a tab that is already on this page is a `hashchange`, not a load.
  // The address bar is an external system that only the browser can read, and only after hydration, so the
  // state is set here and not derived.
  //
  // Two things about the router (gate-r21-1, -9). The code of a `hashchange` is read from the event's `newURL`: by the
  // time the listener runs, Next's router may have written its canonical URL, which has no fragment, over the one the
  // visitor pasted. And the strip goes through the router's own `replaceState`, once the router has installed it: a
  // mount effect runs before the router's, and a strip made then reaches the browser's native method, which drops the
  // router's marker from the entry (a Back to it shows another page) and leaves the router holding the code.
  useEffect(() => {
    const take = (hash: string): boolean => {
      if (!hash) return false;
      const linkCode = canonicalInvite(hash.replace(/^#/, ""));
      replaceUrlAfterRouterMount(() => (window.location.hash ? `${window.location.pathname}${window.location.search}` : null));
      if (linkCode) {
        setToken(linkCode);
        setFromLink(true);
        setNotice(null);
        setLinkSeq((n) => n + 1);
        setPhase("looking");
      } else {
        // A fragment with no letter or digit in it (a link a chat app has mangled, `#---`) carries no code.
        // The page must not wait for a lookup that will never start: it asks for the code by hand (wp8-r1-5).
        setPhase("code");
      }
      return true;
    };
    if (!consumed.current) {
      consumed.current = true;
      // The address bar can be read only in the browser and after hydration, so this one read of an external system is the state's source.
      // eslint-disable-next-line react-hooks/set-state-in-effect -- see above: the fragment is external, and no render can derive it
      if (!take(window.location.hash)) setPhase("code");
    }
    const onHashChange = (event: HashChangeEvent) => void take(hashOfHashChange(event.newURL, window.location.hash));
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const lookup = useLookup({
    onInfo: (found) => {
      setInfo(found);
      // A failure of an earlier lookup is over: the info step shows its notice, and must not show that one.
      setNotice(null);
      setPhase("info");
    },
    onInvalid: () => setPhase("invalid"),
    onFailed: (error) => {
      setNotice(error);
      setPhase("code");
    },
  });
  // A link that carried the code looks it up straight away.
  // `run` is the one stable member of `lookup` (a new object each render would re-run this effect after every commit).
  const run = lookup.run;
  useEffect(() => {
    if (phase !== "looking" || !lookupStart.claim(linkSeq)) return;
    void run(token);
  }, [phase, token, linkSeq, run, lookupStart]);

  const restart = () => {
    setToken("");
    setFromLink(false);
    setInfo(null);
    setChallenge(null);
    setNotice(null);
    setPhase("code");
  };

  if (phase === "reading" || phase === "looking") {
    return (
      <AuthCard title={t("invite.title")}>
        <LoadingBlock />
      </AuthCard>
    );
  }

  if (phase === "invalid") {
    return (
      <AuthCard title={t("invite.invalidTitle")} description={t("invite.invalidText")} focusHeading>
        <div className="flex flex-col items-center gap-2 text-sm">
          <Button size="sm" variant="ghost" onPress={restart}>
            {t("invite.another")}
          </Button>
          <Link href={href("/login")}>{t("invite.signIn")}</Link>
        </div>
      </AuthCard>
    );
  }

  if (phase === "confirm" && challenge && info) {
    return (
      <RegisterConfirm
        identity={{kind: "invite", token}}
        challenge={challenge}
        onChallenge={setChallenge}
        onRestart={(error) => {
          setNotice(error);
          setChallenge(null);
          setPhase("info");
        }}
        onClosed={() => setPhase("invalid")}
        title={t("invite.confirmTitle")}
        description={t.rich("invite.confirmDescription", {phone: info.phone_masked, tech: (chunks) => <Tech>{chunks}</Tech>})}
        submitLabel={t("invite.create")}
        secondary={{label: t("invite.another"), onPress: restart}}
        smsAvailable={config.status === "ready" ? config.smsAvailable : true}
      />
    );
  }

  if (phase === "info" && info) {
    return (
      <InfoStep
        token={token}
        info={info}
        notice={notice}
        onSend={() => setNotice(null)}
        smsAvailable={config.status === "ready" ? config.smsAvailable : true}
        onSent={(sent) => {
          setChallenge(sent);
          setNotice(null);
          setPhase("confirm");
        }}
        onInvalid={() => setPhase("invalid")}
        onBack={restart}
      />
    );
  }

  return (
    <CodeStep
      token={token}
      onToken={(canonical) => {
        setToken(canonical);
        setFromLink(false);
      }}
      notice={notice}
      lookup={lookup}
    />
  );
}

/** `POST /auth/invites/lookup`, with the outcome table of 10.5. `invite_invalid` is one state, with no detail. */
function useLookup({
  onInfo,
  onInvalid,
  onFailed,
}: {
  onInfo: (info: InviteInfo) => void;
  onInvalid: () => void;
  onFailed: (error: unknown) => void;
}) {
  const [pending, setPending] = useState(false);
  // Which lookup is the current one, and which code is on the wire. A second link pasted while the first lookup
  // runs starts its own lookup, and the first one's answer is dropped when it arrives: it would otherwise put
  // the first invite's number on a page whose token is the second (wp8-r6-2). The same code twice is one lookup.
  const latestRun = useRef(0);
  const inFlight = useRef<string | null>(null);
  // The callbacks change on every render, and the effect that starts a lookup must not run again for that.
  const latest = useRef({onInfo, onInvalid, onFailed});
  useEffect(() => {
    latest.current = {onInfo, onInvalid, onFailed};
  });

  const [run] = useState(() => async (code: string, report?: (error: unknown) => void) => {
    if (inFlight.current === code) return;
    const mine = ++latestRun.current;
    inFlight.current = code;
    setPending(true);
    try {
      const found = await authApi.lookupInvite(code);
      if (mine === latestRun.current) latest.current.onInfo(found);
    } catch (error) {
      if (mine !== latestRun.current) return;
      if (hasCode(error, "invite_invalid")) latest.current.onInvalid();
      else if (report) report(error);
      else latest.current.onFailed(error);
    } finally {
      // Only the newest lookup ends the wait: an older one that was superseded leaves it to the newer one.
      if (mine === latestRun.current) {
        inFlight.current = null;
        setPending(false);
      }
    }
  });
  return {run, pending};
}

function CodeStep({
  token,
  onToken,
  notice,
  lookup,
}: {
  token: string;
  onToken: (canonical: string) => void;
  notice: unknown;
  lookup: ReturnType<typeof useLookup>;
}) {
  const t = useTranslations("auth");
  const href = useAuthHref();
  const form = useApiForm({focus: "token"});

  // A failure of the lookup that the link started arrives as `notice`. It goes through the form like a typed
  // code's failure does, so a 429 starts its wait here too and the button stays disabled until it ends, instead
  // of letting each press send a lookup that is refused again (wp8-r2-4). Once per notice.
  const {fail} = form;
  const shownFor = useRef<unknown>(null);
  useEffect(() => {
    if (notice === null || notice === undefined || shownFor.current === notice) return;
    shownFor.current = notice;
    fail(notice);
  }, [notice, fail]);

  function submit() {
    if (lookup.pending || form.blocked) return;
    if (!isFullInvite(token)) return form.setFieldError("token", t("fields.inviteCode.required"));
    form.clear();
    void lookup.run(token, (error) => void form.fail(error));
  }

  return (
    <AuthCard title={t("invite.title")} description={t("invite.subtitle")}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <TextField
          name="token"
          variant="secondary"
          fullWidth
          autoComplete="off"
          isDisabled={lookup.pending}
          isInvalid={form.fieldMessage("token") !== undefined}
          value={groupCode(token)}
          onChange={form.bind("token", (text: string) => changeGrouped(text, INVITE_LENGTH, onToken)).onChange}
        >
          <Label>{t("fields.inviteCode.label")}</Label>
          <Input
            dir="ltr"
            className="text-start font-mono"
            placeholder={INVITE_PLACEHOLDER}
            autoCapitalize="characters"
            autoCorrect="off"
            spellCheck={false}
          />
          <FieldError>{form.fieldMessage("token")}</FieldError>
        </TextField>
        <FormError error={form.formError} onRetry={submit} />
        <OfflineNotice />
        <SubmitButton isPending={lookup.pending} retryIn={form.retryIn}>
          {t("invite.submit")}
        </SubmitButton>
      </AuthForm>
      <p className="text-center text-sm">
        <Link href={href("/login")}>{t("invite.signIn")}</Link>
      </p>
    </AuthCard>
  );
}

function InfoStep({
  token,
  info,
  notice,
  onSend,
  smsAvailable,
  onSent,
  onInvalid,
  onBack,
}: {
  token: string;
  info: InviteInfo;
  notice: unknown;
  /** The request starts: the notice of the step we came back to goes (wp8-r3-2). */
  onSend: () => void;
  smsAvailable: boolean;
  onSent: (challenge: Challenge) => void;
  onInvalid: () => void;
  onBack: () => void;
}) {
  const t = useTranslations("auth");
  const locale = useLocale() as Locale;
  const format = useAppFormat();
  const form = useApiForm();
  const [pending, setPending] = useState(false);

  async function send() {
    if (pending || form.blocked) return;
    setPending(true);
    form.clear();
    onSend();
    try {
      const issued = await authApi.requestOtp({purpose: "invite", invite_token: token, locale});
      onSent({id: issued.challenge_id, readyAt: Date.now() + issued.resend_after_s * 1000});
    } catch (error) {
      if (hasCode(error, "invite_invalid", "registration_closed")) onInvalid();
      else form.fail(error);
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthCard
      focusHeading
      title={t("invite.lookupTitle")}
      description={t.rich("invite.lookupText", {
        phone: info.phone_masked,
        date: format.dateTime(info.expires_at),
        tech: (chunks) => <Tech>{chunks}</Tech>,
      })}
    >
      <FormError error={notice} />
      {/* SMS is down: the invite cannot be confirmed, and the admin can make the account without one (10.5). */}
      {smsAvailable ? null : (
        <Alert status="warning">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("invite.smsDown")}</Alert.Description>
          </Alert.Content>
        </Alert>
      )}
      <AuthForm form={form} onSubmit={() => void send()}>
        <FormError error={form.formError} smsDown={t("invite.smsDown")} onRetry={() => void send()} />
        <OfflineNotice />
        <SubmitButton isPending={pending} retryIn={form.retryIn} isDisabled={!smsAvailable}>
          {t("invite.send")}
        </SubmitButton>
      </AuthForm>
      <div className="flex justify-center">
        <Button size="sm" variant="ghost" onPress={onBack}>
          {t("invite.another")}
        </Button>
      </div>
    </AuthCard>
  );
}
