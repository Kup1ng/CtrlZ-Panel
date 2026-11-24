"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Alert, Button, Description, FieldError, Input, Label, Link, TextField} from "@heroui/react";
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
import {inviteTokenFromFragment, inviteTokenFromPaste, isInviteToken} from "./inviteToken.ts";
import {RegisterConfirm, type Challenge} from "./RegisterConfirm.tsx";
import {useAuthConfig} from "./useAuthConfig.ts";

// Spec 10.5, D67. The link is `/invite#<token>`, the token a signed, case-sensitive string of 140 characters that nobody
// types. On mount the fragment is read and removed from the address bar at once: it never reaches a server, but it should
// not sit in the history entry, in a screenshot or in the referrer of the next page either. Without a fragment the visitor
// pastes the link (or the bare token) into one field; it is cut out, checked for its length and alphabet, and sent exactly
// as it is (inviteToken.ts: nothing is folded, grouped or turned into ASCII). The token lives in component state and
// nowhere else (no storage). The one time it is written into a URL again is the language switch, and only a token that came
// from a link: it goes into the other language's fragment, which that page removes at once (wp8-r20-1, wp8-r21-3). A
// pasted token is never put in a URL, because a URL is recorded in the browser's global history and a pasted token never was in one.

type Phase = "reading" | "code" | "looking" | "info" | "confirm" | "invalid";

/** Lets go of the token the page holds as far as a "Send code" that is on the wire is concerned (webi-r3-5). */
function supersede(epoch: {current: number}) {
  epoch.current += 1;
}

export function InviteFlow() {
  const t = useTranslations("auth");
  const href = useAuthHref();
  const config = useAuthConfig();
  const [phase, setPhase] = useState<Phase>("reading");
  const [token, setToken] = useState("");
  const [info, setInfo] = useState<InviteInfo | null>(null);
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [notice, setNotice] = useState<unknown>(null);
  // Whether the token in `token` came from the link's fragment. The language switch carries only such a token in the
  // destination's fragment: it was in a URL already, so nothing new reaches the history, and the page that loads looks
  // it up again instead of the switch being held off (wp8-r20-1). A token the visitor pasted stays out of every URL
  // (wp8-r21-3). Set when the fragment is taken, cleared when the visitor pastes another or starts again.
  const [fromLink, setFromLink] = useState(false);
  // Only a whole token, and not one the server called invalid. The confirm step still holds the switch
  // (RegisterConfirm): its challenge cannot be carried, and another SMS would be sent.
  useCarryAcrossLocaleSwitch(fromLink && phase !== "invalid" && phase !== "reading" && isInviteToken(token) ? token : null);
  const consumed = useRef(false);
  // Which link the page is on. The effect below starts one lookup per number (lookupStart.ts says why not a flag).
  const [linkSeq, setLinkSeq] = useState(0);
  const [lookupStart] = useState(createLookupStart);
  // Which token the page holds, as a number: take() and restart() bump it, and a "Send code" answer that was asked under an
  // older number is dropped (webi-r3-5). `lookup.cancel` does the same for the lookup on the wire; this is the send's.
  const sendEpoch = useRef(0);

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

  // The fragment is taken when the page loads, once however many times a development build runs the effect
  // (the second run would find it gone and show the empty field), and again when it changes without a load:
  // a link pasted into the address bar of a tab that is already on this page is a `hashchange`, not a load.
  // The address bar is an external system that only the browser can read, and only after hydration, so the
  // state is set here and not derived.
  //
  // Two things about the router (gate-r21-1, -9). The token of a `hashchange` is read from the event's `newURL`: by the
  // time the listener runs, Next's router may have written its canonical URL, which has no fragment, over the one the
  // visitor pasted. And the strip goes through the router's own `replaceState`, once the router has installed it: a
  // mount effect runs before the router's, and a strip made then reaches the browser's native method, which drops the
  // router's marker from the entry (a Back to it shows another page) and leaves the router holding the token.
  const cancelLookup = lookup.cancel;
  useEffect(() => {
    const take = (hash: string): boolean => {
      if (!hash) return false;
      const linkToken = inviteTokenFromFragment(hash);
      replaceUrlAfterRouterMount(() => (window.location.hash ? `${window.location.pathname}${window.location.search}` : null));
      if (linkToken === null) {
        // Something is there and it is not a token (a link a chat app has cut or mangled, `#---`): the one `invite_invalid`
        // state, with no lookup spent on a string that cannot be signed. The page does not wait for a lookup that will
        // never start (wp8-r1-5); "Try another link" leads to the paste field.
        // A lookup of an earlier link may still be on the wire: its answer would put that invite's number on a page that holds no
        // token (webi-r1-8), so it is superseded here, and the token that came from a link is gone with the state.
        cancelLookup();
        supersede(sendEpoch);
        setToken("");
        setFromLink(false);
        setInfo(null);
        setChallenge(null);
        setNotice(null);
        setPhase("invalid");
      } else {
        supersede(sendEpoch);
        setChallenge(null);
        setToken(linkToken);
        setFromLink(true);
        setNotice(null);
        setLinkSeq((n) => n + 1);
        setPhase("looking");
      }
      return true;
    };
    if (!consumed.current) {
      consumed.current = true;
      // The address bar can be read only in the browser and after hydration, so this one read of an external system is the state's source.
      if (!take(window.location.hash)) setPhase("code");
    }
    const onHashChange = (event: HashChangeEvent) => void take(hashOfHashChange(event.newURL, window.location.hash));
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, [cancelLookup]);

  // A link that carried the token looks it up straight away.
  // `run` is the one stable member of `lookup` (a new object each render would re-run this effect after every commit).
  const run = lookup.run;
  useEffect(() => {
    if (phase !== "looking" || !lookupStart.claim(linkSeq)) return;
    void run(token);
  }, [phase, token, linkSeq, run, lookupStart]);

  const restart = () => {
    // The same rule as a bad link: an answer that is still coming belongs to a token this page no longer holds.
    lookup.cancel();
    supersede(sendEpoch);
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
        sendEpoch={sendEpoch}
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
      onToken={setToken}
      // Any edit of the field takes the offer of the link's token back: what is in it is no longer the link (wp8-r21-3).
      onEdit={() => setFromLink(false)}
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
  // Which lookup is the current one, and which token is on the wire. A second link pasted while the first lookup
  // runs starts its own lookup, and the first one's answer is dropped when it arrives: it would otherwise put
  // the first invite's number on a page whose token is the second (wp8-r6-2). The same token twice is one lookup.
  const latestRun = useRef(0);
  const inFlight = useRef<string | null>(null);
  // The callbacks change on every render, and the effect that starts a lookup must not run again for that.
  const latest = useRef({onInfo, onInvalid, onFailed});
  useEffect(() => {
    latest.current = {onInfo, onInvalid, onFailed};
  });

  const [run] = useState(() => async (token: string, report?: (error: unknown) => void) => {
    if (inFlight.current === token) return;
    const mine = ++latestRun.current;
    inFlight.current = token;
    setPending(true);
    try {
      const found = await authApi.lookupInvite(token);
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
  // Supersedes the lookup on the wire: its answer is dropped when it arrives and the wait ends now.
  const [cancel] = useState(() => () => {
    latestRun.current++;
    inFlight.current = null;
    setPending(false);
  });
  return {run, pending, cancel};
}

function CodeStep({
  token,
  onToken,
  onEdit,
  notice,
  lookup,
}: {
  /** The token the visitor is on (a link's whose lookup failed, say): the field starts with it, so a retry needs no second paste. */
  token: string;
  /** A token that passed the shape check and is about to be looked up. */
  onToken: (pasted: string) => void;
  onEdit: () => void;
  notice: unknown;
  lookup: ReturnType<typeof useLookup>;
}) {
  const t = useTranslations("auth");
  const errors = useTranslations("errors");
  const href = useAuthHref();
  const form = useApiForm({focus: "token"});
  // What is in the field: a whole link or a bare token, as pasted. It is state of this step only (never a URL, never storage).
  const [text, setText] = useState(token);

  // A failure of the lookup that the link started arrives as `notice`. It goes through the form like a pasted
  // link's failure does, so a 429 starts its wait here too and the button stays disabled until it ends, instead
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
    if (text.trim() === "") return form.setFieldError("token", t("fields.inviteLink.required"));
    // The shape is checked before a lookup is spent. A paste that is not a token gets the one invite_invalid text: the
    // page says nothing about why, and a shape check reveals nothing about any invite.
    const pasted = inviteTokenFromPaste(text);
    if (pasted === null) return form.setFieldError("token", errors("invite_invalid"));
    form.clear();
    onToken(pasted);
    void lookup.run(pasted, (error) => void form.fail(error));
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
          value={text}
          onChange={form.bind("token", (next: string) => {
            setText(next);
            onEdit();
          }).onChange}
        >
          <Label>{t("fields.inviteLink.label")}</Label>
          <Input dir="ltr" className="text-start font-mono" autoCapitalize="none" autoCorrect="off" spellCheck={false} />
          <Description>{t("fields.inviteLink.hint")}</Description>
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
  sendEpoch,
  onSend,
  smsAvailable,
  onSent,
  onInvalid,
  onBack,
}: {
  token: string;
  info: InviteInfo;
  notice: unknown;
  /** Bumped when the page lets go of this token; an answer asked under an older number is not acted on (webi-r3-5). */
  sendEpoch: {readonly current: number};
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
    const mine = sendEpoch.current;
    try {
      const issued = await authApi.requestOtp({purpose: "invite", invite_token: token, locale});
      // The page moved to another token (or none) while the SMS was being asked for: its number is not the one this answer is for.
      if (mine === sendEpoch.current) onSent({id: issued.challenge_id, readyAt: Date.now() + issued.resend_after_s * 1000});
    } catch (error) {
      if (mine !== sendEpoch.current) return;
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
