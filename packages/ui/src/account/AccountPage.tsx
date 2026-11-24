"use client";

import {useSession} from "@ctrlz/api-client/hooks/me.ts";
import {useTranslations} from "next-intl";

import {ReauthProvider} from "../auth/ReauthDialog.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {LoadingBlock} from "../forms/LoadingBlock.tsx";
import {InlineEditGroup} from "../forms/InlineEditRow.tsx";
import {PageHeader} from "../shell/PageHeader.tsx";
import {AccountSection} from "./AccountSection.tsx";
import {OptionsSection} from "./OptionsSection.tsx";
import {PasskeysSection} from "./PasskeysSection.tsx";
import {PasswordRow} from "./PasswordRow.tsx";
import {PhoneRow} from "./PhoneRow.tsx";
import {SessionsRow} from "./SessionsRow.tsx";
import {TotpRow} from "./TotpRow.tsx";

// Spec 12, WF "Preferences": Details, Passkeys and Options as three sections of full-width rows. The
// shell's session gate has already asked `/me`, so the page reads the same cache entry; the loading and
// error states below are for the moment a refetch has failed under it. One `ReauthProvider` serves every
// row, so a call that meets `reauth_required` anywhere on the page opens the same dialog (spec 14.3).

export function AccountPage() {
  const t = useTranslations("account");
  const {me, status, error, retry} = useSession();

  return (
    <>
      <PageHeader icon="account" title={t("page.title")} subtitle={t("page.subtitle")} helpKey="account" />
      {me ? (
        <ReauthProvider>
          <InlineEditGroup>
            <div className="flex w-full max-w-3xl flex-col gap-8 pb-8">
              <AccountSection id="details" title={t("sections.details")}>
                <PhoneRow me={me} />
                <PasswordRow me={me} />
                <TotpRow me={me} />
                <SessionsRow />
              </AccountSection>
              <PasskeysSection me={me} />
              <OptionsSection me={me} />
            </div>
          </InlineEditGroup>
        </ReauthProvider>
      ) : status === "error" ? (
        <SectionError error={error} onRetry={retry} />
      ) : (
        <div className="w-full max-w-3xl">
          <LoadingBlock rows={4} />
        </div>
      )}
    </>
  );
}
