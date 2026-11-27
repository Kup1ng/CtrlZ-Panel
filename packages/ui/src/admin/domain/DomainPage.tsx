"use client";

import {useDomain} from "@ctrlz/api-client/admin/hooks/domain.ts";
import {Skeleton} from "@heroui/react";
import {useTranslations} from "next-intl";

import {SectionError} from "../../feedback/SectionError.tsx";
import {PageHeader} from "../../shell/PageHeader.tsx";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {keepRetry} from "../shared/restoreFocus.ts";
import {CertificatesSection} from "./CertificatesSection.tsx";
import {DomainForm} from "./DomainForm.tsx";
import {DomainStatus} from "./DomainStatus.tsx";

// p4-nodes 10.1 and 10.4, T-344. The domain: what it is now and whether it is in force, the three values with the transition and what it
// touches, and the certificates. The settings are read once and the form is keyed on the zone it was made from, so a form that is open
// is never rebuilt under the admin: another admin's change reaches it as a conflict (`useServerForm`), not as a reset.

export function DomainPage() {
  const t = useTranslations("nodes");
  const domain = useDomain();
  return (
    <>
      <PageHeader icon="domain" title={t("pages.domain.title")} subtitle={t("pages.domain.subtitle")} />
      <div className="flex flex-col gap-8">
        {domain.isPending ? (
          <div role="status" aria-busy="true" aria-label={t("domain.loadingLabel")} className="flex flex-col gap-4">
            <Skeleton className="h-48 w-full max-w-3xl rounded-(--radius-box)" />
            <Skeleton className="h-64 w-full max-w-3xl rounded-(--radius-box)" />
          </div>
        ) : !domain.data ? (
          <SectionError error={domain.error} onRetry={keepRetry(() => domain.refetch())} />
        ) : (
          <>
            <RefreshFailed error={domain.error} onRetry={() => domain.refetch()} />
            <DomainStatus settings={domain.data} />
            <DomainForm current={domain.data} />
          </>
        )}
        <CertificatesSection />
      </div>
    </>
  );
}
