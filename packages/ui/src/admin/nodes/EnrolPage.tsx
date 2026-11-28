"use client";

import {useTranslations} from "next-intl";

import {PageHeader} from "../../shell/PageHeader.tsx";
import {EnrolForm} from "./EnrolForm.tsx";
import {EnrolList} from "./EnrolList.tsx";
import {BackToNodes} from "./NodeDetailPage.tsx";

// p4-nodes 4.2 and 10.1, T-340: the new install command, and the hosts that have called in, with the comparison of their fingerprints.

export function EnrolPage() {
  const t = useTranslations("nodes");
  return (
    <>
      <BackToNodes />
      <PageHeader icon="nodes" title={t("pages.enrol.title")} subtitle={t("pages.enrol.subtitle")} />
      <div className="flex flex-col gap-8">
        <div className="max-w-3xl">
          <EnrolForm />
        </div>
        <EnrolList />
      </div>
    </>
  );
}
