"use client";

// /docs/api (spec p3 6.5, 10, Plan T-320): the public API, drawn from `publicApi.generated.json` (made from api/public-openapi.yaml by
// packages/api-client/scripts/gen-public-docs.mjs) with our own components. No renderer from outside, and no request at run time: the data is a
// chunk of the app, loaded when the page opens. Groups are the tags of the document, each with its operations; the search narrows them by method,
// path, id and summary; an operation opens to its parameters, body, answers and an example request.

import {Link} from "@ctrlz/i18n/navigation.ts";
import {Accordion, Chip, Skeleton, toast} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useEffect, useMemo, useState} from "react";
import type {Key} from "react-aria-components";

import {downloadFile} from "../data/download.ts";
import {Tech} from "../data/Tech.tsx";
import {TechCopyRow} from "../data/TechCopyRow.tsx";
import {useErrorText} from "../feedback/errorText.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {PageHeader} from "../shell/PageHeader.tsx";
import {OperationBody, Prose} from "./ApiOperation.tsx";
import {groupsOf, matches, type PublicApi} from "./apiDocsModel.ts";

type Load = {state: "loading"} | {state: "ready"; api: PublicApi} | {state: "error"; error: unknown};

export function ApiDocsScreen() {
  const t = useTranslations("api");
  const errorText = useErrorText();
  const [load, setLoad] = useState<Load>({state: "loading"});
  const [attempt, setAttempt] = useState(0);
  const [query, setQuery] = useState("");
  const [openGroups, setOpenGroups] = useState<Set<Key>>(new Set());
  const [openOps, setOpenOps] = useState<Set<Key>>(new Set());

  useEffect(() => {
    let live = true;
    // A lazy chunk of the app: the document is some 130 kB, and only this page reads it.
    import("./publicApi.generated.json").then(
      (module) => live && setLoad({state: "ready", api: module.default as unknown as PublicApi}),
      (error: unknown) => live && setLoad({state: "error", error}),
    );
    return () => {
      live = false;
    };
  }, [attempt]);

  // The file of the Download button is the OpenAPI document itself (spec p3 6.5, S8-r2-2), so a client generator or Postman can read it. It is a second lazy
  // chunk, fetched from this origin when the button is pressed and not before, and saved through a Blob: no request outside the panel.
  async function download() {
    try {
      const {default: spec} = await import("./publicApiSpec.generated.json");
      downloadFile(spec.file, spec.yaml, "application/yaml;charset=utf-8");
    } catch (error) {
      toast.danger(errorText(error));
    }
  }

  const api = load.state === "ready" ? load.api : null;
  const searching = query.trim() !== "";
  const groups = useMemo(() => (api ? groupsOf(api, api.operations.filter((op) => matches(op, query))) : []), [api, query]);
  const shownCount = groups.reduce((sum, group) => sum + group.operations.length, 0);

  return (
    <div data-screen="api-docs">
      <PageHeader
        icon="api"
        title={t("apiDocsPage.title")}
        subtitle={t("apiDocsPage.subtitle")}
        helpKey="apiTokens"
        onSearch={setQuery}
        actions={
          api
            ? [{id: "download", label: t("apiDocsPage.download"), icon: "download", onAction: () => void download()}]
            : undefined
        }
      />
      <div className="flex w-full max-w-4xl flex-col gap-4 pb-8">
        {load.state === "loading" ? (
          <div role="status" aria-busy="true" className="flex flex-col gap-2">
            <span className="sr-only">{t("apiDocsPage.loading")}</span>
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} aria-hidden className="h-14 w-full rounded-(--radius-box)" />
            ))}
          </div>
        ) : null}
        {load.state === "error" ? <SectionError error={load.error} onRetry={() => (setLoad({state: "loading"}), setAttempt((n) => n + 1))} /> : null}
        {api ? (
          <>
            <section className="bg-surface flex flex-col gap-3 rounded-(--radius-box) p-4" aria-label={t("apiDocsPage.about")}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-base font-semibold" dir="ltr">
                  {api.title}
                </h2>
                <Chip size="sm" variant="soft">
                  <Tech>{api.version}</Tech>
                </Chip>
              </div>
              <Prose text={api.description} />
              <TechCopyRow label={t("apiDocsPage.baseUrl")} value={`${typeof window === "undefined" ? "" : window.location.origin}${api.server}`} />
              <TechCopyRow label={t("apiDocsPage.header")} value="Authorization: Bearer ctz_YOUR_TOKEN" />
              <p className="text-muted text-xs">
                {t.rich("apiDocsPage.tokens", {
                  tokens: (chunks) => (
                    <Link href="/preferences/api" className="text-foreground font-medium underline underline-offset-2">
                      {chunks}
                    </Link>
                  ),
                })}
              </p>
            </section>

            <p className="text-muted text-xs" role="status" aria-live="polite" data-testid="docs-count">
              {searching ? t("apiDocsPage.found", {count: shownCount, total: api.operations.length}) : t("apiDocsPage.total", {count: api.operations.length, groups: groups.length})}
            </p>

            {groups.length === 0 ? (
              <SectionEmpty icon="search" title={t("apiDocsPage.noMatch")} description={t("apiDocsPage.noMatchText")} />
            ) : (
              <Accordion
                allowsMultipleExpanded
                className="w-full"
                aria-label={t("apiDocsPage.groups")}
                expandedKeys={searching ? new Set(groups.map((g) => g.tag)) : openGroups}
                onExpandedChange={(keys) => !searching && setOpenGroups(new Set(keys))}
              >
                {groups.map((group) => (
                  <Accordion.Item key={group.tag} id={group.tag}>
                    <Accordion.Heading>
                      <Accordion.Trigger>
                        <span className="flex min-w-0 flex-1 flex-col items-start gap-0.5 text-start">
                          <span dir="ltr" className="text-sm font-semibold">
                            {group.tag}
                          </span>
                          <span dir="ltr" className="text-muted text-xs font-normal">
                            {group.description}
                          </span>
                        </span>
                        <span className="text-muted text-xs">{t("apiDocsPage.operations", {count: group.operations.length})}</span>
                        <Accordion.Indicator />
                      </Accordion.Trigger>
                    </Accordion.Heading>
                    <Accordion.Panel>
                      <Accordion.Body>
                        <Accordion
                          allowsMultipleExpanded
                          className="w-full"
                          aria-label={t("apiDocsPage.groupOperations", {name: group.tag})}
                          expandedKeys={openOps}
                          onExpandedChange={(keys) => setOpenOps(new Set(keys))}
                        >
                          {group.operations.map((op) => (
                            <Accordion.Item key={op.id} id={op.id}>
                              <Accordion.Heading>
                                <Accordion.Trigger>
                                  <span dir="ltr" className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-2 gap-y-0.5 text-start">
                                    <Tech className="text-xs font-semibold">{op.method}</Tech>
                                    <Tech className="text-sm [overflow-wrap:anywhere]">{op.path}</Tech>
                                    <span className="text-muted w-full text-xs font-normal">{op.summary}</span>
                                  </span>
                                  <Chip size="sm" variant="soft" color={op.token === "write" ? "warning" : "default"}>
                                    <Icon name={op.token === "write" ? "edit" : "search"} className="size-3.5" />
                                    {t(`reference.token.${op.token}`)}
                                  </Chip>
                                  <Accordion.Indicator />
                                </Accordion.Trigger>
                              </Accordion.Heading>
                              <Accordion.Panel>
                                <Accordion.Body>{openOps.has(op.id) ? <OperationBody op={op} api={api} /> : null}</Accordion.Body>
                              </Accordion.Panel>
                            </Accordion.Item>
                          ))}
                        </Accordion>
                      </Accordion.Body>
                    </Accordion.Panel>
                  </Accordion.Item>
                ))}
              </Accordion>
            )}
          </>
        ) : null}
      </div>
    </div>
  );
}
