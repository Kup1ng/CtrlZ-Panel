"use client";

import {Button, Chip} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {Tech} from "../data/Tech.tsx";
import {CopyBlock} from "../setup/CopyBlock.tsx";
import {curlOf, isError, proseOf, type Body, type Field, type Operation, type Param, type PublicApi} from "./apiDocsModel.ts";

// One operation of the public API (spec p3 6.5): what it does, which token may call it, its parameters, its request body, its answers and an example
// request. The reference text is the document's own, in English, and is drawn left to right in both languages (a technical reference whose words
// are the names of fields and codes); the labels around it follow the page's language. Named schemas open in place, to a depth of three, so a
// reader follows `Profile` to its fields without the page growing without bound.

const MAX_DEPTH = 3;

export function Prose({text}: {text: string}) {
  return (
    <div dir="ltr" lang="en" className="flex flex-col gap-2 text-sm">
      {proseOf(text).map((paragraph, index) => (
        <p key={index} className="text-start">
          {paragraph.map((piece, at) => (piece.kind === "code" ? <Tech key={at}>{piece.text}</Tech> : <span key={at}>{piece.text}</span>))}
        </p>
      ))}
    </div>
  );
}

function FieldRow({field, api, depth}: {field: Field; api: PublicApi; depth: number}) {
  const t = useTranslations("api");
  const [open, setOpen] = useState(false);
  const target = field.ref ? api.schemas[field.ref] : undefined;
  const nested = Boolean(target?.fields?.length) && depth < MAX_DEPTH;
  return (
    <li className="flex flex-col gap-1 py-2" data-field={field.name}>
      <div dir="ltr" className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <Tech className="text-sm font-medium">{field.name}</Tech>
        <Tech className="text-muted text-xs">{field.type}</Tech>
        {field.required ? <span className="text-xs">{t("reference.required")}</span> : <span className="text-muted text-xs">{t("reference.optional")}</span>}
        {field.limits ? <span className="text-muted text-xs">{field.limits}</span> : null}
      </div>
      {field.description ? <Prose text={field.description} /> : null}
      {nested ? (
        <div className="flex flex-col gap-1">
          <Button
            size="sm"
            variant="tertiary"
            className="self-start"
            aria-expanded={open}
            aria-label={t(open ? "reference.hideSchema" : "reference.showSchema", {name: field.ref ?? ""})}
            onPress={() => setOpen((v) => !v)}
          >
            <Icon name="chevron" flip className={open ? "size-4 rotate-90" : "size-4"} />
            <Tech>{field.ref}</Tech>
          </Button>
          {open ? <FieldList fields={target!.fields!} api={api} depth={depth + 1} nestedIn /> : null}
        </div>
      ) : null}
    </li>
  );
}

function FieldList({fields, api, depth, nestedIn = false}: {fields: Field[]; api: PublicApi; depth: number; nestedIn?: boolean}) {
  return (
    <ul className={["divide-separator flex flex-col divide-y", nestedIn ? "border-separator ms-3 border-s ps-3" : ""].filter(Boolean).join(" ")}>
      {fields.map((field) => (
        <FieldRow key={field.name} field={field} api={api} depth={depth} />
      ))}
    </ul>
  );
}

function BodyView({body, api}: {body: Body; api: PublicApi}) {
  const t = useTranslations("api");
  const schema = body.ref ? api.schemas[body.ref] : undefined;
  const fields = body.fields ?? schema?.fields;
  return (
    <div className="flex flex-col gap-1">
      <p dir="ltr" className="text-muted flex flex-wrap items-baseline gap-x-2 text-xs">
        <Tech>{body.mediaType}</Tech>
        {body.ref ? <Tech className="text-foreground text-sm font-medium">{schema?.type === "array" ? `[${schema.items}]` : body.ref}</Tech> : null}
        {!body.ref && body.type ? <Tech>{body.type}</Tech> : null}
      </p>
      {schema?.description ? <Prose text={schema.description} /> : null}
      {fields && fields.length > 0 ? <FieldList fields={fields} api={api} depth={1} /> : null}
      {!fields && schema?.ref && api.schemas[schema.ref]?.fields ? <FieldList fields={api.schemas[schema.ref]!.fields!} api={api} depth={1} /> : null}
      {schema?.enum ? (
        <p dir="ltr" className="text-xs">
          {t("reference.oneOf")} <Tech>{schema.enum.map((v) => JSON.stringify(v)).join(" | ")}</Tech>
        </p>
      ) : null}
    </div>
  );
}

function ParamList({params}: {params: Param[]}) {
  const t = useTranslations("api");
  return (
    <ul className="divide-separator flex flex-col divide-y">
      {params.map((p) => (
        <li key={`${p.in}:${p.name}`} className="flex flex-col gap-1 py-2" data-param={p.name}>
          <div dir="ltr" className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <Tech className="text-sm font-medium">{p.name}</Tech>
            <Tech className="text-muted text-xs">{p.type}</Tech>
            <span className="text-muted text-xs">{t(`reference.in.${p.in === "path" || p.in === "query" || p.in === "header" ? p.in : "query"}`)}</span>
            {p.required ? <span className="text-xs">{t("reference.required")}</span> : <span className="text-muted text-xs">{t("reference.optional")}</span>}
            {p.limits ? <span className="text-muted text-xs">{p.limits}</span> : null}
          </div>
          {p.description ? <Prose text={p.description} /> : null}
        </li>
      ))}
    </ul>
  );
}

export function OperationBody({op, api}: {op: Operation; api: PublicApi}) {
  const t = useTranslations("api");
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  return (
    <div className="flex flex-col gap-4 pb-2" data-operation={op.id}>
      {op.description ? <Prose text={op.description} /> : null}
      {op.parameters.length > 0 ? (
        <section className="flex flex-col gap-1" aria-label={t("reference.parameters")}>
          <h4 className="text-sm font-semibold">{t("reference.parameters")}</h4>
          <ParamList params={op.parameters} />
        </section>
      ) : null}
      {op.request ? (
        <section className="flex flex-col gap-1" aria-label={t("reference.request")}>
          <h4 className="text-sm font-semibold">{t("reference.request")}</h4>
          <BodyView body={op.request} api={api} />
        </section>
      ) : null}
      <section className="flex flex-col gap-2" aria-label={t("reference.responses")}>
        <h4 className="text-sm font-semibold">{t("reference.responses")}</h4>
        <ul className="flex flex-col gap-3">
          {op.responses.map((response) => (
            <li key={response.status} className="flex flex-col gap-1" data-status={response.status}>
              <p dir="ltr" className="flex flex-wrap items-center gap-2 text-sm">
                <Chip size="sm" variant="soft" color={isError(response.status) ? "danger" : "success"}>
                  <Icon name={isError(response.status) ? "error" : "check"} className="size-3.5" />
                  {response.status === "default" ? t("reference.errorStatus") : response.status}
                </Chip>
              </p>
              {response.shared ? <Prose text={api.shared[response.shared] ?? ""} /> : response.description ? <Prose text={response.description} /> : null}
              {response.body ? <BodyView body={response.body} api={api} /> : null}
            </li>
          ))}
        </ul>
      </section>
      <CopyBlock label={t("reference.example", {name: op.id})} text={curlOf(op, origin, api.server)} />
    </div>
  );
}
