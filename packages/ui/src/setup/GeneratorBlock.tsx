"use client";

import {useGenerator, type GeneratorId} from "@ctrlz/api-client/hooks/setup.ts";
import {Skeleton} from "@heroui/react";
import {useTranslations} from "next-intl";

import {SectionError} from "../feedback/SectionError.tsx";
import {CopyBlock} from "./CopyBlock.tsx";
import {SecretCopyNote} from "./SecretCopyNote.tsx";

// Automatic Setup of a platform that has a generator (spec p3 8.2): the text the API builds from the Resolver view, shown to copy. It
// carries the DoH token for the generators that need the URL, so it is a one-time secret for the clipboard. The ones that hold only an address or
// a host name (the Android private DNS host, the address list) carry no token and are copied as plain text.

const TOKEN_GENERATORS: readonly GeneratorId[] = ["windows-doh", "firefox-policy", "chromium-policy"];

export function GeneratorBlock({endpointId, generator, client = ""}: {endpointId: string; generator: GeneratorId; client?: string}) {
  const t = useTranslations("setup");
  const query = useGenerator(endpointId, generator, client);
  if (query.isError) return <SectionError error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return <Skeleton className="h-24 w-full" />;
  const secret = TOKEN_GENERATORS.includes(generator);
  return (
    <>
      <CopyBlock label={t(`generators.${generator}`)} text={query.data} secret={secret} />
      {secret ? <SecretCopyNote /> : null}
    </>
  );
}
