"use client";

import {Alert, Button} from "@heroui/react";
import {useTranslations} from "next-intl";

import {useErrorText} from "../feedback/errorText.ts";

// A page of the Endpoint list failed after the first one came in (or a refetch failed): the rows on screen may be only part of the
// tenant's, so the screen says so and offers to ask again. Select All stays off until the list is whole (S5-r1-4, S5-r1-11).

export function PartialListNotice({error, onRetry}: {error: unknown; onRetry: () => void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const errorText = useErrorText();
  return (
    <Alert status="warning" role="alert" data-testid="endpoints-partial">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{t("list.partial.title")}</Alert.Title>
        <Alert.Description>
          {t("list.partial.text")} {errorText(error)}
        </Alert.Description>
      </Alert.Content>
      <Button size="sm" variant="secondary" aria-label={t("list.partial.retryAria")} onPress={onRetry}>
        {c("retry")}
      </Button>
    </Alert>
  );
}
