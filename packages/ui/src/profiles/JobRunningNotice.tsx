"use client";

import {Alert, Button} from "@heroui/react";
import {useTranslations} from "next-intl";

// Spec p2 3.5, 9.2 (T-192). A 409 `job_running` on Import or Duplicate: the tenant already has a large job, and THIS request was not
// started. The form stays as it is, with the file or the name the person chose, and says so; the running job, which may be a rules batch or
// an upload and not this action at all, is opened only when the person asks (`onShow`), under a title of its own kind.

export function JobRunningNotice({onShow}: {onShow: () => void}) {
  const t = useTranslations("profiles");
  return (
    <Alert status="warning" data-testid="job-running">
      <Alert.Indicator />
      <Alert.Content className="min-w-0">
        <Alert.Title>{t("dialogs.jobRunning.title")}</Alert.Title>
        <Alert.Description>{t("dialogs.jobRunning.text")}</Alert.Description>
        <Button size="sm" variant="secondary" className="mt-2 self-start" onPress={onShow}>
          {t("dialogs.jobRunning.show")}
        </Button>
      </Alert.Content>
    </Alert>
  );
}
