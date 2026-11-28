"use client";

import {buttonVariants} from "@heroui/react";
import {EmptyState} from "@heroui-pro/react";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

// T-121. The 404 body. [locale]/not-found.tsx puts it inside the shell for a
// visitor who has a session cookie, and alone otherwise (spec 8.7).

export function NotFoundView({standalone = false}: {standalone?: boolean}) {
  const t = useTranslations("shell");
  return (
    <div className={standalone ? "not-found not-found--standalone" : "not-found"}>
      <EmptyState>
        <EmptyState.Header>
          <EmptyState.Media variant="icon">
            <Icon name="search" className="size-6" />
          </EmptyState.Media>
          <EmptyState.Title>{t("notFound.title")}</EmptyState.Title>
          <EmptyState.Description>{t("notFound.text")}</EmptyState.Description>
        </EmptyState.Header>
        <EmptyState.Content>
          <Link href="/" className={buttonVariants({variant: "primary"})}>
            {t("notFound.home")}
          </Link>
        </EmptyState.Content>
      </EmptyState>
    </div>
  );
}

