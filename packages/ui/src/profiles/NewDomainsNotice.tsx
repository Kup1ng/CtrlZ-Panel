"use client";

import {AlertDialog} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// T-537, D45. Switching New Domains on, and changing its mode, tells the person that names ending in .ir and .ایران are not covered, because
// their registration date is not published. The change has already been applied (a switch answers at once); this is the notice, and it holds
// no data, so it lives in state and not in the address. The same sentence is in the filter's explanation (`helpPane=filter.new-domains`).

export function NewDomainsNotice({isOpen, onClose}: {isOpen: boolean; onClose: () => void}) {
  const t = useTranslations("profiles");
  const c = useTranslations("common");
  return (
    <AlertDialog.Backdrop isOpen={isOpen} onOpenChange={(open) => !open && onClose()}>
      <AlertDialog.Container placement="center">
        <AlertDialog.Dialog className="sm:max-w-[400px]">
          <AlertDialog.CloseTrigger aria-label={c("close")} />
          <AlertDialog.Header>
            <AlertDialog.Icon status="warning">
              <Icon name="warning" className="size-5" />
            </AlertDialog.Icon>
            <AlertDialog.Heading>{t("filters.newDomains.title")}</AlertDialog.Heading>
          </AlertDialog.Header>
          <AlertDialog.Body>
            <p>{t("filters.newDomains.warning")}</p>
          </AlertDialog.Body>
          <AlertDialog.Footer>
            <PrimaryButton slot="close">
              {t("filters.newDomains.ok")}
            </PrimaryButton>
          </AlertDialog.Footer>
        </AlertDialog.Dialog>
      </AlertDialog.Container>
    </AlertDialog.Backdrop>
  );
}
