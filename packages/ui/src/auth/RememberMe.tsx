"use client";

import {Checkbox} from "@heroui/react";
import {useTranslations} from "next-intl";

// "Remember me" (AUTH 3.4): the refresh cookie lives 30 days, and the label says so. It is a plain
// checkbox, off by default, and it only becomes `remember_me` in the sign-in request.

export function RememberMe({isSelected, onChange, isDisabled}: {isSelected: boolean; onChange: (value: boolean) => void; isDisabled?: boolean}) {
  const t = useTranslations("auth");
  return (
    <Checkbox name="remember_me" variant="secondary" isSelected={isSelected} onChange={onChange} isDisabled={isDisabled}>
      <Checkbox.Content>
        <Checkbox.Control>
          <Checkbox.Indicator />
        </Checkbox.Control>
        {t("fields.remember")}
      </Checkbox.Content>
    </Checkbox>
  );
}
