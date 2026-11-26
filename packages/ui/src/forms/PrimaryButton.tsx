"use client";

import {Button} from "@heroui/react";
import type {ComponentProps} from "react";

import {buzz} from "../hooks/useHaptics.ts";

// T-310. The one place where a primary action gives its haptic pulse: every primary Button that acts (a submit, a create, a
// confirm that starts a call) is this component, so a page neither calls `buzz` nor forgets it. `variant` is fixed. A Button that
// is disabled or pending does not press, so nothing buzzes for a refusal. The pulse comes before the handler, so a handler that
// throws or navigates away still gave it.

export type PrimaryButtonProps = Omit<ComponentProps<typeof Button>, "variant">;

export function PrimaryButton({onPress, ...props}: PrimaryButtonProps) {
  return (
    <Button
      {...props}
      variant="primary"
      onPress={(event) => {
        buzz();
        onPress?.(event);
      }}
    />
  );
}
