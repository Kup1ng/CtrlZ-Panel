"use client";

import {useFieldErrorText} from "./errorText.ts";

// The text of a field code on a screen of P2 or P3. It is `useFieldErrorText` with the `profiles` namespace first, which holds the three codes
// that the admin console words itself (errors.ts, SCREEN_OWN_FIELD_CODES), then the shared `errors.fields`, then the generic "not valid" line.
// Every screen of the profiles and of the Endpoints reads field codes through it.
export function useScreenFieldText() {
  return useFieldErrorText("profiles");
}
