"use client";

import {Form} from "@heroui/react";
import {createContext, useContext, type ReactNode} from "react";

import type {ApiForm} from "./useApiForm.ts";

// The `<Form>` of every auth page: the messages come from our i18n and not from the browser
// (`validationBehavior="aria"`), and the element is handed to `useApiForm`, which moves the focus to the
// first invalid field. Each field gets its own message from `form.bind` as `error` and shows it through
// `isInvalid`: React Aria's `validationErrors` kept an old field's message and did not show a new one in
// the next field, so messages that the page or the server set are not passed through it. The element is
// taken out of `form` here, once, because the React compiler's lint takes an object whose member is
// passed as a `ref` to be a ref itself, and then rejects every other read of it in the page component.

/** Whether the form must not be sent now (a wait, or offline), for the Retry button of a FormError inside it. */
const BlockedContext = createContext(false);
export const useFormBlocked = () => useContext(BlockedContext);

export function AuthForm({form, onSubmit, children}: {form: ApiForm; onSubmit: () => void; children: ReactNode}) {
  const {attachForm, blocked} = form;
  return (
    <BlockedContext value={blocked}>
      <Form
        className="flex flex-col gap-4"
        ref={attachForm}
        validationBehavior="aria"
        // The server render has no handler until React hydrates. A form without a method submits as a GET, so
        // a submit that no button blocks (a password manager's requestSubmit, form.submit()) would put the
        // password in the address bar, the history, the Referer and the access logs (wp8-r2-9). A POST puts
        // it in a body that none of them record, and after hydration onSubmit stops the native submit anyway.
        method="post"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        {children}
      </Form>
    </BlockedContext>
  );
}
