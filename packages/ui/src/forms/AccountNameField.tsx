"use client";

// The account name for the password manager, on a form that sets a new password and has no visible number field
// (Register's confirm step, Forgot Password step 3). Browsers pick the account name with a heuristic, the last text
// field before the password, so without this the SMS code could be saved as the name, or the entry for the
// number would keep the old password (wp8-r17-5). The field is read-only, outside the tab order and hidden from
// assistive technology; it is visually hidden and not `display: none` because password managers skip a field
// that is not rendered. Never use it with a masked number (/me and the invite give only `phone_masked`).

export function AccountNameField({phone}: {phone: string}) {
  return (
    <input
      type="text"
      name="username"
      data-account-name=""
      autoComplete="username"
      value={phone}
      readOnly
      tabIndex={-1}
      aria-hidden
      dir="ltr"
      className="sr-only"
    />
  );
}
