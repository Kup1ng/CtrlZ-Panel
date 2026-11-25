// A write-only secret that is not the password of the person typing it (an SMS gateway key, the account name of a gateway)
// sits on the same origin as their saved console login. Browsers ignore `autocomplete="off"` on a password field and on the
// text field next to it, so Chrome, Edge, Firefox and Safari fill the console username and password into it and offer to
// save what was typed there as the console login. A key filled that way is sent sealed to a third party: the strongest
// credential of the service would leave with the next OTP (wp10-r1-5).
//
// What keeps a manager out is the field's type and name. The browsers' own managers look only at `type="password"` fields
// and ignore the attributes below, so the secret is a text input masked by CSS (PasswordField with `autoComplete="off"`;
// where the browser cannot draw the mask it is a password input instead, see there), with a name that is neither `username` nor `password` (wp10-r2-6). The attributes here are the opt-out of the managers
// that do read them (1Password, LastPass, Bitwarden, Dashlane): they are a second layer, not the one that stops the browser.

/** Attributes for the input of a field a password manager must neither fill nor offer to save. */
export const NO_MANAGER = {
  "data-1p-ignore": "true",
  "data-lpignore": "true",
  "data-bwignore": "true",
  "data-form-type": "other",
} as const;
