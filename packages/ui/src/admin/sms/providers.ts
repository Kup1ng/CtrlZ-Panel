import type {SmsProvider} from "@ctrlz/api-client/admin/hooks/sms.ts";

// Spec 13.3. What each gateway's credentials look like. The API checks only the shape of the object it gets
// (`{"api_key"}` for sms.ir, `{"username","password"}` for Melipayamak, nothing for `noop`); a real check is the test
// send. A field marked `secret` is typed hidden, and none of them is ever filled back: credentials are sealed on the
// server at once and never returned (admin-openapi.yaml, `PUT /sms/gateways/{provider}`).

export type CredentialField = {name: string; secret: boolean};

export const CREDENTIAL_FIELDS: Record<SmsProvider, readonly CredentialField[]> = {
  sms_ir: [{name: "api_key", secret: true}],
  melipayamak: [
    {name: "username", secret: false},
    {name: "password", secret: true},
  ],
  noop: [],
};

/** Product names, not words of either language, so they are the same in both and live here and not in the messages. */
export const PROVIDER_LABEL: Record<string, string> = {sms_ir: "sms.ir", melipayamak: "Melipayamak", noop: "noop"};

export const providerLabel = (provider: string): string => PROVIDER_LABEL[provider] ?? provider;



/** sms.ir types a template id as an int32 (`smsir.ParseTemplateID`): one it cannot send is refused by the PUT. */
export const SMSIR_MAX_TEMPLATE_ID = 2147483647;

/**
 * Whether the API's PUT would take this provider template id (`senders.ValidTemplateID`): 1 to 18 ASCII digits with a value
 * above zero for every provider, and for sms.ir also not above the int32 bound. `id` is already in ASCII digits.
 */
export function isTemplateId(provider: string, id: string): boolean {
  if (!/^[0-9]{1,18}$/.test(id)) return false;
  const value = BigInt(id);
  if (value <= 0n) return false;
  return provider !== "sms_ir" || value <= BigInt(SMSIR_MAX_TEMPLATE_ID);
}
