import type {AlertRow} from "@ctrlz/api-client/admin/hooks/alerts.ts";

// Spec 13.6. What an operator alert says. The API gives a kind and closed params (`RowParams`), never text, so the
// words are ours: `admin.alerts.<kind>` with the params as values, and a generic line for a kind this client does
// not know yet (the kinds of later phases arrive as `other`). Pure, so the choice of key is tested without a DOM.

/** The gateways the SMS page names, as a visitor knows them. Product names, not words of either language. */
export const PROVIDER_NAMES: Record<string, string> = {sms_ir: "sms.ir", melipayamak: "Melipayamak", noop: "noop"};

/** The classes of an SMS failure (AUTH 9.1). The API may send the name or its number, so both are read. */
const CLASS_BY_NUMBER = ["transient", "auth", "credit", "config", "recipient", "blacklisted"] as const;
export type FailureClass = (typeof CLASS_BY_NUMBER)[number];

function failureClass(value: unknown): FailureClass | undefined {
  if (typeof value === "number") return CLASS_BY_NUMBER[value - 1];
  return CLASS_BY_NUMBER.find((name) => name === value);
}

const SMS_KINDS = new Set(["sms_gateway", "sms_down", "sms_outbox_cap", "sms_payload"]);

/** An alert about the SMS service: shown on the SMS page as well as in the stack. */
export const isSmsAlert = (alert: Pick<AlertRow, "kind">): boolean => SMS_KINDS.has(alert.kind);

export type AlertText = {
  /** A key under `admin.alerts`. */
  titleKey: string;
  /** A key under `admin.alerts`, or none. */
  textKey?: string;
  values: {provider: string};
  /** The closed code the worker recorded (`no_credentials`, `timeout`...), for a `<Tech>` line. Never user text. */
  code?: string;
};

const param = (alert: Pick<AlertRow, "params">, name: string): unknown => (alert.params as Record<string, unknown>)[name];

/**
 * `known` says which keys the message catalogue has (`t.has`). A kind or a class without a line falls back to the
 * generic one, so a newer API never breaks an older page.
 */
export function alertText(alert: Pick<AlertRow, "kind" | "params">, known: (key: string) => boolean): AlertText {
  const rawProvider = param(alert, "provider");
  const provider = typeof rawProvider === "string" ? (PROVIDER_NAMES[rawProvider] ?? rawProvider) : "";
  const code = typeof param(alert, "code") === "string" ? String(param(alert, "code")) : typeof param(alert, "reason") === "string" ? String(param(alert, "reason")) : undefined;
  const values = {provider};

  if (alert.kind === "sms_gateway") {
    const cls = failureClass(param(alert, "class"));
    const textKey = cls && known(`sms_gateway.${cls}`) ? `sms_gateway.${cls}` : "sms_gateway.other";
    return {titleKey: "sms_gateway.title", textKey, values, code};
  }
  if (known(`${alert.kind}.title`)) {
    return {titleKey: `${alert.kind}.title`, textKey: known(`${alert.kind}.text`) ? `${alert.kind}.text` : undefined, values, code};
  }
  return {titleKey: "generic.title", textKey: "generic.text", values, code};
}
