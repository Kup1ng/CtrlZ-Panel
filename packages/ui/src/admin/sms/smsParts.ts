// Spec 13.3, Templates tab. How many billed parts a template body costs, as the editor shows it live: the characters and
// the parts with `{code}` filled by a code of full length. A message is GSM-7 when every character is in the GSM 03.38
// alphabet (160 units for one part, then 153 per part), and UCS-2 as soon as one is not, which a Persian body always is
// (70 units for one part, then 67 per part). In GSM-7 a few characters (the extension table) cost two units. In UCS-2 a
// character outside the BMP is two units, as it is on the wire.
//
// An estimate, not a bill: the gateway may add its own text (the telecom's opt-out line, «لغو11», on a Persian OTP), and
// that is why the one-part templates have a bound below. Pure, so the figures are tested without a DOM.

/** The OTP code length (AUTH 5.1), used to fill `{code}` the way a real message would be. */
export const OTP_CODE_LENGTH = 6;

const GSM_BASIC = new Set(
  "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà",
);
const GSM_EXTENSION = new Set("^{}\\[~]|€\f");

export type Encoding = "gsm7" | "ucs2";

export type SmsCount = {
  encoding: Encoding;
  /** Characters of the message as a person counts them (code points). */
  characters: number;
  /** Units of the encoding: what the limits below are measured in. */
  units: number;
  /** Units of one part, and of each part once there are several. */
  single: number;
  multi: number;
  parts: number;
};

/** The body as it would go out: `{code}` becomes a code of full length, every other placeholder is left as typed. */
export function filled(body: string): string {
  return body.replaceAll("{code}", "0".repeat(OTP_CODE_LENGTH));
}

export function countSms(body: string): SmsCount {
  const text = filled(body);
  const chars = [...text];
  const gsm = chars.every((ch) => GSM_BASIC.has(ch) || GSM_EXTENSION.has(ch));
  if (gsm) {
    const units = chars.reduce((sum, ch) => sum + (GSM_EXTENSION.has(ch) ? 2 : 1), 0);
    return {encoding: "gsm7", characters: chars.length, units, single: 160, multi: 153, parts: units === 0 ? 0 : units <= 160 ? 1 : Math.ceil(units / 153)};
  }
  // UTF-16 units, which is what `.length` counts: a character outside the BMP is a pair.
  const units = text.length;
  return {encoding: "ucs2", characters: chars.length, units, single: 70, multi: 67, parts: units === 0 ? 0 : units <= 70 ? 1 : Math.ceil(units / 67)};
}

/**
 * The three login-code templates (`otp`, `otp_reset`, `otp_phone`) are held to ONE billed part by the API (owner decision
 * D58): the daily money cap counts one part for each message, so a body that needs two would understate it. This is the
 * rule of `sms.CheckBodyLength` on the server, with its figures: 64 UCS-2 units in Persian (70 for one part, minus the room
 * for the telecom's opt-out line, «لغو11»), and in English 160 GSM-7 units with every character inside the GSM alphabet (one
 * outside it sends the whole message as UCS-2, 70 units). Other keys are not bounded.
 */
export const OTP_FA_MAX_UNITS = 64;
export const OTP_EN_MAX_UNITS = 160;
const ONE_PART_KEYS: ReadonlySet<string> = new Set(["otp", "otp_reset", "otp_phone"]);

export const isOnePartKey = (key: string): boolean => ONE_PART_KEYS.has(key);

/**
 * Why the API would refuse this body for a one-part template, or null when it would not. `text` is the body as it will be
 * sent (cleaned) and `locale` the template's own language, which picks the bound exactly as the server does.
 * "too_long": over the unit bound. "not_gsm": an English body with a character outside the GSM alphabet.
 */
export function otpBodyRefusal(key: string, locale: string, text: string): "too_long" | "not_gsm" | null {
  if (!isOnePartKey(key)) return null;
  if (locale === "en") {
    const count = countSms(text);
    if (count.encoding !== "gsm7") return "not_gsm";
    return count.units > OTP_EN_MAX_UNITS ? "too_long" : null;
  }
  // Persian is counted in UTF-16 units whatever the characters are, as the server does.
  return filled(text).length > OTP_FA_MAX_UNITS ? "too_long" : null;
}

/** The `{name}` placeholders of a body, in order, without repeats: the mapping of a gateway must name as many parameters. */
export function placeholders(body: string): string[] {
  return [...new Set([...body.matchAll(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g)].map((m) => m[1]!))];
}
