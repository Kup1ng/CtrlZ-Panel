import type {useTranslations} from "next-intl";

// The wait that a 429 asks for, said in the unit a person reads. Most limits are short (a login, a code), and the button counts seconds. A daily budget
// (api tokens, feedback: 20 a day each, spec p3 9.1) answers with a Retry-After of tens of thousands of seconds, and "Try again in 71,234 s" says nothing,
// so past two minutes the button says minutes and past two hours it says hours (S8-r2-4). Always rounded up, so the button never says less than the wait.

export type Wait = {unit: "seconds" | "minutes" | "hours"; count: number};

export function waitOf(seconds: number): Wait {
  if (seconds <= 120) return {unit: "seconds", count: seconds};
  const minutes = Math.ceil(seconds / 60);
  if (minutes <= 120) return {unit: "minutes", count: minutes};
  return {unit: "hours", count: Math.ceil(minutes / 60)};
}

/** The label of a button that waits `seconds`, from the `auth` messages. */
export function retryText(t: ReturnType<typeof useTranslations<"auth">>, seconds: number): string {
  const {unit, count} = waitOf(seconds);
  if (unit === "seconds") return t("form.retryIn", {seconds: count});
  return unit === "minutes" ? t("form.retryInMinutes", {minutes: count}) : t("form.retryInHours", {hours: count});
}
