// Not a test run by vitest: `tsc --noEmit` checks it. It proves that
// types.d.ts is in the program and that message keys and locales are checked.
import {createTranslator, type Locale, type Messages} from "next-intl";

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
// eslint-disable-next-line @typescript-eslint/no-unused-vars
declare function assert<T extends true>(): void;

assert<Equal<Locale, "fa" | "en">>();
assert<Equal<Messages["common"]["close"], string>>();

const t = createTranslator({locale: "fa", messages: {} as Messages, namespace: "common"});
t("close");
t("theme.dark");
// @ts-expect-error a key that is in no file
t("closeee");
// @ts-expect-error a namespace key one level too deep
t("theme.dark.x");
