import {isLocale} from "@ctrlz/i18n/locale.ts";
import {redirect} from "@ctrlz/i18n/navigation.ts";
import {notFound} from "next/navigation";

// T-113: the locale root goes to the first sidebar entry.
export default async function Home({params}: {params: Promise<{locale: string}>}) {
  const {locale} = await params;
  if (!isLocale(locale)) notFound();
  redirect({href: "/profiles", locale});
}
