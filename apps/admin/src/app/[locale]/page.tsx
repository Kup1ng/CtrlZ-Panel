import {isLocale} from "@ctrlz/i18n/locale.ts";
import {redirect} from "@ctrlz/i18n/navigation.ts";
import {notFound} from "next/navigation";

// "/" in the admin goes to Overview (p4-nodes 10.1; it was Users in spec 19.2 before the nodes had a page).
export default async function Home({params}: {params: Promise<{locale: string}>}) {
  const {locale} = await params;
  if (!isLocale(locale)) notFound();
  redirect({href: "/overview", locale});
}
