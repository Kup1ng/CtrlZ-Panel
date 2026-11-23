import {isLocale} from "@ctrlz/i18n/locale.ts";
import {redirect} from "@ctrlz/i18n/navigation.ts";
import {notFound} from "next/navigation";

// "/" in the admin goes to Users (spec 19.2). The Users page is WP10's.
export default async function Home({params}: {params: Promise<{locale: string}>}) {
  const {locale} = await params;
  if (!isLocale(locale)) notFound();
  redirect({href: "/users", locale});
}
