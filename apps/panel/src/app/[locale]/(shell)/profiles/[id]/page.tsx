import {isLocale} from "@ctrlz/i18n/locale.ts";
import {redirect} from "@ctrlz/i18n/navigation.ts";
import {isUuid} from "@ctrlz/api-client/hooks/support.ts";
import {profileHref} from "@ctrlz/ui/profiles/profileRoutes.ts";
import {notFound} from "next/navigation";

// WF: a click on a profile goes to Profile Options.
export default async function Page({params}: {params: Promise<{id: string; locale: string}>}) {
  const {id, locale} = await params;
  if (!isUuid(id) || !isLocale(locale)) notFound();
  redirect({href: profileHref(id, "options"), locale});
}
