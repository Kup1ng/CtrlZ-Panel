import {isLocale} from "@ctrlz/i18n/locale.ts";
import {redirect} from "@ctrlz/i18n/navigation.ts";
import {isUuid} from "@ctrlz/api-client/hooks/support.ts";
import {endpointHref} from "@ctrlz/ui/endpoints/endpointRoutes.ts";
import {notFound} from "next/navigation";

export default async function Page({params}: {params: Promise<{id: string; locale: string}>}) {
  const {id, locale} = await params;
  if (!isUuid(id) || !isLocale(locale)) notFound();
  redirect({href: endpointHref(id, "clients"), locale});
}
