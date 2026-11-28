import {InviteFlow} from "@ctrlz/ui/auth/InviteFlow.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("auth");
  return {title: t("invite.title")};
}

export default function Page() {
  return <InviteFlow />;
}
