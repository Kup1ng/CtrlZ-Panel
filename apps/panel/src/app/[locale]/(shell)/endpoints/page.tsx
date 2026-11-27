import {EndpointsListScreen} from "@ctrlz/ui/endpoints/EndpointsListScreen.tsx";
import {ReauthProvider} from "@ctrlz/ui/auth/ReauthDialog.tsx";
import {getTranslations} from "next-intl/server";

export async function generateMetadata() {
  const t = await getTranslations("shell");
  return {title: t("nav.endpoints")};
}

// This page is under no frame, so it has its own ReauthProvider: a sensitive write (a lock password, a token) can answer reauth_required.
// Lane P3a fills EndpointsListScreen (packages/ui/src/screens/lanes.ts).
export default function Page() {
  return (
    <ReauthProvider>
      <EndpointsListScreen />
    </ReauthProvider>
  );
}
