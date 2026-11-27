import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";

// The data of the admin's user menu (spec 13). `apps/admin/src/nav.ts` builds the list with the server layout's own
// translator, and the client menu renders it, so the type lives where both can import it: an app may import `ui`, and
// `ui` may not import an app.

export type AdminUserMenuItem = {id: "account" | "logout"; label: string; icon: GeneralIconName};
