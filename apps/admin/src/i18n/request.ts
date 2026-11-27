import {createRequest} from "@ctrlz/i18n/request.ts";
// Replaced by the Next compiler. It reads the [locale] segment of the root
// layout, which is why there is no app/layout.tsx.
import {locale} from "next/root-params";

export default createRequest("admin", locale);
