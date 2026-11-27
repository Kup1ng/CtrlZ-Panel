"use client";

import {useApiForm} from "../../forms/useApiForm.ts";

/** The namespace of the field-code texts that only the admin API answers (`admin.fieldErrors.<code>`). */
export const ADMIN_FIELD_ERRORS = "admin.fieldErrors";

/**
 * `useApiForm` for the admin app. The admin API names field codes the panel's does not (`price_required`, `public_suffix`,
 * `count`...), and their sentences are admin wording. They live in the admin namespace and not in the shared
 * `errors.fields`, where a panel code of the same name would have shown the admin sentence (wp10-r5-2). Every admin
 * form goes through here; adminNamespaceGuard.test.ts fails for one that calls useApiForm itself.
 */
export function useAdminForm(options: {focus?: string} = {}) {
  return useApiForm({...options, fieldNamespace: ADMIN_FIELD_ERRORS});
}
