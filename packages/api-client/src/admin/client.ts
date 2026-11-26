import {createApiClient} from "../core.ts";
import type {paths} from "../generated/admin";

/**
 * The admin API. No refresh: an admin session simply ends (spec 11.4, AUTH 3.3),
 * and a 401 goes to the login page with a "session ended" notice.
 */
export const adminApi = createApiClient<paths>({refresh: false});
