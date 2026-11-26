import {createApiClient} from "./core.ts";
import type {paths} from "./generated/panel";
import {handleSessionEnded} from "./session.ts";

/**
 * The tenant API (spec 14.2). `api.use(errorMiddleware, refreshMiddleware)` of the
 * spec is spelled in `createApiClient`, which registers the error middleware first
 * so that the refresh middleware sees a 401 before it is turned into an error.
 */
export const api = createApiClient<paths>({refresh: {onEnded: handleSessionEnded}});
