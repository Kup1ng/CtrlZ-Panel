import {hasCode} from "@ctrlz/api-client/errors.ts";
import {sessionGuard} from "@ctrlz/api-client/sessionEnd.ts";

import {isHandledError} from "../../feedback/handleApiError.ts";

/**
 * The quiet write of a switch row, apart from React so a test can end a session in the middle of it (S2-r3-5): sends, and on a refusal says
 * so through `notify`, except for an error the app already handled, a 423 (the banner says it) and any answer that comes after the session
 * ended, which is not the present person's. Resolves to whether it worked.
 */
export async function sendQuietly<T>(send: (body: T) => Promise<unknown>, body: T, failed: string, errorText: (error: unknown) => string, notify: (message: string) => void): Promise<boolean> {
  const alive = sessionGuard();
  const error = await send(body);
  if (error === null) return true;
  if (!alive()) return false;
  if (!isHandledError(error) && !hasCode(error, "profile_locked")) notify(`${failed} ${errorText(error)}`);
  return false;
}
