import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import type {ResolverView} from "@ctrlz/api-client/hooks/setup.ts";

/**
 * Where the setup flow gets its values and what it may do. The owner's dialog has a session: generators, the Apple profile of the profile
 * and Endpoint, the claim page. A share page has none: the Resolver view came with the link, and the only thing it can ask is the Apple
 * profile of the link itself (spec p3 7.2). `link` is a secret of the page: it goes in a request body and nowhere else.
 */
export type SetupSource =
  | {kind: "endpoint"; endpoint: Endpoint; view: ResolverView}
  | {kind: "share"; link: string; view: ResolverView};

/** `version` is the platform's version when it is not the default one (it travels in `setupOs`, platforms.ts `parseSetupNav`). */
export type SetupNav = {os: string | null; step: number | null; version?: string | null};
