import {queryOptions, useQuery} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import {shouldRetry} from "../queryDefaults.ts";

// `GET /auth/config`: what the login pages and one shell banner need (spec 10.1,
// 8.8). Public, cached by the API for 30 seconds.

export const configKeys = {public: ["auth", "config"] as const};

export const publicConfigQueryOptions = () =>
  queryOptions({
    queryKey: configKeys.public,
    queryFn: async ({signal}) => required(await api.GET("/auth/config", {signal})),
    staleTime: 30_000,
    retry: shouldRetry,
  });

export function usePublicConfig(options: {enabled?: boolean} = {}) {
  return useQuery({...publicConfigQueryOptions(), enabled: options.enabled ?? true});
}
