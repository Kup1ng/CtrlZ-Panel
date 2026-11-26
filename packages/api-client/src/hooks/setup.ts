import {queryOptions, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {api} from "../client.ts";
import {required} from "../core.ts";
import type {components} from "../generated/panel";
import {shouldRetry} from "../queryDefaults.ts";
import {endpointKeys} from "./profileKeys.ts";
import {isUuid} from "./support.ts";

// Spec p3 7 and 8. What a person is given to set a device up: the Resolver view (the one source of every value), the generators,
// share links, the Apple profile and its download link, and the public share view that a link opens without a session.
//
// Secrets: the DoH token lives in `ResolverView` and in the generators' text, so they are never put in a URL, a query key or storage
// (the cache holds them in memory only, like every query). A share URL and a download URL are returned once, by a mutation, and are shown
// in a state-only dialog.

export type ResolverView = components["schemas"]["ResolverView"];
export type ShareLink = components["schemas"]["ShareLink"];
export type ShareLinkCreated = components["schemas"]["ShareLinkCreated"];
export type ShareView = components["schemas"]["ShareView"];
export type AppleProfileRequest = components["schemas"]["AppleProfileRequest"];
export type ShareAppleParams = components["schemas"]["ShareAppleParams"];
export type AppleLink = components["schemas"]["AppleLink"];

/** Exactly the five protocols, from one list (D24, D51): the Resolvers page, the wizard and E8 all read it. */
export const RESOLVER_PROTOCOLS = ["plain", "doh", "doh3", "dot", "doq"] as const satisfies readonly ResolverView["protocols"][number][];

/** The ids of the registry of generators (spec p3 8.2). An id not in it is 404. */
export const GENERATOR_IDS = ["windows-doh", "firefox-policy", "chromium-policy", "android-private-dns", "address-list"] as const;
export type GeneratorId = (typeof GENERATOR_IDS)[number];

/** `ready` is false while the zone or the pair is missing: nothing is generated, and the routes that generate answer 409 `setup_unavailable`. */
export const isResolverReady = (view: Pick<ResolverView, "ready">): boolean => view.ready;

export const resolverViewQuery = (endpointId: string | undefined, client = "") =>
  queryOptions({
    queryKey: endpointKeys.resolvers(endpointId ?? "", client),
    queryFn: async ({signal}) =>
      required(await api.GET("/endpoints/{id}/resolvers", {params: {path: {id: endpointId!}, query: client ? {client} : {}}, signal})),
    enabled: isUuid(endpointId),
    retry: shouldRetry,
    // The view carries the DoH token: it is read when the dialog opens and forgotten soon after.
    gcTime: 60_000,
  });

export function useResolverView(endpointId: string | undefined, client = "", options: {enabled?: boolean} = {}) {
  return useQuery({...resolverViewQuery(endpointId, client), enabled: isUuid(endpointId) && (options.enabled ?? true)});
}

export const generatorQuery = (endpointId: string | undefined, generator: GeneratorId, client = "") =>
  queryOptions({
    queryKey: endpointKeys.generator(endpointId ?? "", generator, client),
    queryFn: async ({signal}): Promise<string> => {
      const result = (await api.GET("/endpoints/{id}/generators", {
        params: {path: {id: endpointId!}, query: {generator, ...(client ? {client} : {})}},
        parseAs: "text",
        signal,
      })) as unknown as {data?: string};
      return required(result);
    },
    enabled: isUuid(endpointId),
    retry: shouldRetry,
    gcTime: 60_000,
  });

/** The text of one generator (Windows commands, a Firefox policy, a router's address list), for the wizard's copy buttons. */
export function useGenerator(endpointId: string | undefined, generator: GeneratorId, client = "", options: {enabled?: boolean} = {}) {
  return useQuery({...generatorQuery(endpointId, generator, client), enabled: isUuid(endpointId) && (options.enabled ?? true)});
}

export const shareLinksQuery = (endpointId: string | undefined) =>
  queryOptions({
    queryKey: endpointKeys.shareLinks(endpointId ?? ""),
    queryFn: async ({signal}) => required(await api.GET("/endpoints/{id}/share-links", {params: {path: {id: endpointId!}}, signal})).links,
    enabled: isUuid(endpointId),
    retry: shouldRetry,
  });

export function useShareLinks(endpointId: string | undefined) {
  return useQuery(shareLinksQuery(endpointId));
}

/** A link that can still be used. The list puts these first; revoked and used-up ones are shown struck out and with a word. */
export const isShareLive = (link: Pick<ShareLink, "revoked" | "uses" | "max_uses" | "expires_at">, now: number): boolean =>
  !link.revoked && link.uses < link.max_uses && Date.parse(link.expires_at) > now;

/** The answer holds the URL, once: the caller keeps it in the state of the dialog that shows it and nowhere else. */
export function useCreateShareLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, client, ttlHours}: {endpointId: string; client?: string; ttlHours?: number}) =>
      required(
        await api.POST("/endpoints/{id}/share-links", {
          params: {path: {id: endpointId}},
          body: {...(client ? {client} : {}), ...(ttlHours ? {ttl_hours: ttlHours} : {})},
        }),
      ),
    onSuccess: (_created, v) => void queryClient.invalidateQueries({queryKey: endpointKeys.shareLinks(v.endpointId)}),
  });
}

export function useRevokeShareLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({endpointId, shareId}: {endpointId: string; shareId: string}) => {
      await api.DELETE("/endpoints/{id}/share-links/{sid}", {params: {path: {id: endpointId, sid: shareId}}});
    },
    onSuccess: (_x, v) => void queryClient.invalidateQueries({queryKey: endpointKeys.shareLinks(v.endpointId)}),
  });
}

/** `POST /endpoints/{id}/apple-profile`: a download link (15 minutes, 3 uses) for the profile built from the Advanced settings. */
export function useCreateAppleProfile() {
  return useMutation({
    mutationFn: async ({endpointId, ...body}: {endpointId: string} & AppleProfileRequest) =>
      required(await api.POST("/endpoints/{id}/apple-profile", {params: {path: {id: endpointId}}, body})),
  });
}

// ---- Public routes: no session, no shell. The link value is a secret and goes in a body, never in a URL of ours. ----

/** `POST /public/share`: what a share link shows. A junk, expired, revoked or used-up link is always the same 404. */
export async function openShare(link: string): Promise<ShareView> {
  return required(await api.POST("/public/share", {body: {link}}));
}

/** `POST /public/share/apple-profile`: a download link built from a share link. It spends one use of the share link. */
export async function createShareAppleProfile(link: string, params: ShareAppleParams): Promise<AppleLink> {
  return required(await api.POST("/public/share/apple-profile", {body: {link, params}}));
}

export function useOpenShare() {
  return useMutation({mutationFn: openShare});
}

export function useCreateShareAppleProfile() {
  return useMutation({mutationFn: ({link, params}: {link: string; params: ShareAppleParams}) => createShareAppleProfile(link, params)});
}
