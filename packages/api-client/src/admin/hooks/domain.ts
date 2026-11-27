import {infiniteQueryOptions, queryOptions, useInfiniteQuery, useMutation, useQuery, useQueryClient} from "@tanstack/react-query";

import {required} from "../../core.ts";
import type {components} from "../../generated/admin";
import {shouldRetry} from "../../queryDefaults.ts";
import {adminApi} from "../client.ts";

// P4, p4-nodes 9.2 and 10.4. The domain settings with their impact, and the certificates. Writes are `admin-fresh`. The Domain page
// (a later package) uses these; they are here so that every resource has its hooks and its mock in one place.

type S = components["schemas"];
export type DomainSettings = S["DomainSettings"];
export type DomainRequest = S["DomainRequest"];
export type DomainImpact = S["DomainImpact"];
export type CertificateView = S["CertificateView"];
export type UploadCertificateRequest = S["UploadCertificateRequest"];

export const TRANSITION_DAYS_MIN = 1;
export const TRANSITION_DAYS_MAX = 90;
export const TRANSITION_DAYS_DEFAULT = 30;

export const domainKeys = {
  settings: ["admin", "domain", "settings"] as const,
  impact: ["admin", "domain", "impact"] as const,
  certificates: ["admin", "certificates"] as const,
};

export const domainQueryOptions = () =>
  queryOptions({queryKey: domainKeys.settings, queryFn: async ({signal}) => required(await adminApi.GET("/settings/domain", {signal})), retry: shouldRetry});
export const useDomain = () => useQuery(domainQueryOptions());

/** What a change of the zone touches: the Endpoints and the Apple profiles already made. Asked fresh, never kept across visits. */
export function useDomainImpact(enabled = true) {
  return useQuery({
    queryKey: domainKeys.impact,
    queryFn: async ({signal}) => required(await adminApi.GET("/settings/domain/impact", {signal})),
    enabled,
    staleTime: 0,
    gcTime: 0,
    retry: shouldRetry,
  });
}

export function useSaveDomain() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: DomainRequest) => required(await adminApi.PUT("/settings/domain", {body})),
    onSuccess: (settings) => queryClient.setQueryData(domainKeys.settings, settings),
  });
}

export const certificatesQueryOptions = () =>
  infiniteQueryOptions({
    queryKey: domainKeys.certificates,
    queryFn: async ({pageParam, signal}) => required(await adminApi.GET("/certificates", {params: {query: {cursor: pageParam, limit: 50}}, signal})),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor,
    retry: shouldRetry,
  });
export const useCertificates = () => useInfiniteQuery(certificatesQueryOptions());

/** The PEM chain and key are in the request only: nothing here keeps them, and the answer holds no chain and no key. */
export function useUploadCertificate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: UploadCertificateRequest) => required(await adminApi.POST("/certificates", {body})),
    onSettled: () => queryClient.invalidateQueries({queryKey: domainKeys.certificates}),
  });
}

export function useRetireCertificate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await adminApi.POST("/certificates/{id}:retire", {params: {path: {id}}});
    },
    onSettled: () => queryClient.invalidateQueries({queryKey: domainKeys.certificates}),
  });
}
