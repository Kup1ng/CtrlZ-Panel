import {QueryClient} from "@tanstack/react-query";
import {describe, expect, it} from "vitest";

import {checkKey, checkServerValue} from "./useServerCheck.ts";

// wp10-r9-4. A failed read before a write must not reach the page's own query: every admin page swaps its form for a section error
// when its query has an error, which threw the open form and the admin's edits away.
const KEY = ["sms", "limits"] as const;
const same = (a: number, b: number) => a === b;

function setup(read: () => Promise<{cap: number}>) {
  const queryClient = new QueryClient({defaultOptions: {queries: {retry: false}}});
  queryClient.setQueryData(KEY, {cap: 1});
  const options = {queryKey: KEY, queryFn: read, retry: false as const};
  return {queryClient, options};
}

describe("checkServerValue", () => {
  it("leaves the page's query without an error when the read fails, and throws for the form's catch block", async () => {
    const {queryClient, options} = setup(() => Promise.reject(new Error("503")));
    await expect(checkServerValue(queryClient, options, (d) => d.cap, 1, same)).rejects.toThrow("503");
    const page = queryClient.getQueryState(KEY);
    expect(page?.error).toBeNull();
    expect(page?.status).toBe("success");
    expect(page?.data).toEqual({cap: 1});
  });

  it("does not leave its own query behind", async () => {
    const {queryClient, options} = setup(() => Promise.resolve({cap: 1}));
    await checkServerValue(queryClient, options, (d) => d.cap, 1, same);
    await Promise.resolve();
    expect(queryClient.getQueryCache().find({queryKey: checkKey(KEY), exact: true})?.getObserversCount() ?? 0).toBe(0);
  });

  it("is true, and leaves the page's value, when the server still holds what the form saw", async () => {
    const {queryClient, options} = setup(() => Promise.resolve({cap: 1}));
    expect(await checkServerValue(queryClient, options, (d) => d.cap, 1, same)).toBe(true);
    expect(queryClient.getQueryData(KEY)).toEqual({cap: 1});
  });

  it("is false and puts the newer value in the page's query when it moved", async () => {
    const {queryClient, options} = setup(() => Promise.resolve({cap: 9}));
    expect(await checkServerValue(queryClient, options, (d) => d.cap, 1, same)).toBe(false);
    expect(queryClient.getQueryData(KEY)).toEqual({cap: 9});
    expect(queryClient.getQueryState(KEY)?.error).toBeNull();
  });
});
