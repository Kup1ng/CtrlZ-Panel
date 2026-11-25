import {MutationObserver, QueryClient} from "@tanstack/react-query";
import {describe, expect, it} from "vitest";

import {makeQueryClient, mutationDefaults} from "./queryDefaults.ts";

const nextTick = () => new Promise((resolve) => setTimeout(resolve, 5));

/** What a dialog does: run a mutation through an observer, then unmount (unsubscribe). */
async function runAndUnmount(client: QueryClient) {
  const observer = new MutationObserver(client, {mutationFn: async (password: string) => ({recoveryCodes: ["abcd-efgh"], echoed: password})});
  const unsubscribe = observer.subscribe(() => undefined);
  await observer.mutate("correct horse battery staple");
  unsubscribe();
}

// wp4-r7-3: a one-time secret (a password in the variables, recovery codes in the answer) must not
// outlive the dialog that showed it. The cache keeps a mutation for gcTime after its last observer.
describe("mutations leave no trace once the screen that ran them is gone (wp4-r7-3)", () => {
  it("the app's client drops a mutation, its variables and its answer, as soon as its observer unmounts", async () => {
    const client = makeQueryClient();
    await runAndUnmount(client);
    await nextTick();
    expect(client.getMutationCache().getAll()).toHaveLength(0);
  });

  it("while the dialog is open the answer is still there to show", async () => {
    const client = makeQueryClient();
    const observer = new MutationObserver(client, {mutationFn: async () => ({recoveryCodes: ["abcd-efgh"]})});
    const unsubscribe = observer.subscribe(() => undefined);
    await observer.mutate(undefined);
    await nextTick();
    expect(observer.getCurrentResult().data).toEqual({recoveryCodes: ["abcd-efgh"]});
    unsubscribe();
  });

  it("TanStack's own default keeps them (5 minutes), which is the leak this default closes", async () => {
    const client = new QueryClient();
    await runAndUnmount(client);
    await nextTick();
    const [kept] = client.getMutationCache().getAll();
    expect(kept?.state.variables).toBe("correct horse battery staple");
  });

  it("is a default of the client, so a screen cannot forget it", () => {
    expect(mutationDefaults.gcTime).toBe(0);
    expect(makeQueryClient().getDefaultOptions().mutations?.gcTime).toBe(0);
  });
});
