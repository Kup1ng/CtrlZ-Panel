import type {Locale} from "./locale.ts";
import {APP_NAMESPACES, isPending, type AppId, type AppMessages, type MessageTree, type Namespace} from "./namespaces.ts";

async function loadNamespace(locale: Locale, ns: Namespace): Promise<MessageTree | undefined> {
  try {
    // A template with a fixed folder and extension: the bundler turns it into
    // one chunk per file, and nothing is read at run time beyond these files.
    const mod = (await import(`../messages/${locale}/${ns}.json`)) as {default: MessageTree};
    return mod.default;
  } catch (error) {
    if (isPending(ns)) return undefined;
    throw error;
  }
}

/** Loads every namespace of `app` for `locale`, as `{common: {...}, ...}`. */
export async function loadMessages(locale: Locale, app: AppId): Promise<AppMessages> {
  const names = APP_NAMESPACES[app];
  const loaded = await Promise.all(names.map((ns) => loadNamespace(locale, ns)));
  const out: AppMessages = {};
  names.forEach((ns, i) => {
    const tree = loaded[i];
    if (tree) out[ns] = tree;
  });
  return out;
}
