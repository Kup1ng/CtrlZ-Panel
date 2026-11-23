// One JSON file per namespace under messages/<locale>/. Each work package
// writes keys only in its own namespace (spec 4.5).
export const NAMESPACE_OWNER = {
  common: "WP3",
  errors: "WP4",
  shell: "WP6",
  feedback: "WP7",
  auth: "WP8",
  account: "WP9",
  admin: "WP10",
  lab: "WP11",
} as const;

export type Namespace = keyof typeof NAMESPACE_OWNER;
export type AppId = "panel" | "admin";

// What each app receives, on the server and in the browser. `panel` never
// receives `admin` and `admin` never receives `account`, so a tenant's browser
// holds no admin wording. `lab` exists only in the panel (the lab pages).
export const APP_NAMESPACES = {
  panel: ["common", "errors", "shell", "feedback", "auth", "account", "lab"],
  admin: ["common", "errors", "shell", "feedback", "auth", "admin"],
} as const satisfies Record<AppId, readonly Namespace[]>;

// Namespaces whose files do not exist yet. The loader skips only these, so a
// file that goes missing later is an error and not an empty page. The owner of
// a namespace deletes its entry here when the file lands, and adds one line to
// types.d.ts. A test fails if this list and the files on disk disagree.
export const PENDING_NAMESPACES = [
  "errors",
  "feedback",
  "auth",
  "account",
  "admin",
] as const satisfies readonly Namespace[];

export type PendingNamespace = (typeof PENDING_NAMESPACES)[number];

export function isPending(ns: string): boolean {
  return (PENDING_NAMESPACES as readonly string[]).includes(ns);
}

export type MessageTree = {[key: string]: string | MessageTree};
export type AppMessages = Partial<Record<Namespace, MessageTree>>;

/**
 * Keeps only the namespaces `app` is allowed to send to the browser. The
 * server may hold more, for example while a namespace is shared by a test.
 */
export function pickNamespaces<M extends Record<string, unknown>>(
  messages: M,
  app: AppId,
): Partial<M> {
  const allowed: readonly string[] = APP_NAMESPACES[app];
  const out: Record<string, unknown> = {};
  for (const [ns, value] of Object.entries(messages)) {
    if (allowed.includes(ns)) out[ns] = value;
  }
  return out as Partial<M>;
}
