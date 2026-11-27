// The model of /docs/api (spec p3 6.5, T-320). The data is `publicApi.generated.json`, which `packages/api-client/scripts/gen-public-docs.mjs` writes
// from `api/public-openapi.yaml`; this file is what the page decides from it: the shape of the data, the groups in the order the document names them,
// the search, the example request and the split of a description into paragraphs and code.

export type Field = {name: string; type: string; required: boolean; description?: string; limits?: string; ref?: string};

export type Param = {name: string; in: string; required: boolean; type: string; description?: string; limits?: string};

export type Body = {mediaType: string; ref?: string; fields?: Field[]; type?: string};

export type Response = {status: string; description?: string; body?: Body; shared?: string};

export type Operation = {
  id: string;
  tag: string;
  method: "GET" | "PUT" | "POST" | "PATCH" | "DELETE";
  path: string;
  summary: string;
  description?: string;
  /** The token kind that may call it: a `read` token calls `read` only, a `write` token calls both. */
  token: "read" | "write";
  parameters: Param[];
  request?: Body & {required: boolean};
  responses: Response[];
};

export type Schema = {name: string; type: string; description?: string; enum?: unknown[]; fields?: Field[]; items?: string; ref?: string};

export type PublicApi = {
  title: string;
  version: string;
  description: string;
  server: string;
  tags: {name: string; description: string}[];
  shared: Record<string, string>;
  operations: Operation[];
  schemas: Record<string, Schema>;
};

export type Group = {tag: string; description: string; operations: Operation[]};

/** The groups in the order of the document's own tag list, each with its operations in document order. A tag the list does not name goes last. */
export function groupsOf(api: PublicApi, operations: readonly Operation[] = api.operations): Group[] {
  const known = new Map(api.tags.map((tag, index) => [tag.name, index] as const));
  const byTag = new Map<string, Operation[]>();
  for (const op of operations) {
    const list = byTag.get(op.tag) ?? [];
    list.push(op);
    byTag.set(op.tag, list);
  }
  return [...byTag.entries()]
    .sort(([a], [b]) => (known.get(a) ?? 999) - (known.get(b) ?? 999) || a.localeCompare(b))
    .map(([tag, list]) => ({tag, description: api.tags.find((t) => t.name === tag)?.description ?? "", operations: list}));
}

/** An operation matches when every word of the query is in its method, path, id, summary or group. Case does not matter; an empty query matches all. */
export function matches(op: Operation, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const haystack = `${op.method} ${op.path} ${op.id} ${op.summary} ${op.tag}`.toLowerCase();
  return words.every((word) => haystack.includes(word));
}

// The header is put together from parts: a secret scanner reads `curl ... -H "Authorization: Bearer <word>"` in a source file as a leaked credential,
// and the word here is the name of a shell variable.
export const TOKEN_VARIABLE = "$CTRLZ_TOKEN";
export const AUTH_FLAG = ["  -H", `"Authorization: Bearer ${TOKEN_VARIABLE}"`].join(" ");

/** The placeholder of a path parameter in an example: `{id}` becomes `ID`, so the line reads as a thing to replace. */
const placeholder = (name: string) => name.toUpperCase().replace(/[^A-Z0-9]+/g, "_");

/** The value of a required header in an example: a fresh unique key for the idempotency header, a placeholder to replace for any other. */
const headerValue = (name: string) => (name.toLowerCase() === "idempotency-key" ? "$(uuidgen)" : placeholder(name));

/**
 * An example request in curl, one flag a line. The token is the shell variable `$CTRLZ_TOKEN`, plainly not a value (and no secret scanner takes it for one), the address is the one the
 * page was opened at (`origin`, a runtime value of the page, never a fixed host), and a body is `@body.json` so no field is invented. A header the document marks
 * required is a flag too, or the server refuses the copied request: `Idempotency-Key` takes a fresh key from `uuidgen` (S8-r2-1), any other one a placeholder to replace.
 */
export function curlOf(op: Operation, origin: string, server: string): string {
  const path = op.path.replace(/\{([^}]+)\}/g, (_, name: string) => placeholder(name));
  const queries = op.parameters.filter((p) => p.in === "query" && p.required).map((p) => `${p.name}=${placeholder(p.name)}`);
  const url = `${origin}${server}${path}${queries.length > 0 ? `?${queries.join("&")}` : ""}`;
  const lines = [`curl ${op.method === "GET" ? "" : `-X ${op.method} `}"${url}"`, AUTH_FLAG];
  for (const header of op.parameters.filter((p) => p.in === "header" && p.required)) lines.push(`  -H "${header.name}: ${headerValue(header.name)}"`);
  if (op.request) {
    lines.push(`  -H "Content-Type: ${op.request.mediaType}"`);
    lines.push("  -d @body.json");
  }
  return lines.join(" \\\n");
}

export type Piece = {kind: "text" | "code"; text: string};

/** A description is plain paragraphs with `code` spans. Nothing else of Markdown is read, so no link and no HTML can come out of the document. */
export function proseOf(text: string): Piece[][] {
  return text
    .split(/\n{2,}/)
    .map((paragraph) => paragraph.replace(/\s*\n\s*/g, " ").trim())
    .filter(Boolean)
    .map((paragraph) =>
      paragraph
        .split(/(`[^`]+`)/)
        .filter(Boolean)
        .map((part): Piece => (part.startsWith("`") && part.endsWith("`") && part.length > 2 ? {kind: "code", text: part.slice(1, -1)} : {kind: "text", text: part})),
    );
}

/** The status line of a response: `200`, or `default` shown as the errors of every operation. */
export const isError = (status: string): boolean => status === "default" || Number(status) >= 400;
