// Spec p3 6.5 (T-320): the page /docs/api draws the public OpenAPI document with our own components, so the document is turned at build
// time into one small JSON file that the page loads lazily. No renderer from outside, no request at run time.
//
//   node packages/api-client/scripts/gen-public-docs.mjs [--in api/public-openapi.yaml] [--out packages/ui/src/docs/publicApi.generated.json] [--spec-out packages/ui/src/docs/publicApiSpec.generated.json]
//
// A second file carries the OpenAPI document itself, as the text of the YAML, for the Download button of the page (S8-r2-2): a client generator, Postman or
// Swagger reads the real file and not the flat model below. The page loads it lazily, only when the button is pressed.
//
// The input is `api/public-openapi.yaml`, which `go run ./tools/genpublicapi` writes. A test (packages/ui/src/docs/publicApi.test.ts) fails when
// the JSON is not what this script writes from the YAML, so the page cannot go stale; it reads the YAML only when the file is there.
//
// The model is flat on purpose: named schemas live once in `schemas`, an operation points at them by name, and a schema lists its fields with a
// short type text, so a reader follows `Profile` to its own table instead of one operation holding a kilobyte of nested objects.

import {createRequire} from "node:module";
import {existsSync, readdirSync, readFileSync, writeFileSync} from "node:fs";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");

function arg(name, fallback) {
  const at = process.argv.indexOf(`--${name}`);
  return at > 0 && process.argv[at + 1] ? resolve(process.argv[at + 1]) : fallback;
}

// js-yaml is not a dependency of this package (adding one is a lockfile change for a build-time reader), but openapi-typescript brings it into the
// store, so the script finds the copy there. A repository that has no copy fails loudly. When two majors are installed the highest version is the one used,
// whatever order the directory lists them in, so the document is the same on every machine.
const versionOf = (dir) => (/^js-yaml@(\d+)\.(\d+)\.(\d+)/.exec(dir) ?? []).slice(1).map(Number);
const newer = (a, b) => {
  const left = versionOf(a);
  const right = versionOf(b);
  for (let i = 0; i < 3; i++) if (left[i] !== right[i]) return (right[i] ?? 0) - (left[i] ?? 0);
  return 0;
};
export function loadYaml() {
  const store = join(root, "node_modules", ".pnpm");
  const found = readdirSync(store)
    .filter((name) => /^js-yaml@\d+\.\d+\.\d+/.test(name))
    .sort(newer)[0];
  if (!found) throw new Error("js-yaml is not in node_modules/.pnpm: run pnpm install first");
  return createRequire(join(store, found, "node_modules", "js-yaml", "package.json"))("js-yaml");
}

/** The file the page offers for download: the YAML as written, with Unix line endings so the bytes do not depend on the machine that ran the generator. */
export function specOf(yamlText) {
  return {file: "ctrlz-public-api.yaml", yaml: String(yamlText).replace(/\r\n/g, "\n")};
}

const METHODS = ["get", "put", "post", "patch", "delete"];

// What a token may do is the security-relevant column of the reference, so a missing or unknown `x-ctrlz-token` is an error and not "read": a write
// operation that lost its annotation would be documented as callable with a read token (S8-r1-8). The server's lint and gate still decide; this keeps the page honest.
function tokenOf(op, method, path) {
  const value = op["x-ctrlz-token"];
  if (value !== "read" && value !== "write") {
    throw new Error(`${method.toUpperCase()} ${path}: x-ctrlz-token must be "read" or "write", got ${JSON.stringify(value)}`);
  }
  return value;
}

export function buildDocs(doc) {
  const schemas = {};
  const used = new Set();

  const refName = (ref) => ref.replace("#/components/schemas/", "");
  const resolveRef = (ref) => {
    const parts = ref.replace(/^#\//, "").split("/");
    return parts.reduce((node, part) => node?.[part], doc);
  };

  /** One line for a type: `string`, `uuid`, `integer`, `[Name]`, `{name: string}`, `a | b` for an enum. */
  function typeText(schema) {
    if (!schema) return "any";
    if (schema.$ref) {
      used.add(refName(schema.$ref));
      return refName(schema.$ref);
    }
    if (schema.enum) return schema.enum.map((value) => JSON.stringify(value)).join(" | ");
    if (schema.const !== undefined) return JSON.stringify(schema.const);
    if (schema.type === "array") return `[${typeText(schema.items)}]`;
    if (schema.type === "object" || schema.properties) {
      if (schema.additionalProperties && typeof schema.additionalProperties === "object") return `{string: ${typeText(schema.additionalProperties)}}`;
      return "object";
    }
    if (schema.format && schema.type === "string") return schema.format === "date-time" ? "date-time" : schema.format;
    return Array.isArray(schema.type) ? schema.type.join(" | ") : (schema.type ?? "any");
  }

  function limits(schema) {
    const out = [];
    if (schema.minLength !== undefined || schema.maxLength !== undefined) out.push(`${schema.minLength ?? 0} to ${schema.maxLength ?? "…"} characters`);
    if (schema.minimum !== undefined || schema.maximum !== undefined) out.push(`${schema.minimum ?? "…"} to ${schema.maximum ?? "…"}`);
    if (schema.maxItems !== undefined) out.push(`at most ${schema.maxItems} items`);
    return out.join(", ");
  }

  function fieldOf(name, schema, required) {
    const resolved = schema.$ref ? resolveRef(schema.$ref) : schema;
    const item = schema.type === "array" && schema.items?.$ref ? schema.items : undefined;
    const field = {name, type: typeText(schema), required};
    if (schema.description) field.description = String(schema.description).trim();
    const bounds = limits(resolved ?? schema);
    if (bounds) field.limits = bounds;
    if (schema.$ref) field.ref = refName(schema.$ref);
    else if (item) field.ref = refName(item.$ref);
    return field;
  }

  function schemaOf(name) {
    const raw = doc.components.schemas[name];
    const out = {name, type: typeText({...raw, $ref: undefined})};
    if (raw.description) out.description = String(raw.description).trim();
    if (raw.enum) out.enum = raw.enum;
    if (raw.properties) {
      const required = new Set(raw.required ?? []);
      out.fields = Object.entries(raw.properties).map(([field, schema]) => fieldOf(field, schema, required.has(field)));
    } else if (raw.type === "array") {
      out.items = typeText(raw.items);
      if (raw.items?.$ref) out.ref = refName(raw.items.$ref);
    }
    return out;
  }

  /** The body of a request or response: a named schema, or an inline object turned into fields. */
  function bodyOf(content) {
    const json = content?.["application/json"];
    const media = json ?? (content ? Object.values(content)[0] : undefined);
    if (!media) return undefined;
    const mediaType = json ? "application/json" : Object.keys(content)[0];
    const schema = media.schema;
    if (!schema) return {mediaType};
    if (schema.$ref) {
      used.add(refName(schema.$ref));
      return {mediaType, ref: refName(schema.$ref)};
    }
    if (schema.properties) {
      const required = new Set(schema.required ?? []);
      return {mediaType, fields: Object.entries(schema.properties).map(([field, s]) => fieldOf(field, s, required.has(field)))};
    }
    return {mediaType, type: typeText(schema)};
  }

  function paramOf(parameter) {
    const resolved = parameter.$ref ? resolveRef(parameter.$ref) : parameter;
    const out = {name: resolved.name, in: resolved.in, required: Boolean(resolved.required), type: typeText(resolved.schema)};
    if (resolved.description) out.description = String(resolved.description).trim();
    const bounds = limits(resolved.schema ?? {});
    if (bounds) out.limits = bounds;
    return out;
  }

  const operations = [];
  for (const [path, item] of Object.entries(doc.paths)) {
    for (const method of METHODS) {
      const op = item[method];
      if (!op) continue;
      const parameters = [...(item.parameters ?? []), ...(op.parameters ?? [])].map(paramOf);
      const responses = Object.entries(op.responses ?? {}).map(([status, response]) => {
        // A shared response (the Problem of every operation) is named, not copied 65 times: the page explains it once.
        if (response.$ref) return {status, shared: response.$ref.split("/").pop()};
        const resolved = response.$ref ? resolveRef(response.$ref) : response;
        const out = {status, description: String(resolved.description ?? "").trim()};
        const body = bodyOf(resolved.content);
        if (body) out.body = body;
        return out;
      });
      const entry = {
        id: op.operationId,
        tag: op.tags?.[0] ?? "other",
        method: method.toUpperCase(),
        path,
        summary: String(op.summary ?? "").trim(),
        token: tokenOf(op, method, path),
        parameters,
        responses,
      };
      if (op.description) entry.description = String(op.description).trim();
      const body = bodyOf(op.requestBody?.content);
      if (body) entry.request = {...body, required: Boolean(op.requestBody?.required)};
      operations.push(entry);
    }
  }

  // Every schema an operation reaches, and the schemas those reach, in name order so the file is stable.
  const queue = [...used];
  while (queue.length > 0) {
    const name = queue.pop();
    if (schemas[name] || !doc.components.schemas[name]) continue;
    const before = new Set(used);
    schemas[name] = schemaOf(name);
    for (const added of used) if (!before.has(added)) queue.push(added);
  }

  return {
    title: doc.info.title,
    version: doc.info.version,
    description: String(doc.info.description ?? "").trim(),
    server: doc.servers?.[0]?.url ?? "/api/v1",
    tags: (doc.tags ?? []).map((tag) => ({name: tag.name, description: String(tag.description ?? "").trim()})),
    shared: Object.fromEntries(Object.entries(doc.components.responses ?? {}).map(([name, response]) => [name, String(response.description ?? "").trim()])),
    operations,
    schemas: Object.fromEntries(Object.entries(schemas).sort(([a], [b]) => (a < b ? -1 : 1))),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const input = arg("in", join(root, "api", "public-openapi.yaml"));
  const output = arg("out", join(root, "packages", "ui", "src", "docs", "publicApi.generated.json"));
  if (!existsSync(input)) throw new Error(`${input} does not exist: run "go run ./tools/genpublicapi" first`);
  const text = readFileSync(input, "utf8");
  const docs = buildDocs(loadYaml().load(text));
  writeFileSync(output, `${JSON.stringify(docs, null, 1)}\n`);
  writeFileSync(arg("spec-out", join(dirname(output), "publicApiSpec.generated.json")), `${JSON.stringify(specOf(text))}\n`);
  console.log(`${docs.operations.length} operations, ${Object.keys(docs.schemas).length} schemas -> ${output}`);
}
