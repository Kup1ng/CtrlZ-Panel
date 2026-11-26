import {existsSync, readFileSync} from "node:fs";
import path from "node:path";

import {describe, expect, it} from "vitest";

import data from "./publicApi.generated.json";
import specData from "./publicApiSpec.generated.json";
import {AUTH_FLAG, curlOf, groupsOf, isError, matches, proseOf, type Operation, type PublicApi} from "./apiDocsModel.ts";
import {buildDocs, loadYaml, specOf} from "../../../api-client/scripts/gen-public-docs.mjs";

const api = data as unknown as PublicApi;
const JOIN = " \\\n";
const REPO = path.resolve(import.meta.dirname, "../../../..");

describe("the generated public API document (spec p3 6.5, T-320)", () => {
  // The file is written by the Go generator and arrives with the foundation merge, so a branch of the web alone has none. Where the check is the gate (the Panel CI
  // sets CTRLZ_REQUIRE_PUBLIC_API=1) a missing file is a failure and not a pass, and elsewhere the case says it was skipped instead of passing without looking (S8-r1-5).
  it("is what the generator writes from api/public-openapi.yaml", (ctx) => {
    const yaml = path.join(REPO, "api", "public-openapi.yaml");
    if (!existsSync(yaml)) {
      if (process.env.CTRLZ_REQUIRE_PUBLIC_API) throw new Error("api/public-openapi.yaml is not in the tree, so the generated API reference cannot be checked for freshness");
      ctx.skip();
      return;
    }
    expect(buildDocs(loadYaml().load(readFileSync(yaml, "utf8")))).toEqual(JSON.parse(JSON.stringify(api)));
  });

  // S8-r2-2: the Download button gives the OpenAPI file itself, so it must be the YAML the generator read and not a text that drifted from it.
  it("carries the YAML of api/public-openapi.yaml for the download, byte for byte with Unix line endings", (ctx) => {
    const yaml = path.join(REPO, "api", "public-openapi.yaml");
    if (!existsSync(yaml)) {
      if (process.env.CTRLZ_REQUIRE_PUBLIC_API) throw new Error("api/public-openapi.yaml is not in the tree, so the downloadable file cannot be checked for freshness");
      ctx.skip();
      return;
    }
    expect(specData).toEqual(specOf(readFileSync(yaml, "utf8")));
  });

  it("is a real OpenAPI document that parses to the model's own operations", () => {
    const doc = loadYaml().load(specData.yaml) as {openapi: string; paths: Record<string, unknown>};
    expect(doc.openapi).toMatch(/^3\./);
    expect(buildDocs(doc).operations.length).toBe(api.operations.length);
    expect(specData.file).toBe("ctrlz-public-api.yaml");
    expect(specData.yaml).not.toContain("\r");
  });

  it("has only operations a token may call, each in a group the document names", () => {
    const tags = new Set(api.tags.map((tag) => tag.name));
    expect(api.operations.length).toBeGreaterThan(0);
    for (const op of api.operations) {
      expect(["read", "write"], op.id).toContain(op.token);
      expect(tags.has(op.tag), `${op.id}: ${op.tag}`).toBe(true);
      // The rule of the public API: a read token reaches reads only.
      if (op.token === "read") expect(op.method, op.id).toBe("GET");
    }
  });

  it("points every schema reference at a schema it holds, and every operation id once", () => {
    const missing: string[] = [];
    const ref = (name: string | undefined, where: string) => {
      if (name && !api.schemas[name]) missing.push(`${where} -> ${name}`);
    };
    for (const op of api.operations) {
      ref(op.request?.ref, op.id);
      for (const field of op.request?.fields ?? []) ref(field.ref, op.id);
      for (const response of op.responses) {
        ref(response.body?.ref, op.id);
        for (const field of response.body?.fields ?? []) ref(field.ref, op.id);
      }
    }
    for (const schema of Object.values(api.schemas)) {
      ref(schema.ref, schema.name);
      for (const field of schema.fields ?? []) ref(field.ref, schema.name);
    }
    expect(missing).toEqual([]);
    expect(new Set(api.operations.map((op) => op.id)).size).toBe(api.operations.length);
  });

  it("holds no external address: the page is read offline (rule 9)", () => {
    expect(JSON.stringify(data)).not.toMatch(new RegExp(`https?${":"}//`, "i"));
  });
});

describe("the generator", () => {
  const doc = (token: unknown) => ({
    info: {title: "t", version: "1"},
    paths: {"/x": {patch: {operationId: "patchX", tags: ["account"], responses: {}, ...(token === undefined ? {} : {"x-ctrlz-token": token})}}},
    components: {schemas: {}},
  });

  // S8-r1-8: the read/write column is the security-relevant one, so it never defaults.
  it("takes the token of an operation from its annotation and refuses a missing or unknown one", () => {
    expect(buildDocs(doc("write")).operations[0]?.token).toBe("write");
    expect(buildDocs(doc("read")).operations[0]?.token).toBe("read");
    expect(() => buildDocs(doc(undefined))).toThrow(/x-ctrlz-token/);
    expect(() => buildDocs(doc("admin"))).toThrow(/x-ctrlz-token/);
  });
});

describe("the model", () => {
  const op = (over: Partial<Operation>): Operation => ({id: "x", tag: "endpoints", method: "GET", path: "/x", summary: "", token: "read", parameters: [], responses: [], ...over});

  it("lists the groups in the order the document names them, each operation once", () => {
    const groups = groupsOf(api);
    expect(groups.map((group) => group.tag)).toEqual(api.tags.map((tag) => tag.name).filter((name) => api.operations.some((o) => o.tag === name)));
    expect(groups.flatMap((group) => group.operations).length).toBe(api.operations.length);
  });

  it("puts a tag the list does not name last", () => {
    const groups = groupsOf(api, [op({tag: "zzz"}), op({tag: "account"})]);
    expect(groups.map((g) => g.tag)).toEqual(["account", "zzz"]);
  });

  it("searches by every word, in the method, the path, the id, the summary and the group", () => {
    const create = op({id: "createEndpoint", method: "POST", path: "/endpoints", summary: "Create Endpoints"});
    expect(matches(create, "")).toBe(true);
    expect(matches(create, "post endpoints")).toBe(true);
    expect(matches(create, "createendpoint")).toBe(true);
    expect(matches(create, "delete")).toBe(false);
    expect(matches(create, "post profiles")).toBe(false);
  });

  it("writes an example with a placeholder token and the origin it was given, and never invents a body", () => {
    const text = curlOf(
      op({method: "PATCH", path: "/endpoints/{id}/clients/{cid}", request: {mediaType: "application/json", ref: "ClientPatch", required: true}}),
      "ORIGIN",
      "/api/v1",
    );
    expect(text).toBe(['curl -X PATCH "ORIGIN/api/v1/endpoints/ID/clients/CID"', AUTH_FLAG, '  -H "Content-Type: application/json"', "  -d @body.json"].join(JOIN));
    expect(curlOf(op({path: "/profiles"}), "ORIGIN", "/api/v1")).toBe(['curl "ORIGIN/api/v1/profiles"', AUTH_FLAG].join(JOIN));
  });

  // S8-r2-1: five operations of the reference need Idempotency-Key, and a copied example without it is refused by the server.
  it("carries every required header parameter in the example, and an optional one it leaves out", () => {
    const header = (name: string, required: boolean) => ({name, in: "header", required, type: "string"});
    const text = curlOf(op({method: "POST", path: "/endpoints", parameters: [header("Idempotency-Key", true), header("X-Trace", false), header("X-Tenant-Id", true)], request: {mediaType: "application/json", ref: "EndpointCreate", required: true}}), "ORIGIN", "/api/v1");
    expect(text).toBe(
      ['curl -X POST "ORIGIN/api/v1/endpoints"', AUTH_FLAG, '  -H "Idempotency-Key: $(uuidgen)"', '  -H "X-Tenant-Id: X_TENANT_ID"', '  -H "Content-Type: application/json"', "  -d @body.json"].join(JOIN),
    );
  });

  it("gives every operation of the generated reference the required headers it declares", () => {
    const withHeader = api.operations.filter((o) => o.parameters.some((p) => p.in === "header" && p.required));
    expect(withHeader.map((o) => o.id).length).toBeGreaterThanOrEqual(5);
    for (const o of withHeader) {
      const text = curlOf(o, "ORIGIN", api.server);
      for (const p of o.parameters.filter((x) => x.in === "header" && x.required)) expect(text, `${o.id}: ${p.name}`).toContain(`-H "${p.name}: `);
    }
    const key = api.operations.find((o) => o.method === "POST" && o.path === "/endpoints")!;
    expect(curlOf(key, "ORIGIN", api.server)).toContain('-H "Idempotency-Key: $(uuidgen)"');
  });

  it("splits a description into paragraphs and code spans, and reads no other markup", () => {
    expect(proseOf("A `read` token.\nSecond line.\n\n<b>x</b> [a](x)")).toEqual([
      [
        {kind: "text", text: "A "},
        {kind: "code", text: "read"},
        {kind: "text", text: " token. Second line."},
      ],
      [{kind: "text", text: "<b>x</b> [a](x)"}],
    ]);
  });

  it("calls default and every status from 400 an error", () => {
    expect([isError("200"), isError("204"), isError("404"), isError("default")]).toEqual([false, false, true, true]);
  });
});
