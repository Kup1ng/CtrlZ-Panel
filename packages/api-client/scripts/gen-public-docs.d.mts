import type {PublicApi} from "../../ui/src/docs/apiDocsModel.ts";

export function buildDocs(doc: unknown): PublicApi;
export function loadYaml(): {load(text: string): unknown};
export function specOf(yamlText: string): {file: string; yaml: string};
