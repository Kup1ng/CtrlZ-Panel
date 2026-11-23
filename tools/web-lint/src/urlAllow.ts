import {readFileSync} from "node:fs";

/** The file paths of tools/web-lint/url-allow.txt: one per line, comments after `#`. */
export function readUrlAllow(path: string): string[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .map((line) => line.replace(/#.*/, "").trim())
    .filter(Boolean);
}
