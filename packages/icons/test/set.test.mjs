import {execFileSync} from "node:child_process";
import {existsSync, readFileSync, readdirSync} from "node:fs";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {describe, expect, it} from "vitest";
import {METHOD, parseProvenance, validateIconSvg} from "../scripts/lib.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const svgs = (group) => readdirSync(join(root, "svg", group)).filter((f) => f.endsWith(".svg")).map((f) => f.slice(0, -4)).sort();

// Plan.md, Filters: the 20 native categories. The slugs are ours until the catalogue fixes them (P2).
const FILTERS = [
  "ads-trackers", "adult", "ai", "clickbait", "crypto", "dating", "drugs", "dynamic-dns", "file-hosting", "gambling",
  "games", "government", "iot-telemetry", "malware", "new-domains", "phishing", "social", "torrents", "url-shorteners", "vpn-dns",
];
// Plan.md, Services: the 12 categories.
const SERVICES = ["audio", "career", "finance", "gaming", "hosting", "news", "recreation", "shop", "social", "tools", "vendors", "video"];

describe("the set", () => {
  it("has all twenty native filters", () => {
    expect(svgs("filters")).toEqual([...FILTERS].sort());
  });

  it("has all twelve service categories", () => {
    expect(svgs("services")).toEqual([...SERVICES].sort());
  });

  it("has the rule icons the lab and the Rules page need", () => {
    expect(svgs("rules")).toEqual(
      ["action-block", "action-bypass", "action-redirect", "expiry", "folder", "folder-magic", "geo-destination", "geo-source"].sort(),
    );
  });

  it("passes the validator, file by file", () => {
    for (const group of ["filters", "services", "rules"]) {
      for (const name of svgs(group)) {
        const errors = validateIconSvg(readFileSync(join(root, "svg", group, `${name}.svg`), "utf8"));
        expect({file: `${group}/${name}`, errors}).toEqual({file: `${group}/${name}`, errors: []});
      }
    }
  });

  it("has a provenance row for every file and no row without a file (T-476)", () => {
    const rows = parseProvenance(readFileSync(join(root, "PROVENANCE.md"), "utf8"));
    const files = ["filters", "services", "rules"].flatMap((g) => svgs(g).map((n) => `svg/${g}/${n}.svg`));
    for (const f of files) expect(rows.get(f)?.method, f).toBe(METHOD.svg);
    expect([...rows.keys()].filter((k) => k.startsWith("svg/")).sort()).toEqual(files.sort());
    expect(rows.get("brand/Logo.svg")?.method).toBe(METHOD.brand);
  });

  it("keeps the generated files current", () => {
    // Throws with the build's own message when something is stale.
    execFileSync(process.execPath, [join(root, "scripts", "build.mjs"), "--check"], {stdio: "pipe"});
  });

  it("ships the brand files and an empty logo manifest (spec 7.4)", () => {
    expect(existsSync(join(root, "brand", "Logo.svg"))).toBe(true);
    expect(existsSync(join(root, "brand", "Logo.png"))).toBe(true);
    expect(JSON.parse(readFileSync(join(root, "logos", "manifest.json"), "utf8"))).toEqual([]);
  });

  it("holds no remote URL anywhere in the sources or generated files", () => {
    const scan = (dir) =>
      readdirSync(dir, {withFileTypes: true}).flatMap((e) => {
        const p = join(dir, e.name);
        if (e.isDirectory()) return e.name === "node_modules" ? [] : scan(p);
        return /\.(svg|tsx|ts)$/.test(e.name) ? [p] : [];
      });
    for (const f of [...scan(join(root, "svg")), ...scan(join(root, "src")), ...scan(join(root, "brand"))]) {
      const text = readFileSync(f, "utf8").replace('xmlns="http://www.w3.org/2000/svg"', "");
      expect(text, f).not.toMatch(/https?:\/\//);
    }
  });
});
