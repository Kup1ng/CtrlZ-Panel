import {readdirSync, readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

// Docker is not available while the frontend is built (the auth review's CI owns it), so these
// files cannot be started or even run through `docker compose config`. What can be checked without
// it is the one property that would hurt the other workflow: a name or a handle that makes the e2e
// stack collide with the project `ctrlz` (spec 17.1, 17.7).

const dir = fileURLToPath(new URL("../../../deploy/compose/", import.meta.url));
const e2eFiles = readdirSync(dir).filter((f) => /^e2e.*\.yml$/.test(f));
const read = (f: string) => readFileSync(`${dir}${f}`, "utf8");

describe("deploy/compose/e2e*.yml", () => {
  it("has the three files of the spec: the web tier, the stack and the offline run", () => {
    expect(e2eFiles.sort()).toEqual(["e2e-offline.yml", "e2e-stack.yml", "e2e.yml"]);
  });

  it.each(e2eFiles)("%s names its own project, never the one the auth review's CI uses", (file) => {
    const names = [...read(file).matchAll(/^name:\s*(\S+)\s*$/gm)].map((m) => m[1]);
    expect(names).toEqual(["ctrlz-e2e"]);
  });

  it.each(e2eFiles)("%s attaches to nothing outside its own project", (file) => {
    const text = read(file).replace(/^\s*#.*$/gm, "");
    expect(text, "container_name would be shared across projects").not.toMatch(/container_name:/);
    expect(text, "an external network or volume is the main stack's").not.toMatch(/external:\s*true/);
    expect(text).not.toMatch(/network_mode:\s*host/);
    expect(text, "a named volume of the main project").not.toMatch(/(pgdata|chdata|valkey_data|caddy_data)/);
  });

  it("the base file is still the project `ctrlz`, so the override really changes the name", () => {
    expect(read("docker-compose.yml")).toMatch(/^name:\s*ctrlz\s*$/m);
  });

  it("e2e-stack.yml is the only file that sets CTRLZ_ENV, and sets test", () => {
    for (const file of e2eFiles) {
      const sets = [...read(file).matchAll(/^\s*CTRLZ_ENV:\s*(\S+)\s*$/gm)].map((m) => m[1]);
      if (file === "e2e-stack.yml") expect(sets).toEqual(["test", "test", "test"]);
      else expect(sets, file).toEqual([]);
    }
  });

  it("the web images are never pulled", () => {
    const text = read("e2e.yml");
    expect([...text.matchAll(/pull_policy:\s*(\S+)/g)].map((m) => m[1])).toEqual(["never", "never"]);
  });

  it("the e2e output directory is ignored by git (spec 17.7)", () => {
    const ignore = readFileSync(fileURLToPath(new URL("../../../.gitignore", import.meta.url)), "utf8");
    expect(ignore).toMatch(/^deploy\/compose\/e2e-out\/$/m);
  });
});
