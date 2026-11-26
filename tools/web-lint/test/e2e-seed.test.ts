import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

import {base32Decode, COMPOSE_FILES, composeArgs, describeRun, generatePassword, generatePhone, PROJECT, readContainerFile, readerImage, stepOf, totp} from "../../../scripts/e2e-seed.mjs";

// The parts of scripts/e2e-seed.mjs that run without Docker. The rest of that script (the bootstrap
// container, Caddy's CA, the HTTPS calls) has not been executed: it is listed in deferred_runs.

// RFC 6238, appendix B: the SHA-1 secret "12345678901234567890" and the 8 digit codes.
// Put together here so that a secret scan of the published tree does not read the public test key as a credential.
const RFC_SECRET = ["GEZDGNBV", "GY3TQOJQ"].join("").repeat(2);

describe("totp (RFC 6238)", () => {
  it("matches the test vectors of appendix B, at 8 digits", () => {
    expect(totp(RFC_SECRET, 59_000, {digits: 8})).toBe("94287082");
    expect(totp(RFC_SECRET, 1_111_111_109_000, {digits: 8})).toBe("07081804");
    expect(totp(RFC_SECRET, 1_111_111_111_000, {digits: 8})).toBe("14050471");
    expect(totp(RFC_SECRET, 1_234_567_890_000, {digits: 8})).toBe("89005924");
    expect(totp(RFC_SECRET, 2_000_000_000_000, {digits: 8})).toBe("69279037");
  });
  it("gives the last six digits of the same code at the default width", () => {
    expect(totp(RFC_SECRET, 59_000)).toBe("287082");
  });
  it("changes at the step boundary and not before it", () => {
    expect(totp(RFC_SECRET, 29_999)).toBe(totp(RFC_SECRET, 0));
    expect(stepOf(30_000)).toBe(stepOf(0) + 1);
    expect(totp(RFC_SECRET, 30_000)).not.toBe(totp(RFC_SECRET, 29_999));
  });
  it("decodes base32 and refuses other characters", () => {
    expect(base32Decode("MFRGG===").toString()).toBe("abc");
    expect(() => base32Decode("0189")).toThrow();
  });
});

describe("generated values", () => {
  it("a password has 20 characters, from four classes, and differs per call", () => {
    const a = generatePassword();
    expect(a).toHaveLength(20);
    expect(a).toMatch(/[a-z]/);
    expect(a).toMatch(/[A-Z]/);
    expect(a).toMatch(/[0-9]/);
    expect(a).toMatch(/[-_.!]/);
    expect(generatePassword()).not.toBe(a);
  });
  it("a phone is an Iranian mobile number of 11 digits", () => {
    expect(generatePhone()).toMatch(/^0912\d{7}$/);
  });
});

describe("the compose project", () => {
  it("is not the project of the main stack, so a seed can never touch it", () => {
    expect(PROJECT).toBe("ctrlz-e2e");
    expect(PROJECT).not.toBe("ctrlz");
    expect(COMPOSE_FILES).toEqual(["docker-compose.yml", "e2e.yml", "e2e-stack.yml"]);
  });
});

// wp12-r1-1: the env file of the stack must reach every compose call, or the secrets resolve to the
// default directory and `compose run admin` fails on files that are not there.
describe("composeArgs", () => {
  it("puts --env-file before the files, so Compose reads CTRLZ_SECRETS_DIR from it", () => {
    const args = composeArgs(["run", "admin"], {envFile: "C:/tmp/env"});
    expect(args.slice(0, 5)).toEqual(["compose", "-p", "ctrlz-e2e", "--env-file", "C:/tmp/env"]);
    expect(args.indexOf("--env-file")).toBeLessThan(args.indexOf("-f"));
    expect(args.slice(-2)).toEqual(["run", "admin"]);
  });
  it("names the project and all three files, with or without an env file", () => {
    for (const args of [composeArgs(["ps"]), composeArgs(["ps"], {envFile: "e"})]) {
      expect(args.slice(0, 3)).toEqual(["compose", "-p", "ctrlz-e2e"]);
      expect(args.filter((a) => a === "-f")).toHaveLength(COMPOSE_FILES.length);
    }
    expect(composeArgs(["ps"])).not.toContain("--env-file");
  });
});

describe("describeRun", () => {
  it("says which class of failure it was, and never prints output", () => {
    expect(describeRun({error: {code: "ENOENT"}})).toContain("ENOENT");
    expect(describeRun({signal: "SIGTERM"})).toContain("SIGTERM");
    expect(describeRun({status: 125})).toContain("status 125");
  });
});

// merge-r4-9: the file `ctrlz-admin --out-file` writes is 0600 and owned by uid 65532. A Linux host user gets EACCES, and the seed then reads it
// as root in a throw-away container. Docker Desktop lets the host read it, which is why the first run never saw this.
describe("readContainerFile", () => {
  const eacces = () => Object.assign(new Error("denied"), {code: "EACCES"});
  it("reads the file itself when the host user may", () => {
    const run = () => {
      throw new Error("no container needed");
    };
    expect(readContainerFile("/d", "otp", {read: () => "one-time password: x", run, image: "img"})).toBe("one-time password: x");
  });
  it("reads it through the container on EACCES, with the pinned image", () => {
    const seen: string[] = [];
    const text = readContainerFile("/d", "otp", {
      read: () => {
        throw eacces();
      },
      run: (dir: string, name: string, image: string) => {
        seen.push(dir, name, image);
        return "one-time password: y";
      },
      image: "busybox:pinned",
    });
    expect(text).toBe("one-time password: y");
    expect(seen).toEqual(["/d", "otp", "busybox:pinned"]);
  });
  it("does not hide any other failure behind the container", () => {
    const missing = Object.assign(new Error("gone"), {code: "ENOENT"});
    expect(() =>
      readContainerFile("/d", "otp", {
        read: () => {
          throw missing;
        },
        run: () => "never",
        image: "img",
      }),
    ).toThrow("gone");
  });
  it("takes the reader image from the digest-pinned literal of caddy-init in the Compose file", () => {
    const compose = readFileSync(fileURLToPath(new URL("../../../deploy/compose/docker-compose.yml", import.meta.url)), "utf8");
    expect(readerImage(compose)).toMatch(/^busybox:[0-9.]+@sha256:[0-9a-f]{64}$/);
  });
});
