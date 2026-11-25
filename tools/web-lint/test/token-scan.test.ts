import {Readable} from "node:stream";
import {randomBytes} from "node:crypto";
import {gzipSync} from "node:zlib";

import {describe, expect, it} from "vitest";

import {createEntryScanner, createScanner, tarContains} from "../../../scripts/ci-web-token-scan.mjs";

// A tar writer with just enough in it: ustar headers, no checksums (the scanner does not read them).
function tarEntry(name: string, data: Buffer): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, "ascii");
  header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124, "ascii");
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([header, data, pad]);
}
const end = Buffer.alloc(1024);
const tar = (...entries: Buffer[]) => Buffer.concat([...entries, end]);
const stream = (b: Buffer, size = 700) => Readable.from(Array.from({length: Math.ceil(b.length / size)}, (_, i) => b.subarray(i * size, (i + 1) * size)));

const TOKEN = Buffer.from("tok_0123456789abcdef");

describe("createScanner", () => {
  it("finds a needle that straddles two chunks", () => {
    const s = createScanner(Buffer.from("secret"));
    s.push(Buffer.from("xxsec"));
    expect(s.found).toBe(false);
    s.push(Buffer.from("retxx"));
    expect(s.found).toBe(true);
  });
  it("never finds an empty needle, which would match everything", () => {
    const s = createScanner(Buffer.alloc(0));
    s.push(Buffer.from("anything"));
    expect(s.found).toBe(false);
  });
});

describe("createEntryScanner (wp12-r1-7)", () => {
  it("keeps the raw bytes and the decompressed bytes apart, so one cannot be the other's neighbour", () => {
    const s = createEntryScanner(Buffer.from("secret"));
    s.pushDecoded(Buffer.from("xxsec"));
    s.pushRaw(Buffer.from("raw bytes between two decompressed chunks"));
    s.pushDecoded(Buffer.from("retxx"));
    expect(s.found).toBe(true);
  });
  it("does not make a token out of the end of one stream and the start of the other", () => {
    const s = createEntryScanner(Buffer.from("secret"));
    s.pushRaw(Buffer.from("xxsec"));
    s.pushDecoded(Buffer.from("retxx"));
    expect(s.found).toBe(false);
  });
});

describe("tarContains (spec 3.3 token check)", () => {
  it("says not found for a tree without the token", async () => {
    const archive = tar(tarEntry("a.json", Buffer.from("{}")), tarEntry("b/layer.tar", Buffer.alloc(3000, 7)));
    expect(await tarContains(stream(archive), TOKEN)).toBe(false);
  });
  it("finds the token in a plain entry, in a later entry, and across the stream's chunk edges", async () => {
    const hidden = Buffer.concat([Buffer.alloc(1000, 1), TOKEN, Buffer.alloc(1000, 2)]);
    const archive = tar(tarEntry("a.json", Buffer.from("{}")), tarEntry("layer.tar", hidden));
    for (const size of [64, 511, 512, 700, 100_000]) expect(await tarContains(stream(archive, size), TOKEN), `chunk ${size}`).toBe(true);
  });
  it("finds the token inside a gzipped layer", async () => {
    const layer = gzipSync(tar(tarEntry("root/.npmrc", Buffer.from(`//registry/:_authToken=${TOKEN.toString()}\n`))));
    const archive = tar(tarEntry("blobs/sha256/abc", layer));
    expect(await tarContains(stream(archive), TOKEN)).toBe(true);
    const clean = tar(tarEntry("blobs/sha256/abc", gzipSync(tar(tarEntry("x", Buffer.from("nothing here"))))));
    expect(await tarContains(stream(clean), TOKEN)).toBe(false);
  });
  // wp12-r1-7. One rolling tail per byte stream: the raw bytes of the layer and its gunzipped bytes are
  // two streams, and a tail shared between them hands a decompressed chunk raw bytes as its neighbour.
  it("finds a token that straddles an edge of the decompressed chunks of a layer over 1 MiB", async () => {
    // Filler of 16 symbols deflates to about half its size, so 3 MB gives a layer over the 1 MiB read
    // chunk (raw pushes and decompressed chunks interleave) in which the token is Huffman coded and
    // appears in no raw byte. zlib emits 16 KiB chunks: the token sits across an edge of them.
    const filler = (n: number) => Buffer.from(randomBytes(n).map((b) => b % 16));
    for (const offset of [16_384 - 7, 16_384 - 1, 5 * 16_384 - 10, 600_000]) {
      const layer = gzipSync(Buffer.concat([filler(offset), TOKEN, filler(3_000_000)]));
      expect(layer.length).toBeGreaterThan(1 << 20);
      expect(layer.includes(TOKEN), "the token must exist only in the decompressed bytes").toBe(false);
      const archive = tar(tarEntry("blobs/sha256/big", layer));
      expect(await tarContains(stream(archive, 65_536), TOKEN), `offset ${offset}`).toBe(true);
    }
    const clean = tar(tarEntry("blobs/sha256/big", gzipSync(filler(3_000_000))));
    expect(await tarContains(stream(clean, 65_536), TOKEN)).toBe(false);
  });
  it("cannot decide on a layer that starts as gzip and is not, instead of calling it clean", async () => {
    const broken = Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08, 0x00]), randomBytes(2000)]);
    await expect(tarContains(stream(tar(tarEntry("blobs/sha256/bad", broken))), TOKEN)).rejects.toThrow();
  });
  it("refuses input that is not a tar archive instead of calling it clean", async () => {
    const junk = Buffer.alloc(1024, 0x41);
    await expect(tarContains(stream(junk), TOKEN)).rejects.toThrow();
  });
});
