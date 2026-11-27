#!/usr/bin/env node
// The token check of spec 3.3, used by scripts/ci-web.sh when CTRLZ_WEB_STACK=1: reads the tar
// stream that `docker save` writes and looks for the value of an environment variable in it.
//
//   docker save ctrlz/web-deps:ci | node scripts/ci-web-token-scan.mjs HEROUI_AUTH_TOKEN
//
// The variable is named on the command line and read from the environment, so the value is never in
// a command line, a log or this file. Prints `found` or `not found` and nothing else (fixed rule 7).
// Exit 0 for not found, 1 for found, 2 when it cannot decide (no value to look for, bad input).
//
// What it reads: the outer tar entry by entry, and each entry's bytes as they are, or gunzipped when
// they start with the gzip magic, since a layer is a tar of files that sit in the stream unpacked.
// What it does not read: zstd layers, and a token that was compressed again inside a file. A token
// written by the CLI to a keyring file or a config file is plain text, which is the case that matters.
import {once} from "node:events";
import {createGunzip} from "node:zlib";
import {pathToFileURL} from "node:url";

const BLOCK = 512;

/** Looks for `needle` in a stream of chunks, across chunk edges. */
export function createScanner(needle) {
  let tail = Buffer.alloc(0);
  let found = false;
  return {
    push(chunk) {
      if (found || needle.length === 0) return;
      const window = Buffer.concat([tail, chunk]);
      if (window.includes(needle)) found = true;
      tail = window.subarray(Math.max(0, window.length - (needle.length - 1)));
    },
    get found() {
      return found;
    },
  };
}

/**
 * The scanner of one tar entry: one rolling tail per byte stream. The entry's raw bytes and its
 * gunzipped bytes are two streams that interleave in time, and a tail shared by both would give a
 * decompressed chunk raw bytes for a neighbour and miss a token across a chunk edge (wp12-r1-7).
 */
export function createEntryScanner(needle) {
  const raw = createScanner(needle);
  const decoded = createScanner(needle);
  return {
    pushRaw: (chunk) => raw.push(chunk),
    pushDecoded: (chunk) => decoded.push(chunk),
    get found() {
      return raw.found || decoded.found;
    },
  };
}

/** The bytes of an async iterable of Buffers, `n` at a time. */
class Reader {
  constructor(iterable) {
    this.it = iterable[Symbol.asyncIterator]();
    this.buf = Buffer.alloc(0);
    this.done = false;
  }
  async fill(n) {
    while (this.buf.length < n && !this.done) {
      const {value, done} = await this.it.next();
      if (done) this.done = true;
      else this.buf = Buffer.concat([this.buf, value]);
    }
  }
  /** Up to `n` bytes, fewer only at the end of the stream. */
  async take(n) {
    await this.fill(Math.min(n, 1 << 20));
    const out = this.buf.subarray(0, Math.min(n, this.buf.length));
    this.buf = this.buf.subarray(out.length);
    return out;
  }
}

async function scanEntry(reader, size, needle) {
  const scanner = createEntryScanner(needle);
  let left = size;
  let gunzip = null;
  let gunzipped = Promise.resolve();
  let first = true;
  while (left > 0) {
    const chunk = await reader.take(left);
    if (chunk.length === 0) throw new Error("the archive ends inside an entry");
    left -= chunk.length;
    if (first) {
      first = false;
      if (chunk.length >= 2 && chunk[0] === 0x1f && chunk[1] === 0x8b) {
        gunzip = createGunzip();
        gunzip.on("data", (c) => scanner.pushDecoded(c));
        // A layer that starts as gzip and cannot be read is a layer the scan cannot see into: that is
        // "cannot decide" (exit 2), never "not found".
        gunzipped = new Promise((res, rej) => {
          gunzip.on("end", res);
          gunzip.on("error", rej);
        });
        gunzipped.catch(() => {});
      }
    }
    scanner.pushRaw(chunk);
    // Backpressure: a layer of gigabytes must not pile up in zlib's queue.
    if (gunzip && !gunzip.write(chunk)) await Promise.race([once(gunzip, "drain"), gunzipped]);
  }
  if (gunzip) {
    gunzip.end();
    await gunzipped;
  }
  // Padding up to the next block.
  const pad = (BLOCK - (size % BLOCK)) % BLOCK;
  if (pad) await reader.take(pad);
  return scanner.found;
}

/** True when `needle` is in any entry of the tar stream. */
export async function tarContains(stream, needle) {
  const reader = new Reader(stream);
  let found = false;
  for (;;) {
    const header = await reader.take(BLOCK);
    if (header.length < BLOCK || header.every((b) => b === 0)) break;
    const size = parseInt(header.subarray(124, 136).toString("ascii").replace(/\0.*$/, "").trim() || "0", 8);
    if (Number.isNaN(size)) throw new Error("the stream is not a tar archive");
    if (await scanEntry(reader, size, needle)) found = true;
  }
  return found;
}

async function main() {
  const name = process.argv[2];
  const value = name ? process.env[name] : undefined;
  if (!name || !value || value.length < 8) {
    console.error(`ci-web-token-scan: ${name ?? "<name>"} is not set to a value of at least 8 characters, so there is nothing to look for`);
    process.exit(2);
  }
  try {
    const found = await tarContains(process.stdin, Buffer.from(value));
    console.log(found ? "found" : "not found");
    process.exit(found ? 1 : 0);
  } catch (e) {
    console.error(`ci-web-token-scan: ${e instanceof Error ? e.message : "failed"}`);
    process.exit(2);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
