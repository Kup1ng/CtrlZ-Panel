import {createServer, type Server} from "node:http";
import type {AddressInfo} from "node:net";

import {afterEach, describe, expect, it} from "vitest";

import {rawGet} from "./rawRequest.ts";

let server: Server | undefined;
afterEach(() => new Promise<void>((done) => (server ? server.close(() => done()) : done())));

async function listen(onRequest: (url: string) => void): Promise<string> {
  server = createServer((req, res) => {
    onRequest(req.url ?? "");
    res.setHeader("set-cookie", ["a=1", "b=2"]);
    res.end("hi");
  });
  // Port 0 on the loopback address: the OS picks a free one, so it cannot meet another run's fixed port.
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("rawGet (gate-r3-3)", () => {
  it("sends a backslash as a backslash, which a URL object turns into a slash", async () => {
    const seen: string[] = [];
    const origin = await listen((url) => seen.push(url));
    const raw = `/${String.fromCharCode(92)}evil.example`;
    await rawGet(origin, raw);
    expect(seen).toEqual([raw]);
    // The reason this helper exists: the same text through the URL parser is another path.
    expect(new URL(`https://panel.localhost${raw}`).pathname).toBe("//evil.example");
  });
  it("sends an absolute-form target and a method as written (gate-r19-2)", async () => {
    const seen: string[] = [];
    let method = "";
    server = createServer((req, res) => {
      seen.push(req.url ?? "");
      method = req.method ?? "";
      res.end("ok");
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    await rawGet(origin, "http://evil.example/fa/profiles", {}, "OPTIONS");
    expect(seen).toEqual(["http://evil.example/fa/profiles"]);
    expect(method).toBe("OPTIONS");
  });
  it("keeps a doubled header as two entries, so a test can see a list that browsers would ignore", async () => {
    const origin = await listen(() => {});
    const r = await rawGet(origin, "/x");
    expect(r.status).toBe(200);
    expect(r.headersArray().filter((h) => h.name.toLowerCase() === "set-cookie").map((h) => h.value)).toEqual(["a=1", "b=2"]);
    expect(r.body).toBe("hi");
  });

  // gate-r25-5: an Upgrade request that Next never answers must be a rejection the case can read, not a hang until the test's own timeout.
  it("rejects a request that gets no answer within the time given", async () => {
    server = createServer(() => {
      // never answers
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    await expect(rawGet(origin, "/x", {}, "GET", 150)).rejects.toThrow(/no answer within 150 ms/);
  });
});
