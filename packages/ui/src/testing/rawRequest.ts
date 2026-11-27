import {request as httpRequest} from "node:http";
import {request as httpsRequest} from "node:https";

// A request (GET unless a method is given) whose request line is exactly the text given, so an absolute-form target such as `http://evil.example/x` is sent as written too (gate-r19-2). Playwright's request context (and `new URL`) normalise a path: a backslash
// becomes a slash, so `/\evil.example` is sent as `//evil.example` and a test of the first spelling would test the second twice
// (gate-r3-3). Node's own client writes the path as it is. Used only by header specs that need an odd request line.
export type RawResponse = {
  status: number;
  /** Every header line, in order, so a doubled header is two entries. */
  headersArray(): {name: string; value: string}[];
  body: string;
};

/** An array value is sent as one header line per entry, which Playwright's request context cannot do (merge-r1-4). `timeoutMs` ends a request that gets no answer at all (an Upgrade request that Next never answers, gate-r25-5) with a rejection instead of a hang. */
/** `body` is sent whole with a Content-Length, or, as an array, one chunk at a time with no length (chunked), for the cases of the body limit (merge-r2-4). */
export function rawGet(
  origin: string,
  rawPath: string,
  headers: Record<string, string | string[]> = {},
  method = "GET",
  timeoutMs?: number,
  body?: Buffer | Buffer[],
): Promise<RawResponse> {
  const url = new URL(origin);
  const send = url.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const req = send(
      {
        host: url.hostname,
        port: url.port || undefined,
        path: rawPath,
        method,
        headers,
        // The Caddy run uses a local CA, as the Playwright config does with ignoreHTTPSErrors. Only ever a local host.
        rejectUnauthorized: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const lines: {name: string; value: string}[] = [];
          for (let i = 0; i < res.rawHeaders.length; i += 2) lines.push({name: res.rawHeaders[i]!, value: res.rawHeaders[i + 1]!});
          resolve({status: res.statusCode ?? 0, headersArray: () => lines, body: Buffer.concat(chunks).toString("utf8")});
        });
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    if (timeoutMs) req.setTimeout(timeoutMs, () => req.destroy(new Error(`no answer within ${timeoutMs} ms`)));
    if (Array.isArray(body)) {
      for (const chunk of body) req.write(chunk);
      req.end();
    } else req.end(body);
  });
}

/**
 * A POST that announces `announced` bytes, sends `sent` of them and then waits (merge-r3-5): how the edge ends a body that is never finished.
 * Resolves with how it ended ("answered <status>", "reset" or "open" when nothing happened within `limitMs`), the status and the header lines
 * of an answer (merge-r4-6: the status is part of what the edge promises), and never rejects.
 */
export function rawStalledPost(
  origin: string,
  rawPath: string,
  headers: Record<string, string>,
  announced: number,
  sent: number,
  limitMs: number,
): Promise<{outcome: string; ms: number; status?: number; body: string; headersArray(): {name: string; value: string}[]}> {
  const url = new URL(origin);
  const send = url.protocol === "https:" ? httpsRequest : httpRequest;
  const started = Date.now();
  return new Promise((resolve) => {
    let answered: {status: number; lines: {name: string; value: string}[]} | undefined;
    let body = "";
    const done = (outcome: string) => resolve({outcome, ms: Date.now() - started, status: answered?.status, body, headersArray: () => answered?.lines ?? []});
    const req = send(
      {host: url.hostname, port: url.port || undefined, path: rawPath, method: "POST", rejectUnauthorized: false, headers: {...headers, "content-length": String(announced)}},
      (res) => {
        const lines: {name: string; value: string}[] = [];
        for (let i = 0; i < res.rawHeaders.length; i += 2) lines.push({name: res.rawHeaders[i]!, value: res.rawHeaders[i + 1]!});
        answered = {status: res.statusCode ?? 0, lines};
        res.on("data", (chunk: Buffer) => {
          body += chunk.toString("utf8");
        });
        res.on("end", () => done(`answered ${res.statusCode}`));
        res.on("error", () => done("reset"));
      },
    );
    req.on("error", () => done("reset"));
    req.write(Buffer.alloc(sent, 97));
    setTimeout(() => {
      req.destroy();
      done("open");
    }, limitMs).unref();
  });
}
