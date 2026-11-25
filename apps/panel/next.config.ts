import path from "node:path";
import type {NextConfig} from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

const config: NextConfig = {
  // The workspace packages ship TypeScript source, so Next compiles them.
  transpilePackages: ["@ctrlz/ui", "@ctrlz/icons", "@ctrlz/i18n", "@ctrlz/api-client"],
  // Standalone output is what the image runs. In a monorepo it needs the
  // repository root, or the trace misses files outside the app folder.
  output: "standalone",
  outputFileTracingRoot: path.resolve(import.meta.dirname, "../.."),
  poweredByHeader: false,
  // Next holds up to this much of every non-GET body in memory for each open request (default 10 MB), and writes the request URI into its log
  // when a body passes it. No page takes a body of more than a few hundred bytes, and Caddy refuses a larger one before it gets here
  // (web_rules); this is the second line, for a deployment that runs the container without Caddy (merge-r2-4).
  experimental: {proxyClientMaxBodySize: "64kb"},
  // Unoptimised images avoid `sharp` and a writable image cache at run time.
  images: {unoptimized: true},
  // Next removes one trailing ".rsc" from the path before the proxy runs, but the App Router renders the raw path, so the proxy (and the
  // gate in it) judged a different string than the router rendered, and any unknown name written with ".rsc" got a soft 200 flight payload
  // from the catch-all (gate-r7-2). The proxy cannot see the raw path (request.url is already stripped), but redirects run first, on the
  // raw one. Neither app serves a ".rsc" file (the client router uses the rsc header and "?_rsc="), so the suffix is cut here and the
  // answer is then the plain path's own. A name with several suffixes loses one per hop.
  async redirects() {
    return [{source: "/:path(.+)\\.rsc", destination: "/:path", permanent: false}];
  },
};

export default withNextIntl(config);
