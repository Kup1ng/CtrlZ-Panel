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
  // Unoptimised images avoid `sharp` and a writable image cache at run time.
  images: {unoptimized: true},
};

export default withNextIntl(config);
