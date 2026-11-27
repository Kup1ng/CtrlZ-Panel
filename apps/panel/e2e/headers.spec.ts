import {resolve} from "node:path";

import {declareHeadersSpec} from "@ctrlz/ui/proxy/headersSpec.ts";

// Spec 17.3 headers.spec.ts. The cases are shared with the other app.
declareHeadersSpec({app: "panel", appDir: resolve(__dirname, "..")});
