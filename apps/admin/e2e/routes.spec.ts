import {resolve} from "node:path";

import {declareRoutesSpec} from "@ctrlz/ui/testing/routesSpec.ts";

// Spec 17.3 routes.spec.ts (T-414, T-438). The cases are shared with the other app.
declareRoutesSpec({app: "admin", appDir: resolve(__dirname, "..")});
