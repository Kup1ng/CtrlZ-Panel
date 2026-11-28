// Lets `tsc` check message keys. The shape is taken from the Persian files, and
// a test keeps the English files on the same keys.
import type account from "../messages/fa/account.json";
import type admin from "../messages/fa/admin.json";
import type auth from "../messages/fa/auth.json";
import type common from "../messages/fa/common.json";
import type errors from "../messages/fa/errors.json";
import type feedback from "../messages/fa/feedback.json";
import type lab from "../messages/fa/lab.json";
import type nodes from "../messages/fa/nodes.json";
import type shell from "../messages/fa/shell.json";
import type api from "../messages/fa/api.json";
import type endpoints from "../messages/fa/endpoints.json";
import type jobs from "../messages/fa/jobs.json";
import type profiles from "../messages/fa/profiles.json";
import type rules from "../messages/fa/rules.json";
import type services from "../messages/fa/services.json";
import type setup from "../messages/fa/setup.json";
import type {Locale} from "./locale.ts";
import type {PendingNamespace} from "./namespaces.ts";

declare module "next-intl" {
  interface AppConfig {
    Locale: Locale;
    Messages: {
      // The owner of a namespace adds its line here when its file lands, and
      // removes it from PENDING_NAMESPACES in namespaces.ts.
      account: typeof account;
      admin: typeof admin;
      auth: typeof auth;
      common: typeof common;
      errors: typeof errors;
      feedback: typeof feedback;
      shell: typeof shell;
      lab: typeof lab;
      api: typeof api;
      endpoints: typeof endpoints;
      jobs: typeof jobs;
      nodes: typeof nodes;
      profiles: typeof profiles;
      rules: typeof rules;
      services: typeof services;
      setup: typeof setup;
    } & {
      // Namespaces whose file is not written yet are not checked.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      [K in PendingNamespace]: any;
    };
  }
}
