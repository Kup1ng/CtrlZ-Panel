// The values each URL parameter of FE 9 may hold on the P2 and P3 screens. `useUrlDialog` keeps the closed union of the parameter
// NAMES; the value is a string that anybody can type into the address bar, so each parameter has one parser here, and a screen reads
// `parseProfileDialog(dialog.value)` and never switches on the raw string. A value no parser accepts is `null`, and the dialog stays shut
// (pass it to `UrlModal`'s `isOpen`), exactly as `helpPane=nonsense` does.
//
// A value that carries an id is `<name>:<uuid>`. The id is checked as a UUID, so a path or a script can never ride in a dialog value
// (Plan.md, the P2 note about escaped names), and the parsers return the parts, not the string.
//
// None of these may hold a secret (FE 9, `ctrlz/no-secret-param`): the lock password dialogs, the token value, the share URL and the
// proof code are state-only and are not in this file.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function withId(value: string | null | undefined, name: string): string | null | undefined {
  if (!value) return undefined;
  const [head, id, ...rest] = value.split(":");
  if (head !== name || rest.length > 0) return undefined;
  if (id === undefined) return null; // the name alone
  return UUID.test(id) ? id : undefined;
}

/** `profileDialog` (P2 9.2, 9.5, 9.7). `default-rule` is the Default Rule's destination step. */
export const PROFILE_DIALOGS = ["add", "import", "duplicate", "delete", "default-rule"] as const;
export type ProfileDialog = (typeof PROFILE_DIALOGS)[number];
export const parseProfileDialog = (value: string | null | undefined): ProfileDialog | null =>
  (PROFILE_DIALOGS as readonly string[]).includes(value ?? "") ? (value as ProfileDialog) : null;

/** `serviceDialog` (P2 9.4, 9.5): Choose Service, or the destination of one service in the profile. */
export type ServiceDialog = {kind: "choose"} | {kind: "destination"; slug: string};
export function parseServiceDialog(value: string | null | undefined): ServiceDialog | null {
  if (value === "choose") return {kind: "choose"};
  const m = /^destination:(.+)$/.exec(value ?? "");
  return m && SLUG.test(m[1]!) && m[1]!.length <= 64 ? {kind: "destination", slug: m[1]!} : null;
}
export const serviceDialogValue = (d: ServiceDialog): string => (d.kind === "choose" ? "choose" : `destination:${d.slug}`);

/** `ruleDialog` (P2 9.6): the rule dialog (new, or one rule by id), the folder dialog (new, or one folder), and Upload Folder. */
export type RuleDialog =
  | {kind: "rule"; ruleId: string | null}
  | {kind: "folder"; folderId: string | null}
  | {kind: "upload"};
export function parseRuleDialog(value: string | null | undefined): RuleDialog | null {
  if (value === "upload") return {kind: "upload"};
  const rule = withId(value, "add-edit-rule");
  if (rule !== undefined) return {kind: "rule", ruleId: rule};
  const folder = withId(value, "folder");
  if (folder !== undefined) return {kind: "folder", folderId: folder};
  return null;
}
export const ruleDialogValue = (d: RuleDialog): string =>
  d.kind === "upload" ? "upload" : d.kind === "rule" ? (d.ruleId ? `add-edit-rule:${d.ruleId}` : "add-edit-rule") : d.folderId ? `folder:${d.folderId}` : "folder";

/**
 * `deviceDialog` (P3 10): the Endpoint dialogs, with the Endpoint in `deviceId`. `client` is the Custom Client dialog of an Endpoint's
 * Clients page. `add` needs no `deviceId`; the others do.
 */
export const DEVICE_DIALOGS = ["add", "edit", "delete", "resolvers", "configure", "client"] as const;
export type DeviceDialog = (typeof DEVICE_DIALOGS)[number];
export const parseDeviceDialog = (value: string | null | undefined): DeviceDialog | null =>
  (DEVICE_DIALOGS as readonly string[]).includes(value ?? "") ? (value as DeviceDialog) : null;
export const needsDeviceId = (dialog: DeviceDialog): boolean => dialog !== "add";

/** `deviceId`: an Endpoint id, or nothing. */
export const parseDeviceId = (value: string | null | undefined): string | null => (value && UUID.test(value) ? value : null);

/** `endpointGroupDialog`: create a group, or rename or delete one by id. */
export type EndpointGroupDialog = {kind: "create"} | {kind: "rename"; groupId: string} | {kind: "delete"; groupId: string};
export function parseEndpointGroupDialog(value: string | null | undefined): EndpointGroupDialog | null {
  if (value === "create") return {kind: "create"};
  for (const kind of ["rename", "delete"] as const) {
    const id = withId(value, kind);
    if (id) return {kind, groupId: id};
  }
  return null;
}

/** `ipDialog` (P3 10): add an authorized address, start a claim, or prove one (the claim in the value). */
export type IpDialog = {kind: "add"} | {kind: "claim"} | {kind: "proof"; claimId: string};
export function parseIpDialog(value: string | null | undefined): IpDialog | null {
  if (value === "add") return {kind: "add"};
  if (value === "claim") return {kind: "claim"};
  const proof = withId(value, "proof");
  return proof ? {kind: "proof", claimId: proof} : null;
}

/** `setupOs` (the wizard's platform) and `step` (its step number, 1 to 99). A value outside both is `null`. */
export const parseSetupOs = (value: string | null | undefined): string | null => (value && /^[a-z0-9][a-z0-9-]{0,31}$/.test(value) ? value : null);
export const parseStep = (value: string | null | undefined): number | null => {
  if (!value || !/^[1-9][0-9]?$/.test(value)) return null;
  return Number(value);
};

/** `helpPane` of the P2 and P3 screens, besides the P1 keys of `shell/SectionHelp.tsx`: a filter's or a service's explanation. */
export type HelpTopic = {kind: "filter"; id: string} | {kind: "service"; slug: string} | {kind: "option"; name: string};
export function parseHelpTopic(value: string | null | undefined): HelpTopic | null {
  const m = /^(filter|service|option)\.([a-z0-9][a-z0-9_-]{0,63})$/.exec(value ?? "");
  if (!m) return null;
  return m[1] === "filter" ? {kind: "filter", id: m[2]!} : m[1] === "service" ? {kind: "service", slug: m[2]!} : {kind: "option", name: m[2]!};
}
