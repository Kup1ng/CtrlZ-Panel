import {describe, expect, it} from "vitest";

import {
  needsDeviceId,
  parseDeviceDialog,
  parseDeviceId,
  parseEndpointGroupDialog,
  parseHelpTopic,
  parseIpDialog,
  parseProfileDialog,
  parseRuleDialog,
  parseServiceDialog,
  parseSetupOs,
  parseStep,
  ruleDialogValue,
  serviceDialogValue,
} from "./dialogValues.ts";

const ID = "6f1c1b0e-8f35-4d57-9b8f-1d1c2a3b4c5d";

describe("dialog values", () => {
  it("accepts the profile dialogs of spec p2 9.2 and nothing else", () => {
    for (const v of ["add", "import", "duplicate", "delete", "default-rule"]) expect(parseProfileDialog(v), v).toBe(v);
    for (const v of ["", null, undefined, "ADD", "add ", "constructor", "__proto__", "lock", "unlock"]) expect(parseProfileDialog(v), String(v)).toBeNull();
  });

  it("keeps the lock dialogs out of every union: they are state-only (FE 9)", () => {
    expect(parseProfileDialog("lock")).toBeNull();
    expect(parseProfileDialog("unlock")).toBeNull();
    expect(parseDeviceDialog("lock")).toBeNull();
  });

  it("reads Choose Service and the destination of one service, round trip", () => {
    expect(parseServiceDialog("choose")).toEqual({kind: "choose"});
    expect(parseServiceDialog("destination:telegram")).toEqual({kind: "destination", slug: "telegram"});
    expect(serviceDialogValue({kind: "destination", slug: "x-y"})).toBe("destination:x-y");
    expect(parseServiceDialog(serviceDialogValue({kind: "choose"}))).toEqual({kind: "choose"});
    for (const v of ["destination:", "destination:../x", "destination:A", "destination:a b", "destination:" + "a".repeat(65), "other", null]) {
      expect(parseServiceDialog(v), String(v)).toBeNull();
    }
  });

  it("reads the rule dialogs, with an id only if it is a UUID", () => {
    expect(parseRuleDialog("add-edit-rule")).toEqual({kind: "rule", ruleId: null});
    expect(parseRuleDialog(`add-edit-rule:${ID}`)).toEqual({kind: "rule", ruleId: ID});
    expect(parseRuleDialog("folder")).toEqual({kind: "folder", folderId: null});
    expect(parseRuleDialog(`folder:${ID}`)).toEqual({kind: "folder", folderId: ID});
    expect(parseRuleDialog("upload")).toEqual({kind: "upload"});
    for (const v of ["add-edit-rule:x", "add-edit-rule:../..", `folder:${ID}:x`, `upload:${ID}`, "folder:", "script", null]) {
      expect(parseRuleDialog(v), String(v)).toBeNull();
    }
    for (const d of [{kind: "rule", ruleId: ID}, {kind: "rule", ruleId: null}, {kind: "folder", folderId: ID}, {kind: "upload"}] as const) {
      expect(parseRuleDialog(ruleDialogValue(d))).toEqual(d);
    }
  });

  it("reads the Endpoint dialogs and says which of them needs an Endpoint", () => {
    for (const v of ["add", "edit", "delete", "resolvers", "configure", "client"]) expect(parseDeviceDialog(v), v).toBe(v);
    expect(parseDeviceDialog("share")).toBeNull();
    expect(needsDeviceId("add")).toBe(false);
    expect(needsDeviceId("edit")).toBe(true);
    expect(parseDeviceId(ID)).toBe(ID);
    expect(parseDeviceId("my-router")).toBeNull();
    expect(parseDeviceId(`${ID}/x`)).toBeNull();
  });

  it("reads group and address dialogs", () => {
    expect(parseEndpointGroupDialog("create")).toEqual({kind: "create"});
    expect(parseEndpointGroupDialog(`rename:${ID}`)).toEqual({kind: "rename", groupId: ID});
    expect(parseEndpointGroupDialog(`delete:${ID}`)).toEqual({kind: "delete", groupId: ID});
    expect(parseEndpointGroupDialog("rename")).toBeNull();
    expect(parseIpDialog("add")).toEqual({kind: "add"});
    expect(parseIpDialog("claim")).toEqual({kind: "claim"});
    expect(parseIpDialog(`proof:${ID}`)).toEqual({kind: "proof", claimId: ID});
    expect(parseIpDialog("proof")).toBeNull();
    expect(parseIpDialog("proof:x")).toBeNull();
  });

  it("reads the wizard's platform and step, and the help topics of the screens", () => {
    expect(parseSetupOs("windows-11")).toBe("windows-11");
    expect(parseSetupOs("../x")).toBeNull();
    expect(parseSetupOs("A")).toBeNull();
    expect(parseStep("3")).toBe(3);
    expect(parseStep("12")).toBe(12);
    for (const v of ["0", "100", "-1", "1.5", "a", "", null]) expect(parseStep(v), String(v)).toBeNull();
    expect(parseHelpTopic("filter.malware")).toEqual({kind: "filter", id: "malware"});
    expect(parseHelpTopic("service.telegram")).toEqual({kind: "service", slug: "telegram"});
    expect(parseHelpTopic("option.safe_search")).toEqual({kind: "option", name: "safe_search"});
    expect(parseHelpTopic("filter.")).toBeNull();
    expect(parseHelpTopic("account")).toBeNull();
    expect(parseHelpTopic("filter.a/b")).toBeNull();
  });
});
