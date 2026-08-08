import { describe, it, expect } from "vitest";
import { applyServerAdapt } from "../../../scripts/playerdata-server-adapt";
import type { ClassDef } from "../../../scripts/playerdata-parser";

function cls(name: string, fields: Record<string, string>): ClassDef {
  return {
    fullName: `Torappu.${name}`,
    name,
    fields: Object.entries(fields).map(([n, rawType]) => ({ name: n, rawType, type: rawType })),
  };
}

describe("playerdata-server-adapt", () => {
  it("rename 字段（客户端名 → 服务端 key）", () => {
    const out = applyServerAdapt([cls("PlayerDataModel", { campaign: "PlayerCampaign", arkOdc: "PlayerArkOdc" })]);
    const pdm = out.find(c => c.name === "PlayerDataModel")!;
    expect(pdm.fields.map(f => f.name)).toEqual(["campaignsV2", "arkodc", "deleted", "checkMeta"]);
    expect(pdm.fields[0].type).toBe("PlayerCampaign");
  });

  it("add 服务端独有字段", () => {
    const out = applyServerAdapt([cls("PlayerStage", { stageId: "string" })]);
    const ps = out.find(c => c.name === "PlayerStage")!;
    expect(ps.fields.map(f => f.name)).toContain("startTimes");
    expect(ps.fields.find(f => f.name === "startTimes")!.type).toBe("number");
  });

  it("override 字段类型（结构差异）", () => {
    const out = applyServerAdapt([cls("PlayerCartInfo_Cart", {})]);
    const cart = out.find(c => c.name === "PlayerCartInfo_Cart")!;
    expect(cart.aliasType).toBe("{ [key: string]: string }");
  });

  it("不存在的接口/字段静默跳过", () => {
    const out = applyServerAdapt([cls("NotInList", { a: "string" })]);
    expect(out[0].fields.length).toBe(1);
  });
});
