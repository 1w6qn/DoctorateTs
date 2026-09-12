import { describe, it, expect } from "vitest";
import { applyServerAdapt, applyWireFormat } from "../../../scripts/playerdata-server-adapt";
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

  it("rename 种子模式活动字段（roguelikeActivitySeedModeDatas → SEED_MODE）", () => {
    const out = applyServerAdapt([cls("PlayerRoguelikeV2_OuterData_PlayerRogueActivity", { roguelikeActivitySeedModeDatas: "{ [key: string]: object }" })]);
    const act = out.find(c => c.name === "PlayerRoguelikeV2_OuterData_PlayerRogueActivity")!;
    expect(act.fields.map(f => f.name)).toEqual(["SEED_MODE"]);
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

  it("wire pass 枚举与布尔字段 → number（白名单除外）", () => {
    const out = applyWireFormat(
      [
        cls("PlayerStage", { state: "PlayerStageState", hasBattleReplay: "boolean" }),
        cls("PlayerGacha_PlayerGachaPool", { avail: "boolean" }),
        cls("PlayerSkins", { skinSp: "{ [key: string]: boolean }" }),
      ],
      new Set(["PlayerStageState"]),
    );
    const stage = out.find(c => c.name === "PlayerStage")!;
    expect(stage.fields.find(f => f.name === "state")!.type).toBe("number");
    expect(stage.fields.find(f => f.name === "hasBattleReplay")!.type).toBe("number");
    const pool = out.find(c => c.name === "PlayerGacha_PlayerGachaPool")!;
    expect(pool.fields.find(f => f.name === "avail")!.type).toBe("boolean"); // 白名单保留
    const skins = out.find(c => c.name === "PlayerSkins")!;
    // 字典值递归改写本应得 `{ [key: string]: number }`，但字段级覆盖优先：
    // 真实存档里 changeSkinSpState 按 CS Boolean 写 true/false，而客户端模型声明 number → 两态并存
    // （覆盖表见 scripts/playerdata-server-adapt.ts#SERVER_FIELD_TYPE_OVERRIDES["PlayerSkins.skinSp"]）
    expect(skins.fields.find(f => f.name === "skinSp")!.type).toBe("{ [key: string]: number | boolean }");
  });

  it("wire pass 字符串序列化枚举保留字面量联合 + 字段级类型覆盖", () => {
    const out = applyWireFormat(
      [
        cls("PlayerBuildingRoomSlot", { roomId: "BuildingData_RoomType" }),
        cls("PlayerBuildingMeetingClue", { uid: "number" }),
        cls("PlayerCrisisSocialInfo", { maxPnt: "number" }),
      ],
      new Set(["BuildingData_RoomType"]),
    );
    const slot = out.find(c => c.name === "PlayerBuildingRoomSlot")!;
    expect(slot.fields.find(f => f.name === "roomId")!.type).toBe("BuildingData_RoomType"); // 保留 union
    const clue = out.find(c => c.name === "PlayerBuildingMeetingClue")!;
    expect(clue.fields.find(f => f.name === "uid")!.type).toBe("string"); // override
    const crisis = out.find(c => c.name === "PlayerCrisisSocialInfo")!;
    expect(crisis.fields.find(f => f.name === "maxPnt")!.type).toBe("number | string"); // override
  });
});
