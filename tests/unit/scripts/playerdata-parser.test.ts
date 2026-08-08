import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { parseFile, mapType, parseClassName, extractTypeNames } from "../../../scripts/playerdata-parser";

const fixture = fs.readFileSync(path.join(__dirname, "../../fixtures/playerdata-sample.cs"), "utf-8");

describe("playerdata-parser", () => {
  it("解析出全部类与枚举", () => {
    const { classes, enums } = parseFile(fixture);
    expect(classes.length).toBe(6); // PlayerDataModel/PlayerStatus/PlayerGacha/PlayerMonthlySubPer/PlayerConsumableItem/Tower
    expect(enums.length).toBe(2);
    const pdm = classes.find(c => c.name === "PlayerDataModel")!;
    expect(pdm.fields.length).toBe(6);
  });

  it("跳过 value__ 与方法", () => {
    const { classes } = parseFile(fixture);
    const status = classes.find(c => c.name === "PlayerStatus")!;
    expect(status.fields.map(f => f.name)).toEqual(["nickName", "ap", "apLimitUpFlag", "avatarType"]);
  });

  it("枚举值支持混合大小写与超大数字", () => {
    const { enums } = parseFile(fixture);
    const gachaType = enums.find(e => e.name === "GachaType")!;
    expect(gachaType.values).toEqual(["None", "Diamond", "SingleTicket", "TenTicket"]);
    const avatarType = enums.find(e => e.name === "PlayerAvatarType")!;
    expect(avatarType.values).toEqual(["NONE", "ASSISTANT"]);
  });

  it("mapType 处理 Dictionary/ListDict 嵌套泛型", () => {
    expect(mapType("System.Collections.Generic.Dictionary<System.String,Torappu.PlayerMonthlySubPer>"))
      .toBe("{ [key: string]: PlayerMonthlySubPer }");
    expect(mapType("System.Collections.Generic.Dictionary<System.String,Torappu.ListDict<System.Int32,Torappu.PlayerConsumableItem>>"))
      .toBe("{ [key: string]: { [key: number]: PlayerConsumableItem } }");
    expect(mapType("Torappu.ListDict<System.String,Torappu.PlayerSquadTmpl>"))
      .toBe("{ [key: string]: PlayerSquadTmpl }");
    expect(mapType("Torappu.PlayerStatus")).toBe("PlayerStatus");
    expect(mapType("System.Int32")).toBe("number");
  });

  it("parseClassName 处理嵌套类型", () => {
    expect(parseClassName("Torappu.PlayerData.FakeInstType")).toBe("PlayerData_FakeInstType");
  });

  it("extractTypeNames 提取泛型内引用", () => {
    expect(extractTypeNames("System.Collections.Generic.Dictionary<System.String,Torappu.ListDict<System.Int32,Torappu.PlayerConsumableItem>>"))
      .toEqual(["PlayerConsumableItem"]);
  });
});
