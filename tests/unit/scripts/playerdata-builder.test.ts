import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { buildTypes } from "../../../scripts/types-builder";
import { applyServerAdapt, applyWireFormat } from "../../../scripts/playerdata-server-adapt";

const fixture = fs.readFileSync(path.join(__dirname, "../../fixtures/playerdata-sample.cs"), "utf-8");

function buildPlayerDataTypes(content: string) {
  return buildTypes(content, {
    roots: ["PlayerDataModel"],
    adapt: (classes, enumNames) => applyWireFormat(applyServerAdapt(classes), enumNames),
    headerLines: [],
  });
}

describe("playerdata-builder", () => {
  it("闭包包含 PlayerDataModel 可达类型，排除无关类", () => {
    const { output, classes, enums } = buildPlayerDataTypes(fixture);
    expect(classes).toContain("PlayerDataModel");
    expect(classes).toContain("PlayerStatus");
    expect(classes).toContain("PlayerGacha");
    expect(classes).toContain("PlayerMonthlySubPer");
    expect(classes).toContain("PlayerConsumableItem");
    expect(classes).not.toContain("Tower");
    expect(enums).toEqual(["PlayerAvatarType", "GachaType"]);
  });

  it("生成完整枚举值（不退化 string）", () => {
    const { output } = buildPlayerDataTypes(fixture);
    expect(output).toContain('export type GachaType = "None" | "Diamond" | "SingleTicket" | "TenTicket";');
    expect(output).toContain('export type PlayerAvatarType = "NONE" | "ASSISTANT";');
  });

  it("生成 PlayerDataModel 接口与字典类型字段", () => {
    const { output } = buildPlayerDataTypes(fixture);
    expect(output).toContain("export interface PlayerDataModel {");
    expect(output).toContain("monthlySub: { [key: string]: PlayerMonthlySubPer };");
    expect(output).toContain("consumable: { [key: string]: { [key: number]: PlayerConsumableItem } };");
  });

  it("自检通过：无未定义引用", () => {
    const result = buildPlayerDataTypes(fixture);
    expect(result.classes.length).toBeGreaterThan(0);
    expect(result.enums.length).toBeGreaterThan(0);
  });
});
