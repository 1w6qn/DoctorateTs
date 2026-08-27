import { describe, it, expect, vi } from "vitest";

const excelMock = vi.hoisted(() => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    BuildingData: {
      manufactFormulas: {
        "4": {
          formulaId: "4",
          itemId: "3003",
          count: 1,
          costPoint: 4320,
          formulaType: "F_GOLD",
          costs: [],
        },
        "5": {
          formulaId: "5",
          itemId: "3213",
          count: 1,
          costPoint: 1,
          formulaType: "F_ASC",
          costs: [
            { id: "3212", count: 2, type: "MATERIAL" },
            { id: "32001", count: 1, type: "MATERIAL" },
          ],
        },
      },
      workshopFormulas: {
        "1": {
          formulaId: "1",
          itemId: "3131",
          count: 1,
          goldCost: 800,
          apCost: 360000,
          costs: [{ id: "3112", count: 2, type: "MATERIAL" }],
          extraOutcomeRate: 0.1,
          extraOutcomeGroup: [{ weight: 100, itemId: "3112", itemCount: 1 }],
        },
      },
      rooms: {
        MANUFACTURE: {
          phases: [
            {
              buildCost: {
                items: [{ id: "3131", count: 1, type: "MATERIAL" }],
                time: 0,
                labor: 10,
              },
              maxStationedNum: 1,
            },
          ],
        },
      },
      goldItems: { "3003": 500 },
      laborRecoverTime: 360,
      basicFavorPerDay: 720,
      apToLaborRatio: 2,
    },
  },
}));
vi.mock("@excel/excel", () => excelMock);

import {
  getManufactFormula,
  getWorkshopFormula,
  getRoomPhase,
  getGoldRate,
  getBuildingConstant,
} from "../../../app/game/service/excel/building_excel";

describe("BuildingExcel 查询工具", () => {
  it("getManufactFormula 按 formulaId 查表（字符串/数字兼容）", () => {
    expect(getManufactFormula("4")?.itemId).toBe("3003");
    expect(getManufactFormula(5)?.itemId).toBe("3213");
  });

  it("getManufactFormula 未知返回 undefined", () => {
    expect(getManufactFormula("999")).toBeUndefined();
  });

  it("getWorkshopFormula 按 formulaId 查表", () => {
    expect(getWorkshopFormula("1")?.goldCost).toBe(800);
  });

  it("getRoomPhase 按 roomId+level 取相位（level 1 基）", () => {
    expect(getRoomPhase("MANUFACTURE", 1)?.maxStationedNum).toBe(1);
  });

  it("getRoomPhase 越界返回 undefined", () => {
    expect(getRoomPhase("MANUFACTURE", 99)).toBeUndefined();
  });

  it("getGoldRate 返回 goldItems 3003 汇率", () => {
    expect(getGoldRate()).toBe(500);
  });

  it("getBuildingConstant 读取顶层常量", () => {
    expect(getBuildingConstant("laborRecoverTime")).toBe(360);
    expect(getBuildingConstant("basicFavorPerDay")).toBe(720);
    expect(getBuildingConstant("apToLaborRatio")).toBe(2);
  });
});
