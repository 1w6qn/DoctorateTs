import { describe, it, expect } from "vitest";
import { checkAndRepairSave, hasRepairableIssues } from "../../../app/game/util/save-health";

describe("checkAndRepairSave（存档损坏自动检测与修复）", () => {
  it("PRIVATE.owners 含 null 条目应过滤（setPrivateDormOwner 字段名 bug 残留）", () => {
    const data = {
      status: { uid: "1", nickName: "博士" },
      troop: { chars: {} },
      building: {
        rooms: {
          PRIVATE: {
            slot_47: { owners: [null], comfort: 0 },
            slot_44: { owners: [340], comfort: 0 },
          },
        },
      },
    };
    const issues = checkAndRepairSave(data as any);
    expect(issues.some((i) => i.path.includes("slot_47") && i.fixed)).toBe(true);
    expect(data.building.rooms.PRIVATE.slot_47.owners).toEqual([]);
    // 合规房间不受影响
    expect(data.building.rooms.PRIVATE.slot_44.owners).toEqual([340]);
  });

  it("缺失必填顶层结构应重建", () => {
    const data = { status: { uid: "1" } };
    const issues = checkAndRepairSave(data as any);
    for (const key of ["troop", "dungeon", "activity", "building"]) {
      expect(data[key]).toBeDefined();
    }
    expect(issues.filter((i) => i.fixed).length).toBeGreaterThanOrEqual(3);
  });

  it("troop.chars 内非法干员（缺 charId）应移除", () => {
    const data = {
      status: { uid: "1" },
      troop: { chars: { "1": { instId: 1, charId: "char_001" }, "2": { instId: 2 } } },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(data as any);
    expect(data.troop.chars["2"]).toBeUndefined();
    expect(data.troop.chars["1"]).toBeDefined();
    expect(issues.some((i) => i.path === "troop.chars[2]" && i.fixed)).toBe(true);
  });

  it("status.uid 非字符串应转字符串", () => {
    const data = {
      status: { uid: 2222 },
      troop: {},
      dungeon: {},
      activity: {},
      building: {},
    };
    checkAndRepairSave(data as any);
    expect(data.status.uid).toBe("2222");
  });

  it("合规存档应零修复（幂等）", () => {
    const data = {
      status: { uid: "1" },
      troop: { chars: { "1": { instId: 1, charId: "char_001" } } },
      dungeon: {},
      activity: {},
      building: { rooms: { PRIVATE: { slot_1: { owners: [1] } } } },
    };
    const issues = checkAndRepairSave(data as any);
    expect(issues.filter((i) => i.fixed)).toHaveLength(0);
    expect(hasRepairableIssues(data)).toBe(false);
  });

  it("非对象根节点应标记不可修复", () => {
    const issues = checkAndRepairSave(null as any);
    expect(issues.some((i) => !i.fixed)).toBe(true);
  });

  it("dexNav.charInstId 悬空应重指向 roster 中正确干员（干员发放重建后残留）", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "2": { instId: 2, charId: "char_002" },
          "101": { instId: 101, charId: "char_101_sora" },
        },
      },
      dexNav: {
        character: {
          // 悬空：指向不存在的 instId
          char_002: { charInstId: 999, count: 3 },
          // 错指：指向其他干员（roster[2] 是 char_002）
          char_101_sora: { charInstId: 2, count: 5 },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(data as any);
    expect(data.dexNav.character.char_002.charInstId).toBe(2);
    expect(data.dexNav.character.char_101_sora.charInstId).toBe(101);
    expect(issues.filter((i) => i.fixed && i.path.startsWith("dexNav"))).toHaveLength(2);
  });

  it("dexNav 孤儿条目（干员不在 roster）应移除", () => {
    const data = {
      status: { uid: "1" },
      troop: { chars: { "2": { instId: 2, charId: "char_002" } } },
      dexNav: { character: { char_002: { charInstId: 2, count: 1 }, char_ghost: { charInstId: 5, count: 9 } } },
      dungeon: {},
      activity: {},
      building: {},
    };
    checkAndRepairSave(data as any);
    expect(data.dexNav.character.char_ghost).toBeUndefined();
    expect(data.dexNav.character.char_002).toBeDefined();
  });
});
