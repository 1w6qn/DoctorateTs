import { describe, it, expect, vi, beforeEach } from "vitest";

const excelState = vi.hoisted(() => ({
  teams: {} as Record<string, unknown>,
  chars: {} as Record<string, { mainPower?: Record<string, string | null> }>,
}));

vi.mock("@excel/excel", () => ({
  default: {
    get HandbookTeamTable() { return excelState.teams; },
    get CharacterTable() { return excelState.chars; },
  },
}));

import {
  newlyCompletedPowers,
  powerMembers,
  resetPowerMembersCache,
} from "@game/modules/character/team-power";

/**
 * 势力全员收集判定单元测试（guide_43/guide_48 → GainTeamChar）
 */
describe("team-power 势力全员收集", () => {
  beforeEach(() => {
    resetPowerMembersCache();
    excelState.teams = {
      rhodes: { powerId: "rhodes", powerName: "罗德岛" },
      sweep: { powerId: "sweep", powerName: "S.W.E.E.P." },
      none: { powerId: "none", powerName: "无团队" },
      dublinn: { powerId: "dublinn", powerName: "深池" }, // 无成员 → 应被丢弃
    };
    excelState.chars = {
      char_a: { mainPower: { nationId: "rhodes", groupId: null, teamId: null } },
      char_b: { mainPower: { nationId: "rhodes", groupId: null, teamId: null } },
      char_c: { mainPower: { nationId: "rhodes", groupId: "sweep", teamId: null } },
      char_d: { mainPower: { nationId: null, groupId: "none", teamId: null } },
    };
  });

  it("powerMembers 按 mainPower 归属构建并丢弃无成员势力", () => {
    const map = powerMembers();
    expect(map.get("rhodes")).toEqual(["char_a", "char_b", "char_c"]);
    expect(map.get("sweep")).toEqual(["char_c"]);
    expect(map.get("none")).toEqual(["char_d"]);
    expect(map.has("dublinn")).toBe(false); // 无成员势力被丢弃
  });

  it("集齐某势力全部成员时应回报该势力", () => {
    // 只拥有 char_a/char_c → sweep（仅 char_c）已全员，rhodes 未齐
    const owned = new Set(["char_a", "char_c"]);
    expect(newlyCompletedPowers(owned, "char_c")).toEqual(["sweep"]);
    // 再获得 char_b → rhodes 齐
    owned.add("char_b");
    expect(newlyCompletedPowers(owned, "char_b")).toEqual(["rhodes"]);
  });

  it("未集齐时不回报（避免误发任务进度）", () => {
    const owned = new Set(["char_a"]);
    expect(newlyCompletedPowers(owned, "char_a")).toEqual([]);
  });
});
