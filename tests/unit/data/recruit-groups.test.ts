import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

/** `data/excel/roguelike_topic_table.json` 的主题行视图（本守护只读 `recruitGrps`） */
interface RoguelikeTopicRow {
  /** 招募组键 → 职业映射值 */
  recruitGrps?: Record<string, string>;
}

/** `data/excel/roguelike_topic_table.json` 读取视图（本守护只读 `details` 主题字典） */
interface RoguelikeTopicTable {
  /** 主题 id → 主题行 */
  details: Record<string, RoguelikeTopicRow>;
}

/** 肉鸽招募组职业映射 vs excel recruitGrps 一致性守护（data/rlv2/recruit-groups.json） */
describe("recruit-groups.json 一致性", () => {
  const groups = JSON.parse(
    readFileSync(`${__dirname}/../../../data/rlv2/recruit-groups.json`, "utf-8"),
  ) as Record<string, string[]>;
  const topic = JSON.parse(
    readFileSync(`${__dirname}/../../../data/excel/roguelike_topic_table.json`, "utf-8"),
  ) as RoguelikeTopicTable;
  const professions = [
    "pioneer", "warrior", "tank", "sniper",
    "caster", "support", "medic", "special",
  ];

  it("每组键均存在于 excel recruitGrps", () => {
    for (const key of Object.keys(groups)) {
      const found = Object.values(topic.details).some((d) => d.recruitGrps?.[key]);
      expect(found, `组 ${key} 不存在于任何主题 recruitGrps`).toBe(true);
    }
  });

  it("组内职业均为标准 8 职业", () => {
    for (const profs of Object.values(groups)) {
      for (const p of profs) {
        expect(professions).toContain(p);
      }
    }
  });
});
