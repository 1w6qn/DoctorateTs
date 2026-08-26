import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

/** 肉鸽任务节点语义名→位值 vs excel nodeTypeData 一致性守护（data/rlv2/mission-node-values.json） */
describe("mission-node-values.json 一致性", () => {
  const values = JSON.parse(
    readFileSync(`${__dirname}/../../../data/rlv2/mission-node-values.json`, "utf-8"),
  ) as Record<string, number>;
  const topic = JSON.parse(
    readFileSync(`${__dirname}/../../../data/excel/roguelike_topic_table.json`, "utf-8"),
  );

  it("每个位值均为 2 的幂且存在于某主题 nodeTypeData 键", () => {
    const allKeys = new Set<number>();
    for (const det of Object.values(topic.details) as any[]) {
      for (const k of Object.keys(det.nodeTypeData ?? {})) allKeys.add(Number(k));
    }
    for (const [name, value] of Object.entries(values)) {
      expect(
        Number.isInteger(value) && value > 0 && (value & (value - 1)) === 0,
        `${name}=${value} 非 2 的幂`,
      ).toBe(true);
      expect(
        allKeys.has(value),
        `${name}=${value} 不在任何主题 nodeTypeData 键`,
      ).toBe(true);
    }
  });

  it("覆盖全部 24 个语义名", () => {
    expect(Object.keys(values)).toHaveLength(24);
  });
});
