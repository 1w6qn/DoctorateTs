import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

/** 信用交易所候选池 vs item_table 一致性守护（data/shop/credit-shop-rows.json） */
describe("credit-shop-rows.json 一致性", () => {
  const cfg = JSON.parse(
    readFileSync(`${__dirname}/../../../data/shop/credit-shop-rows.json`, "utf-8"),
  ) as {
    rows: { id: string; count: number; originPrice: number; allow95?: boolean; allow99?: boolean }[][];
  };
  const items = JSON.parse(
    readFileSync(`${__dirname}/../../../data/excel/item_table.json`, "utf-8"),
  ).items as Record<string, { name?: string; itemType?: string }>;

  it("候选池为 7 行（并列随机抽取项）", () => {
    expect(cfg.rows).toHaveLength(7);
  });

  it("每个条目 id 均存在于 item_table 且字段完整", () => {
    for (const row of cfg.rows) {
      for (const entry of row) {
        expect(items[entry.id], `id=${entry.id} 缺失于 item_table`).toBeDefined();
        expect(entry.count).toBeGreaterThan(0);
        expect(entry.originPrice).toBeGreaterThan(0);
      }
    }
  });

  it("特价标记仅出现在允许特价的条目（-95% 行1、-99% 行2）", () => {
    const flagged = cfg.rows.flat().filter((e) => e.allow95 || e.allow99);
    expect(flagged).toHaveLength(4);
    for (const e of flagged) {
      expect(["4001", "2001", "2002"]).toContain(e.id);
    }
  });
});
