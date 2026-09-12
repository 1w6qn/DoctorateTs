/**
 * 适配表重复键守卫
 *
 * `scripts/playerdata-server-adapt.ts` / `scripts/excel-server-adapt.ts` 的覆盖表是
 * `pnpm run generate:types` 的唯一输入；同名键在 JS 语义下「后者胜」，被覆盖的声明
 * 会静默失效（历史实例：`SERVER_ADD_FIELDS.PlayerCharPatch` 声明两次）。
 * 本守卫要求这两张表的源码**不含重复键**，避免生成类型与作者意图不一致。
 *
 * 度量逻辑见 scripts/lib/adapt-table-scan.ts（纯函数，与守卫同源）。
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { scanDuplicateTableKeys } from "../../../scripts/lib/adapt-table-scan";

const REPO_ROOT = path.resolve(__dirname, "../../..");
const ADAPT_FILES = ["scripts/playerdata-server-adapt.ts", "scripts/excel-server-adapt.ts"];

describe("适配表重复键守卫", () => {
  it("负样本自证：顶层、嵌套与引号键的重复都能被抓到", () => {
    const src = `export const T: Record<string, Record<string, string>> = {
      A: { x: "1", y: "2" },
      B: { x: "1", x: "2" },
      A: { z: "3" },
      "D.e": "number",
      "D.e": "string",
    };`;
    expect(scanDuplicateTableKeys(src)).toEqual([
      { table: "T", path: "A", count: 2 },
      { table: "T", path: "B.x", count: 2 },
      { table: "T", path: "D.e", count: 2 },
    ]);
  });

  it("负样本自证：注释与字符串内的假键不计入", () => {
    const src = `export const T = {
      // A: { x: "1" },
      /* B: { y: "2" }, */
      C: { s: "{ a: string, b: number }", t: "x, y" },
      D: { note: "A: 1, A: 2" },
    };`;
    expect(scanDuplicateTableKeys(src)).toEqual([]);
  });

  it("正样本：覆盖表源码不含重复键", () => {
    const findings = ADAPT_FILES.flatMap((rel) => {
      const src = fs.readFileSync(path.join(REPO_ROOT, rel), "utf-8");
      return scanDuplicateTableKeys(src).map((f) => `${rel} → ${f.table}.${f.path} ×${f.count}`);
    });
    expect(findings, `覆盖表存在重复键（同名字面量后者静默覆盖前者）：\n  ${findings.join("\n  ")}`).toEqual(
      [],
    );
  });
});
