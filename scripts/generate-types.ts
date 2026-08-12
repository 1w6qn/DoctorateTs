import * as fs from "fs";
import * as path from "path";
import { buildTypes } from "./types-builder";
import { applyServerAdapt, applyWireFormat } from "./playerdata-server-adapt";
import {
  applyExcelAdapt,
  allTableRoots,
  EXCEL_INDEX_SIGNATURES,
  EXCEL_ENUM_ADDITIONS,
} from "./excel-server-adapt";
import { reconcileExcelJsonKeys } from "./excel-json-keys";

/**
 * 统一类型生成器
 *
 * 从 reference/com.hypergryph.arknights_2.7.61.cs 生成两类类型文件：
 *  - --playerdata：PlayerDataModel 运行时类型（app/excel/types-playerdata.ts）
 *  - --excel：excel 表类型（app/excel/types_excel_gen.ts）
 * 无参数 = 全部生成。命令: npm run generate:types
 */
const CS_FILE = path.join(__dirname, "../reference/com.hypergryph.arknights_2.7.61.cs");
const PLAYERDATA_OUT = path.join(__dirname, "../app/excel/types-playerdata.ts");
const EXCEL_OUT = path.join(__dirname, "../app/excel/types_excel_gen.ts");

function buildPlayerdataTypes(content: string): string {
  const result = buildTypes(content, {
    roots: ["PlayerDataModel"],
    adapt: (classes, enumNames) => applyWireFormat(applyServerAdapt(classes), enumNames),
    headerLines: [
      "自动生成的玩家数据类型定义文件",
      "从 reference/com.hypergryph.arknights_2.7.61.cs 反编译文件生成",
      "（客户端闭包 + 服务端协议适配 + 线格式适配，见 scripts/playerdata-server-adapt.ts）",
      "生成命令: npm run generate:types",
    ],
  });
  return result.output;
}

function buildExcelTypes(content: string): string {
  const result = buildTypes(content, {
    roots: allTableRoots(),
    // excel 协议适配 + JSON 实际键对照（CS 字段名与 JSON 键大小写不一致时以 JSON 为准）
    adapt: (classes, enumNames) =>
      reconcileExcelJsonKeys(applyExcelAdapt(classes, enumNames)),
    enumAdditions: EXCEL_ENUM_ADDITIONS,
    indexSignatures: EXCEL_INDEX_SIGNATURES,
    headerLines: [
      "自动生成的 excel 表类型定义文件",
      "从 reference/com.hypergryph.arknights_2.7.61.cs 反编译文件生成",
      "（客户端表类闭包 + excel 协议适配 + JSON 实际键对照，见 scripts/excel-server-adapt.ts / excel-json-keys.ts）",
      "生成命令: npm run generate:types",
    ],
  });
  return result.output;
}

function main(): void {
  const args = process.argv.slice(2);
  const doPlayerdata = args.length === 0 || args.includes("--playerdata");
  const doExcel = args.length === 0 || args.includes("--excel");
  const force = args.includes("--force");

  if (!fs.existsSync(CS_FILE)) {
    console.error(`输入文件不存在: ${CS_FILE}`);
    console.error("请将官服反编译文件放到 reference/com.hypergryph.arknights_2.7.61.cs");
    process.exit(1);
  }

  // 增量跳过：输出比（CS 源 + 最新 excel 数据 + 适配表）都新 → 无需重新生成（启动提速）
  if (!force) {
    const csMtime = fs.statSync(CS_FILE).mtimeMs;
    const newestData = fs
      .readdirSync(path.join(__dirname, "../data/excel"))
      .filter((f) => f.endsWith(".json"))
      .reduce((m, f) => Math.max(m, fs.statSync(path.join(__dirname, "../data/excel", f)).mtimeMs), 0);
    const adaptMtime = fs
      .readdirSync(__dirname)
      .filter((f) => /adapt\.ts$|types-builder\.ts$|types-adapt\.ts$/.test(f))
      .reduce((m, f) => Math.max(m, fs.statSync(path.join(__dirname, f)).mtimeMs), 0);
    const upToDate =
      (!doPlayerdata || fs.existsSync(PLAYERDATA_OUT) && fs.statSync(PLAYERDATA_OUT).mtimeMs >= Math.max(csMtime, adaptMtime)) &&
      (!doExcel || fs.existsSync(EXCEL_OUT) && fs.statSync(EXCEL_OUT).mtimeMs >= Math.max(csMtime, newestData, adaptMtime));
    if (upToDate) {
      console.log("类型已是最新（CS 源/数据/适配表未变更），跳过生成");
      return;
    }
  }

  const content = fs.readFileSync(CS_FILE, "utf-8");
  console.log(`读取 C# 反编译文件: ${(content.length / 1024 / 1024).toFixed(2)} MB`);

  if (doPlayerdata) {
    console.log("构建 PlayerDataModel 类型闭包...");
    const out = buildPlayerdataTypes(content);
    fs.writeFileSync(PLAYERDATA_OUT, out);
    console.log(`生成完成: ${PLAYERDATA_OUT}（${(out.length / 1024).toFixed(2)} KB）`);
  }
  if (doExcel) {
    console.log("构建 excel 表类型闭包...");
    const out = buildExcelTypes(content);
    fs.writeFileSync(EXCEL_OUT, out);
    console.log(`生成完成: ${EXCEL_OUT}（${(out.length / 1024).toFixed(2)} KB）`);
  }
}

main();
