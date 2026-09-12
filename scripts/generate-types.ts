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
import { requireCsFile } from "./lib/cs-source";
import { reconcileExcelJsonKeys } from "./excel-json-keys";

/**
 * 统一类型生成器
 *
 * 从 reference/com.hypergryph.arknights_*.cs 生成两类类型文件：
 *  - --playerdata：PlayerDataModel 运行时类型（app/game/excel/types-playerdata.ts）
 *  - --excel：excel 表类型（app/game/excel/types_excel_gen.ts）
 * 无参数 = 全部生成。命令: pnpm run generate:types
 * 输入文件：默认自动选 reference/ 下最新的 com.hypergryph.arknights_*.cs，
 * 也可用 --cs <路径> 或环境变量 GENERATE_CS 显式指定（配合 scripts/decompile-client.sh 一键再生）。
 */
const args = process.argv.slice(2);

const CS_FILE = requireCsFile({
  explicit: args.indexOf("--cs") >= 0 ? args[args.indexOf("--cs") + 1] : process.env.GENERATE_CS,
});
// 溯源标注：从实际选中的源文件名取版本，避免把版本号硬编码进生成文件头
const CS_BASENAME = path.basename(CS_FILE);
const CS_RELATIVE = `reference/${CS_BASENAME}`;
const PLAYERDATA_OUT = path.join(__dirname, "../app/game/excel/types-playerdata.ts");
const EXCEL_OUT = path.join(__dirname, "../app/game/excel/types_excel_gen.ts");

function buildPlayerdataTypes(content: string): string {
  const result = buildTypes(content, {
    roots: ["PlayerDataModel"],
    adapt: (classes, enumNames) => applyWireFormat(applyServerAdapt(classes), enumNames),
    importLines: ['import type { ServerPayload } from "./json-value";'],
    jsonTypeName: "ServerPayload",
    headerLines: [
      "自动生成的玩家数据类型定义文件",
      `从 ${CS_RELATIVE} 反编译文件生成`,
      "（客户端闭包 + 服务端协议适配 + 线格式适配，见 scripts/playerdata-server-adapt.ts）",
      "生成命令: pnpm run generate:types",
    ],
  });
  return result.output;
}

function buildExcelTypes(content: string): string {
  const result = buildTypes(content, {
    roots: allTableRoots(),
    // excel 协议适配 + JSON 实际键对照（CS 字段名与 JSON 键大小写不一致时以 JSON 为准）
    adapt: (classes) => reconcileExcelJsonKeys(applyExcelAdapt(classes)),
    enumAdditions: EXCEL_ENUM_ADDITIONS,
    indexSignatures: EXCEL_INDEX_SIGNATURES,
    importLines: ['import type { JsonValue } from "./json-value";'],
    headerLines: [
      "自动生成的 excel 表类型定义文件",
      `从 ${CS_RELATIVE} 反编译文件生成`,
      "（客户端表类闭包 + excel 协议适配 + JSON 实际键对照，见 scripts/excel-server-adapt.ts / excel-json-keys.ts）",
      "生成命令: pnpm run generate:types",
    ],
  });
  return result.output;
}

function main(): void {
  // 无 --playerdata/--excel 指定时默认全部生成（--cs/--force 等参数不影响该默认值）
  const hasDomainFlag = args.includes("--playerdata") || args.includes("--excel");
  const doPlayerdata = !hasDomainFlag || args.includes("--playerdata");
  const doExcel = !hasDomainFlag || args.includes("--excel");
  const force = args.includes("--force");

  if (!fs.existsSync(CS_FILE)) {
    console.error(`输入文件不存在: ${CS_FILE}`);
    console.error(
      "请将官服反编译文件放到 reference/com.hypergryph.arknights_<版本>.cs" +
        "（或运行 `pnpm run decompile` / 用 --cs 显式指定）",
    );
    process.exit(1);
  }
  console.log(`CS 源: ${CS_RELATIVE}`);

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
