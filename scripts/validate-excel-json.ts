import * as fs from "fs";
import * as path from "path";
import { EXCEL_TABLE_ROOTS } from "./excel-server-adapt";
import { isJsonObject, type JsonValue } from "@excel/json-value";

/**
 * data/excel/*.json 类型覆盖校验
 *
 * 用真实 excel 数据校验 app/game/excel/types_excel_gen.ts 的类型闭包是否完整描述
 * 各表结构（缺字段/大小写/结构/标量 四维）。
 *
 * 用法: pnpm exec tsx scripts/validate-excel-json.ts [--tables t1,t2] [--full <file>]
 * 默认全表；--tables 指定子集（逗号分隔）；--full 输出完整报告到文件。
 */

// ---------- 类型定义文件解析 ----------

interface FieldMap {
  [fieldName: string]: string;
}

function parseInterfaces(content: string): Map<string, FieldMap> {
  const out = new Map<string, FieldMap>();
  const re = /export interface (\w+) \{([\s\S]*?)\n\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const fields: FieldMap = {};
    for (const line of m[2].split("\n")) {
      const fm = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\??:\s*(.+?);?\s*$/);
      if (!fm) continue;
      let type = fm[2].trim();
      if (type.endsWith(";")) type = type.slice(0, -1).trim();
      fields[fm[1]] = type;
    }
    out.set(m[1], fields);
  }
  return out;
}

function parseTypeAliases(content: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of content.split("\n")) {
    const m = line.match(/^export type (\w+) = (.*);\s*$/);
    if (m) out.set(m[1], m[2].trim());
  }
  return out;
}

// ---------- TS 类型归一化 ----------

interface TsType {
  kind: "index" | "array" | "iface" | "enum" | "primitive" | "objliteral" | "unknown";
  valueType?: string;
  ifaceName?: string;
  literal?: string;
}

function classifyType(
  typeStr: string,
  interfaces: Map<string, FieldMap>,
  aliases: Map<string, string>,
  seen = new Set<string>(),
): TsType {
  let t = typeStr.trim().replace(/\|\s*(null|undefined)\s*/g, "").trim();
  if (!t) return { kind: "unknown" };
  const indexMatch = t.match(/^\{\s*\[[a-zA-Z_][a-zA-Z0-9_]*:\s*[^\]]+\]:\s*(.+)\s*\}$/);
  if (indexMatch) return { kind: "index", valueType: indexMatch[1].trim() };
  const objMatch = t.match(/^\{\s*([\s\S]+)\s*\}$/);
  if (objMatch && objMatch[1].includes(":")) return { kind: "objliteral", literal: objMatch[1] };
  const arrayMatch = t.match(/^(.+)\[\]$/);
  if (arrayMatch) return { kind: "array", valueType: arrayMatch[1].trim() };
  if (t.includes('"') && t.includes("|")) return { kind: "enum", literal: t };
  if (/^(string|number|boolean|object|any|Date)$/.test(t)) return { kind: "primitive" };
  if (aliases.has(t)) {
    if (seen.has(t)) return { kind: "unknown" };
    seen.add(t);
    const at = aliases.get(t)!;
    if (at === "string" || (at.includes('"') && at.includes("|"))) {
      return { kind: "enum", literal: at === "string" ? "string" : at };
    }
    return classifyType(at, interfaces, aliases, seen);
  }
  if (interfaces.has(t)) return { kind: "iface", ifaceName: t };
  return { kind: "unknown" };
}

// ---------- 校验遍历 ----------

interface Report {
  missing: string[];
  caseDiff: string[];
  typeMismatch: string[];
  scalarMismatch: string[];
  untyped: string[];
  totalNodes: number;
}

function collectReport(): Report {
  return { missing: [], caseDiff: [], typeMismatch: [], scalarMismatch: [], untyped: [], totalNodes: 0 };
}

function checkScalar(jsonValue: JsonValue, tsTypeStr: string, path: string, report: Report, iface: string): void {
  if (jsonValue === null || jsonValue === undefined) return;
  const t = tsTypeStr.trim().replace(/\|\s*(null|undefined)\s*/g, "").trim();
  if (!t) return;
  const jt = typeof jsonValue;
  const loc = `${iface}.${path.split(".").pop() ?? ""}`;
  if (t.includes("|") && /^(number|string|boolean)(\s*\|\s*(number|string|boolean))+$/.test(t)) {
    const allowed = new Set(t.split("|").map(s => s.trim()));
    if (!allowed.has(jt)) report.scalarMismatch.push(`${loc}@${path}: 期望联合 [${[...allowed].join("|")}]，实际 ${jt}`);
    return;
  }
  if (t.includes('"') && t.includes("|")) {
    const vals = new Set(t.split("|").map(s => s.trim().replace(/"/g, "")));
    if (typeof jsonValue !== "string" || !vals.has(jsonValue)) {
      report.scalarMismatch.push(`${loc}@${path}: 期望枚举 [${[...vals].join("|")}]，实际 ${jt} ${JSON.stringify(jsonValue).slice(0, 30)}`);
    }
    return;
  }
  const lit = t.match(/^"(.+)"$/);
  if (lit) {
    if (jsonValue !== lit[1]) report.scalarMismatch.push(`${loc}@${path}: 期望 "${lit[1]}"，实际 ${jt}`);
    return;
  }
  switch (t) {
    case "number":
      if (jt !== "number") report.scalarMismatch.push(`${loc}@${path}: 期望 number，实际 ${jt} ${JSON.stringify(jsonValue).slice(0, 30)}`);
      break;
    case "string":
      if (jt !== "string") report.scalarMismatch.push(`${loc}@${path}: 期望 string，实际 ${jt} ${JSON.stringify(jsonValue).slice(0, 30)}`);
      break;
    case "boolean":
      if (jt !== "boolean") report.scalarMismatch.push(`${loc}@${path}: 期望 boolean，实际 ${jt} ${JSON.stringify(jsonValue).slice(0, 30)}`);
      break;
    default:
      break;
  }
}

function walk(
  jsonValue: JsonValue,
  tsTypeStr: string,
  path: string,
  report: Report,
  interfaces: Map<string, FieldMap>,
  aliases: Map<string, string>,
  ctx: { iface: string },
  seen = new Set<string>(),
): void {
  report.totalNodes++;
  const t = classifyType(tsTypeStr, interfaces, aliases);
  if (jsonValue === null || jsonValue === undefined) return;

  if (Array.isArray(jsonValue)) {
    if (t.kind === "array") {
      for (let i = 0; i < jsonValue.length; i++) walk(jsonValue[i], t.valueType!, `${path}[${i}]`, report, interfaces, aliases, ctx, seen);
    } else if (t.kind === "unknown" || t.kind === "primitive") {
      report.untyped.push(path);
    } else {
      report.typeMismatch.push(`${path}: JSON 数组，类型 ${tsTypeStr}`);
    }
    return;
  }

  if (typeof jsonValue === "object") {
    if (t.kind === "index") {
      for (const key of Object.keys(jsonValue)) {
        walk(jsonValue[key], t.valueType!, `${path}.${key}`, report, interfaces, aliases, ctx, seen);
      }
      return;
    }
    if (t.kind === "objliteral") {
      const fields: FieldMap = {};
      for (const part of t.literal!.split(";")) {
        const idx = part.indexOf(":");
        if (idx === -1) continue;
        const name = part.slice(0, idx).trim().replace(/\?$/, "");
        const type = part.slice(idx + 1).trim();
        if (name) fields[name] = type;
      }
      for (const key of Object.keys(jsonValue)) {
        const childPath = `${path}.${key}`;
        if (key in fields) walk(jsonValue[key], fields[key], childPath, report, interfaces, aliases, ctx, seen);
        else report.missing.push(`${childPath}: 类型对象字面量未声明该字段`);
      }
      return;
    }
    if (t.kind === "iface") {
      const fields = interfaces.get(t.ifaceName!)!;
      const childCtx = { iface: t.ifaceName! };
      for (const key of Object.keys(jsonValue)) {
        const childPath = `${path}.${key}`;
        if (key in fields) {
          walk(jsonValue[key], fields[key], childPath, report, interfaces, aliases, childCtx, seen);
        } else {
          const lower = key.toLowerCase();
          const candidates = Object.keys(fields).filter(f => f.toLowerCase() === lower);
          if (candidates.length > 0) {
            report.caseDiff.push(`${childPath}: JSON key "${key}" vs 类型字段 "${candidates[0]}"`);
            walk(jsonValue[key], fields[candidates[0]], childPath, report, interfaces, aliases, childCtx, seen);
          } else {
            report.missing.push(`${childPath}: 类型 ${t.ifaceName} 未声明该字段（JSON 类型 ${typeof jsonValue[key]}）`);
          }
        }
      }
      return;
    }
    report.untyped.push(path);
    return;
  }

  if (t.kind === "iface") {
    report.typeMismatch.push(`${path}: JSON 叶子 ${typeof jsonValue}，类型应为对象 ${tsTypeStr}`);
  } else if (t.kind === "primitive" || t.kind === "enum") {
    const effective = t.kind === "enum" ? (t.literal === "string" ? "string" : t.literal ?? tsTypeStr) : tsTypeStr;
    checkScalar(jsonValue, effective, path, report, ctx.iface);
  }
}

// ---------- 表遍历配置 ----------

/** 字典表（JSON 顶层 { id: 元素 }，逐元素 walk 根类型）；其余为包装表（整表 walk 根类型） */
const DICT_TABLES = new Set([
  "character_table", "skill_table", "story_table", "chapter_table",
  "story_review_table", "char_master_table",
  "range_table",
  "uniequip_data", "ep_breakbuff_table", "battle_equip_table", "replicate_table",
]);

function walkTable(
  table: string,
  json: JsonValue,
  root: string | Record<string, string>,
  report: Report,
  interfaces: Map<string, FieldMap>,
  aliases: Map<string, string>,
): void {
  if (typeof root === "object") {
    // 多根表：按 jsonKey → 根类 逐 key walk
    for (const [key, rootName] of Object.entries(root)) {
      const value = isJsonObject(json) ? json[key] : undefined;
      if (value === undefined) continue;
      walk(value, rootName, `playerData.${key}`, report, interfaces, aliases, { iface: rootName });
    }
    return;
  }
  if (DICT_TABLES.has(table)) {
    if (Array.isArray(json)) {
      for (let i = 0; i < json.length; i++) walk(json[i], root, `playerData[${i}]`, report, interfaces, aliases, { iface: root });
    } else if (isJsonObject(json)) {
      for (const key of Object.keys(json)) {
        walk(json[key], root, `playerData.${key}`, report, interfaces, aliases, { iface: root });
      }
    }
  } else {
    walk(json, root, "playerData", report, interfaces, aliases, { iface: root });
  }
}

// ---------- main ----------

export function main(argv: string[] = []): void {
  const args = argv;
  const typesFile = "D:/develop/DoctorateTs/app/game/excel/types_excel_gen.ts";
  const tablesArg = args.indexOf("--tables");
  const tableFilter = tablesArg !== -1 ? new Set(args[tablesArg + 1].split(",")) : null;

  const typesContent = fs.readFileSync(typesFile, "utf-8");
  const interfaces = parseInterfaces(typesContent);
  const aliases = parseTypeAliases(typesContent);
  console.log(`解析类型: ${interfaces.size} 接口, ${aliases.size} 别名/枚举`);

  const fullReport: string[] = [];
  let totalNodes = 0;
  let totalMissing = 0;
  let totalScalar = 0;
  let totalType = 0;
  let totalCase = 0;

  for (const [table, root] of Object.entries(EXCEL_TABLE_ROOTS)) {
    if (tableFilter && !tableFilter.has(table)) continue;
    const jsonPath = path.join(__dirname, `../data/excel/${table}.json`);
    if (!fs.existsSync(jsonPath)) {
      console.log(`\n[SKIP] ${table}: 文件不存在`);
      continue;
    }
    const report = collectReport();
    const json = JSON.parse(fs.readFileSync(jsonPath, "utf-8"));
    walkTable(table, json, root, report, interfaces, aliases);
    totalNodes += report.totalNodes;
    totalMissing += report.missing.length;
    totalScalar += report.scalarMismatch.length;
    totalType += report.typeMismatch.length;
    totalCase += report.caseDiff.length;

    const status = [report.missing.length, report.caseDiff.length, report.typeMismatch.length, report.scalarMismatch.length]
      .map(n => (n === 0 ? "0" : `\x1b[31m${n}\x1b[0m`)).join("/");
    console.log(`${table.padEnd(28)} 缺失/大小写/结构/标量: ${status}  (节点 ${report.totalNodes})`);
    if (report.missing.length + report.caseDiff.length + report.typeMismatch.length + report.scalarMismatch.length > 0) {
      fullReport.push(`\n=== ${table} ===`);
      if (args.includes("--raw")) report.missing.slice(0, 30).forEach(m => fullReport.push(`  RAWMISS ${m}`));
      const agg = new Map<string, number>();
      report.missing.forEach(m => {
        // 缺失消息: <path>: 类型 <Iface> 未声明该字段 ...；取缺失字段名（path 最后一段）
        const mm = m.match(/^(.*): 类型 (\w+) 未声明该字段/);
        const field = mm ? `${mm[2]}.${mm[1].split(".").pop()}` : m.split(":")[0];
        agg.set(field, (agg.get(field) ?? 0) + 1);
      });
      for (const [k, v] of [...agg.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)) fullReport.push(`  MISS x${v} ${k}`);
      report.scalarMismatch.slice(0, 12).forEach(m => fullReport.push(`  SCALAR ${m.replace(/@.*/, "")}`));
      report.typeMismatch.slice(0, 6).forEach(m => fullReport.push(`  TYPE ${m}`));
      report.caseDiff.slice(0, 6).forEach(m => fullReport.push(`  CASE ${m}`));
      report.untyped.slice(0, 5).forEach(m => fullReport.push(`  UNTYPED ${m}`));
    }
  }

  console.log(`\n=== 汇总 ===`);
  console.log(`遍历节点: ${totalNodes}`);
  console.log(`缺失: ${totalMissing}  大小写: ${totalCase}  结构: ${totalType}  标量: ${totalScalar}`);

  const fullIdx = args.indexOf("--full");
  if (fullIdx !== -1) {
    const outFile = args[fullIdx + 1] ?? "tmp/_excel-audit.txt";
    fs.writeFileSync(outFile, fullReport.join("\n"));
    console.log(`完整报告写入: ${outFile}`);
  }
}

// 直连执行入口（被 admin-cli tools 导入时不自动运行）
if (typeof require !== "undefined" && require.main === module) {
  main();
}
