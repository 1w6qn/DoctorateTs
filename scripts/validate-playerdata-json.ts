import * as fs from "fs";
import * as path from "path";

/**
 * player_data.json 类型覆盖校验
 *
 * 用官服真实玩家存档校验 app/excel/types-playerdata.ts 的 PlayerDataModel
 * 类型闭包是否完整描述真实数据结构（"toJson 输出与原输入一致"）。
 *
 * 用法: npx tsx scripts/validate-playerdata-json.ts [--input <json>] [--types <ts>] [--root <path>]
 * 默认输入: reference/OpenBachelorS-master/tmp/player_data.json
 * 默认类型: app/excel/types-playerdata.ts
 * --root: JSON 内玩家数据根路径（如官服账号文件 test.json 的 "user"）
 */

// ---------- 类型定义文件解析 ----------

interface FieldMap {
  [fieldName: string]: string; // 字段名 -> TS 类型字符串
}

/** 解析 export interface X { ... } 块 */
function parseInterfaces(content: string): Map<string, FieldMap> {
  const out = new Map<string, FieldMap>();
  const re = /export interface (\w+) \{([\s\S]*?)\n\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const name = m[1];
    const fields: FieldMap = {};
    const body = m[2];
    const fre = /^\s*([A-Za-z_][A-Za-z0-9_]*):\s*([^;]+);/gm;
    let fm: RegExpExecArray | null;
    while ((fm = fre.exec(body)) !== null) {
      fields[fm[1]] = fm[2].trim();
    }
    out.set(name, fields);
  }
  return out;
}

/** 解析 export type X = ...;（枚举/别名） */
function parseTypeAliases(content: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = /export type (\w+) = ([\s\S]*?);/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    out.set(m[1], m[2].trim());
  }
  return out;
}

// ---------- 已知命名差异（C# 字段名 ↔ 真实 JSON key） ----------
// 生成类型忠实 C# 2.7.61 字段名；player_data.json 是官服实际序列化 key。
// 差异来源：C# 字段改名 / 反编译命名 vs 服务端序列化别名。
const FIELD_ALIASES: { [jsonKey: string]: string } = {
  campaignsV2: "campaign", // C# PlayerCampaign campaign
  arkodc: "arkOdc", // 大小写
  event: "events", // C# PlayerEvents events
  nameCardStyle: "playerNameCardStyle",
  avatar: "PlayerAvatar",
  background: "playerHomeBackground",
  homeTheme: "playerHomeTheme",
  mainline: "playerMainlineRecord",
};

// ---------- TS 类型归一化 ----------

interface TsType {
  kind: "index" | "array" | "iface" | "enum" | "primitive" | "unknown";
  valueType?: string; // index/array
  ifaceName?: string;
}

function classifyType(
  typeStr: string,
  interfaces: Map<string, FieldMap>,
  aliases: Map<string, string>,
  seen = new Set<string>(),
): TsType {
  let t = typeStr.trim();
  // 剥 | null / | undefined
  t = t.replace(/\|\s*(null|undefined)\s*/g, "").trim();
  if (!t) return { kind: "unknown" };

  // 索引签名 { [key: K]: V }
  const indexMatch = t.match(/^\{\s*\[key:\s*[^\]]+\]:\s*(.+)\s*\}$/);
  if (indexMatch) return { kind: "index", valueType: indexMatch[1].trim() };

  // 数组 X[]
  const arrayMatch = t.match(/^(.+)\[\]$/);
  if (arrayMatch) return { kind: "array", valueType: arrayMatch[1].trim() };

  // 枚举字面量联合 "A" | "B"（多行内联）
  if (t.includes('"') && t.includes("|")) return { kind: "enum" };

  // 基础类型
  if (/^(string|number|boolean|object|any|Date)$/.test(t)) return { kind: "primitive" };

  // 类型别名（枚举/索引别名）
  if (aliases.has(t)) {
    if (seen.has(t)) return { kind: "unknown" };
    seen.add(t);
    const aliasTarget = aliases.get(t)!;
    // 枚举别名（字面量联合或 string 退化）
    if (aliasTarget === "string" || (aliasTarget.includes('"') && aliasTarget.includes("|"))) {
      return { kind: "enum" };
    }
    // 索引别名
    const aliasIndex = aliasTarget.match(/^\{\s*\[key:\s*[^\]]+\]:\s*(.+)\s*\}$/);
    if (aliasIndex) return { kind: "index", valueType: aliasIndex[1].trim() };
    return { kind: "unknown" };
  }

  // 接口
  if (interfaces.has(t)) return { kind: "iface", ifaceName: t };

  return { kind: "unknown" };
}

// ---------- 校验遍历 ----------

interface Report {
  missing: string[]; // JSON 有、类型无
  caseDiff: string[]; // 大小写差异建议
  typeMismatch: string[]; // 结构类型不匹配
  typeOnly: string[]; // 类型有、JSON 无（信息性）
  totalNodes: number;
}

function collectReport(): Report {
  return { missing: [], caseDiff: [], typeMismatch: [], typeOnly: [], totalNodes: 0 };
}

/** 对缺失路径去重并按「缺失字段名@所在接口」聚合（区分版本差异 vs 真实缺口） */
function aggregateMissing(missing: string[]): { path: string; field: string; iface: string }[] {
  const seen = new Set<string>();
  const out: { path: string; field: string; iface: string }[] = [];
  for (const m of missing) {
    // 形如 playerData.x.y.field: 类型 Iface 未声明该字段
    const mm = m.match(/^(.*)\.([^.]+): 类型 (\w+) 未声明该字段/);
    if (!mm) {
      if (!seen.has(m)) { seen.add(m); out.push({ path: m, field: "?", iface: "?" }); }
      continue;
    }
    const key = `${mm[2]}@${mm[3]}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push({ path: mm[1], field: mm[2], iface: mm[3] });
    }
  }
  return out;
}

function walk(
  jsonValue: unknown,
  tsTypeStr: string,
  path: string,
  report: Report,
  interfaces: Map<string, FieldMap>,
  aliases: Map<string, string>,
): void {
  report.totalNodes++;
  const t = classifyType(tsTypeStr, interfaces, aliases);

  if (jsonValue === null || jsonValue === undefined) return;

  if (Array.isArray(jsonValue)) {
    if (t.kind === "array") {
      for (let i = 0; i < jsonValue.length; i++) {
        walk(jsonValue[i], t.valueType!, `${path}[${i}]`, report, interfaces, aliases);
      }
    } else if (t.kind === "unknown" || t.kind === "primitive") {
      // 未知/基础类型下的数组：类型定义不约束，跳过
    } else {
      report.typeMismatch.push(`${path}: JSON 数组，类型 ${tsTypeStr}`);
    }
    return;
  }

  if (typeof jsonValue === "object") {
    if (t.kind === "index") {
      for (const key of Object.keys(jsonValue as object)) {
        walk((jsonValue as any)[key], t.valueType!, `${path}.${key}`, report, interfaces, aliases);
      }
      return;
    }
    if (t.kind === "iface") {
      const fields = interfaces.get(t.ifaceName!)!;
      for (const key of Object.keys(jsonValue as object)) {
        const childPath = `${path}.${key}`;
        if (key in fields) {
          walk((jsonValue as any)[key], fields[key], childPath, report, interfaces, aliases);
        } else if (key in FIELD_ALIASES && FIELD_ALIASES[key] in fields) {
          // 已知命名差异：用 C# 字段名继续穿透检查
          walk((jsonValue as any)[key], fields[FIELD_ALIASES[key]], childPath, report, interfaces, aliases);
        } else {
          // 大小写不敏感建议
          const lower = key.toLowerCase();
          const candidates = Object.keys(fields).filter(f => f.toLowerCase() === lower);
          if (candidates.length > 0) {
            report.caseDiff.push(`${childPath}: JSON key "${key}" vs 类型字段 "${candidates[0]}"（大小写差异）`);
            walk((jsonValue as any)[key], fields[candidates[0]], childPath, report, interfaces, aliases);
          } else {
            report.missing.push(`${childPath}: 类型 ${t.ifaceName} 未声明该字段（JSON 类型 ${typeof (jsonValue as any)[key]}）`);
          }
        }
      }
      // 类型有、JSON 无
      for (const f of Object.keys(fields)) {
        if (!(f in (jsonValue as object)) && !Object.keys(FIELD_ALIASES).find(k => FIELD_ALIASES[k] === f)) {
          report.typeOnly.push(`${path}.${f}`);
        }
      }
      return;
    }
    // 未知/枚举/原始类型下的对象：跳过
    return;
  }

  // 叶子
  if (t.kind === "iface") {
    report.typeMismatch.push(`${path}: JSON 叶子 ${typeof jsonValue}，类型应为对象 ${tsTypeStr}`);
  }
}

// ---------- main ----------

function getArg(args: string[], name: string, def: string): string {
  const idx = args.indexOf(name);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : def;
}

function main(): void {
  const args = process.argv.slice(2);
  const input = getArg(args, "--input", "D:/develop/DoctorateTs/reference/OpenBachelorS-master/tmp/player_data.json");
  const typesFile = getArg(args, "--types", "D:/develop/DoctorateTs/app/excel/types-playerdata.ts");
  const rootPath = getArg(args, "--root", "");

  console.log(`输入 JSON: ${input}`);
  if (rootPath) console.log(`玩家数据根路径: ${rootPath}`);
  console.log(`类型定义: ${typesFile}`);
  const parsed = JSON.parse(fs.readFileSync(input, "utf-8"));
  const json = rootPath
    ? rootPath.split(".").reduce((acc: unknown, key: string) => (acc as any)?.[key], parsed)
    : parsed;
  if (json === undefined || json === null) {
    console.error(`根路径 "${rootPath}" 不存在`);
    process.exit(1);
  }
  const typesContent = fs.readFileSync(typesFile, "utf-8");
  const interfaces = parseInterfaces(typesContent);
  const aliases = parseTypeAliases(typesContent);
  console.log(`解析类型: ${interfaces.size} 接口, ${aliases.size} 别名/枚举`);

  const report = collectReport();
  walk(json, "PlayerDataModel", "playerData", report, interfaces, aliases);

  console.log(`\n=== 校验结果 ===`);
  console.log(`遍历节点: ${report.totalNodes}`);
  console.log(`缺失字段(JSON 有、类型无): ${report.missing.length}`);
  const agg = aggregateMissing(report.missing);
  console.log(`去重后缺失字段名: ${agg.length}`);
  agg.forEach(m => console.log(`  MISS ${m.field} @ ${m.iface}  (例: ${m.path})`));
  console.log(`\n大小写差异(JSON key vs 类型字段): ${report.caseDiff.length}`);
  report.caseDiff.forEach(m => console.log(`  CASE ${m}`));
  console.log(`\n结构不匹配: ${report.typeMismatch.length}`);
  report.typeMismatch.forEach(m => console.log(`  TYPE ${m}`));
  console.log(`\n类型有、JSON 无(信息性,前 30): ${report.typeOnly.length}`);
  report.typeOnly.slice(0, 30).forEach(m => console.log(`  ONLY ${m}`));
}

main();
