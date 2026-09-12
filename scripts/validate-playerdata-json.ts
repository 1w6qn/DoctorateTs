import * as fs from "fs";
import * as path from "path";
import { isJsonObject, type JsonValue } from "@excel/json-value";

/**
 * player_data.json 类型覆盖校验
 *
 * 用官服真实玩家存档校验 app/game/excel/types-playerdata.ts 的 PlayerDataModel
 * 类型闭包是否完整描述真实数据结构（"toJson 输出与原输入一致"）。
 *
 * 用法: pnpm exec tsx scripts/validate-playerdata-json.ts [--input <json>] [--types <ts>] [--root <path>]
 * 默认输入: reference/OpenBachelorS-master/tmp/player_data.json
 * 默认类型: app/game/excel/types-playerdata.ts
 * --root: JSON 内玩家数据根路径（如官服账号文件 test.json 的 "user"）
 */

// ---------- 类型定义文件解析 ----------

interface FieldMap {
  [fieldName: string]: string; // 字段名 -> TS 类型字符串
}

/** 解析 export interface X { ... } 块（字段类型可含内部 ; 的对象字面量，按行解析） */
function parseInterfaces(content: string): Map<string, FieldMap> {
  const out = new Map<string, FieldMap>();
  const re = /export interface (\w+) \{([\s\S]*?)\n\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const name = m[1];
    const fields: FieldMap = {};
    const body = m[2];
    for (const line of body.split("\n")) {
      const fm = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\??:\s*(.+?);?\s*$/);
      if (!fm) continue;
      let type = fm[2].trim();
      if (type.endsWith(";")) type = type.slice(0, -1).trim();
      fields[fm[1]] = type;
    }
    out.set(name, fields);
  }
  return out;
}

/** 解析 export type X = ...;（枚举/别名；单行，允许内部 ;） */
function parseTypeAliases(content: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of content.split("\n")) {
    const m = line.match(/^export type (\w+) = (.*);\s*$/);
    if (m) out.set(m[1], m[2].trim());
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
  kind: "index" | "array" | "iface" | "enum" | "primitive" | "objliteral" | "unknown";
  valueType?: string; // index/array
  ifaceName?: string;
  literal?: string; // objliteral：对象字面量类型体 { a: X; b: Y }；enum：已解析的字面量联合
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

  // 索引签名 { [key: K]: V }（索引名任意，如 [typeKey:]/[roomType:]）
  const indexMatch = t.match(/^\{\s*\[[a-zA-Z_][a-zA-Z0-9_]*:\s*[^\]]+\]:\s*(.+)\s*\}$/);
  if (indexMatch) return { kind: "index", valueType: indexMatch[1].trim() };

  // 对象字面量 { a: X; b: Y; ... }（服务端适配层生成的具名属性类型）
  const objMatch = t.match(/^\{\s*([\s\S]+)\s*\}$/);
  if (objMatch && objMatch[1].includes(":")) {
    return { kind: "objliteral", literal: objMatch[1] };
  }

  // 数组 X[]
  const arrayMatch = t.match(/^(.+)\[\]$/);
  if (arrayMatch) return { kind: "array", valueType: arrayMatch[1].trim() };

  // 枚举字面量联合 "A" | "B"（多行内联）
  if (t.includes('"') && t.includes("|")) return { kind: "enum", literal: t };

  // 基础类型
  if (/^(string|number|boolean|object|any|Date)$/.test(t)) return { kind: "primitive" };

  // 类型别名（枚举/索引/对象字面量别名）
  if (aliases.has(t)) {
    if (seen.has(t)) return { kind: "unknown" };
    seen.add(t);
    const aliasTarget = aliases.get(t)!;
    // 枚举别名（字面量联合或 string 退化）
    if (aliasTarget === "string" || (aliasTarget.includes('"') && aliasTarget.includes("|"))) {
      return { kind: "enum", literal: aliasTarget === "string" ? "string" : aliasTarget };
    }
    // 递归解析其余结构（索引签名/对象字面量）
    return classifyType(aliasTarget, interfaces, aliases, seen);
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
  scalarMismatch: string[]; // 叶子标量类型不匹配（number/string/boolean/枚举字面量）
  untyped: string[]; // 命中 object/unknown 类型的路径（信息性，提示需补具名 override）
  typeOnly: string[]; // 类型有、JSON 无（信息性）
  totalNodes: number;
}

function collectReport(): Report {
  return { missing: [], caseDiff: [], typeMismatch: [], scalarMismatch: [], untyped: [], typeOnly: [], totalNodes: 0 };
}

/** 已知标量差异例外（官服线格式 vs 运行时格式的文档化分歧），按路径正则匹配 */
const SCALAR_EXCEPTIONS: { re: RegExp; note: string }[] = [
  // 官服 flags 值为 '1' 字符串，运行时写入 number——两侧都是合法序列化
  { re: /\.flags\.[^.]+$/, note: "flags 值：官服 '1' 字符串 vs 运行时 number" },
];

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

/** 命中例外路径则跳过标量差异报告 */
function isScalarException(path: string): boolean {
  return SCALAR_EXCEPTIONS.some(e => e.re.test(path));
}

/** 叶子标量类型比对：number/string/boolean/枚举字面量联合/单值字面量；ctx.iface 为字段所属接口 */
function checkScalar(jsonValue: JsonValue, tsTypeStr: string, path: string, report: Report, iface: string): void {
  if (jsonValue === null || jsonValue === undefined) return;
  const t = tsTypeStr.trim().replace(/\|\s*(null|undefined)\s*/g, "").trim();
  if (!t || isScalarException(path)) return;
  const jt = typeof jsonValue;
  const field = path.split(".").pop() ?? "";
  const loc = `${iface}.${field}`;
  // 基础类型联合（number | string 等：服务端序列化两态并存）
  if (t.includes("|") && /^(number|string|boolean)(\s*\|\s*(number|string|boolean))+$/.test(t)) {
    const allowed = new Set(t.split("|").map(s => s.trim()));
    if (!allowed.has(jt)) {
      report.scalarMismatch.push(`${loc}@${path}: 期望联合 [${[...allowed].join("|")}]，实际 ${jt} ${JSON.stringify(jsonValue).slice(0, 30)}`);
    }
    return;
  }
  // 枚举字面量联合 "A" | "B" | ...
  if (t.includes('"') && t.includes("|")) {
    const vals = new Set(t.split("|").map(s => s.trim().replace(/"/g, "")));
    if (typeof jsonValue !== "string" || !vals.has(jsonValue)) {
      report.scalarMismatch.push(`${loc}@${path}: 期望枚举 [${[...vals].join("|")}]，实际 ${jt} ${JSON.stringify(jsonValue).slice(0, 30)}`);
    }
    return;
  }
  const lit = t.match(/^"(.+)"$/);
  if (lit) {
    if (jsonValue !== lit[1]) report.scalarMismatch.push(`${loc}@${path}: 期望 "${lit[1]}"，实际 ${jt} ${JSON.stringify(jsonValue).slice(0, 30)}`);
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
      for (let i = 0; i < jsonValue.length; i++) {
        walk(jsonValue[i], t.valueType!, `${path}[${i}]`, report, interfaces, aliases, ctx, seen);
      }
    } else if (t.kind === "unknown" || t.kind === "primitive") {
      // 未知/基础类型下的数组：类型定义不约束，记录未覆盖路径
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
      // 对象字面量类型 { a: X; b: Y; ... }（按分号切分，不支持嵌套字面量）
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
        if (key in fields) {
          walk(jsonValue[key], fields[key], childPath, report, interfaces, aliases, ctx, seen);
        } else {
          report.missing.push(`${childPath}: 类型对象字面量未声明该字段（JSON 类型 ${typeof jsonValue[key]}）`);
        }
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
        } else if (key in FIELD_ALIASES && FIELD_ALIASES[key] in fields) {
          // 已知命名差异：用 C# 字段名继续穿透检查
          walk(jsonValue[key], fields[FIELD_ALIASES[key]], childPath, report, interfaces, aliases, childCtx, seen);
        } else {
          // 大小写不敏感建议
          const lower = key.toLowerCase();
          const candidates = Object.keys(fields).filter(f => f.toLowerCase() === lower);
          if (candidates.length > 0) {
            report.caseDiff.push(`${childPath}: JSON key "${key}" vs 类型字段 "${candidates[0]}"（大小写差异）`);
            walk(jsonValue[key], fields[candidates[0]], childPath, report, interfaces, aliases, childCtx, seen);
          } else {
            report.missing.push(`${childPath}: 类型 ${t.ifaceName} 未声明该字段（JSON 类型 ${typeof jsonValue[key]}）`);
          }
        }
      }
      // 类型有、JSON 无
      for (const f of Object.keys(fields)) {
        if (!(f in jsonValue) && !Object.keys(FIELD_ALIASES).find(k => FIELD_ALIASES[k] === f)) {
          report.typeOnly.push(`${path}.${f}`);
        }
      }
      return;
    }
    // 未知/枚举/原始类型下的对象：类型定义不约束，记录未覆盖路径（object/unknown 盲区）
    report.untyped.push(path);
    return;
  }

  // 叶子：对象类型期望遇标量 → 结构不匹配；基础/枚举/字面量 → 标量比对
  if (t.kind === "iface") {
    report.typeMismatch.push(`${path}: JSON 叶子 ${typeof jsonValue}，类型应为对象 ${tsTypeStr}`);
  } else if (t.kind === "primitive" || t.kind === "enum") {
    const effective = t.kind === "enum" ? (t.literal === "string" ? "string" : t.literal ?? tsTypeStr) : tsTypeStr;
    checkScalar(jsonValue, effective, path, report, ctx.iface);
  }
}

// ---------- main ----------

function getArg(args: string[], name: string, def: string): string {
  const idx = args.indexOf(name);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : def;
}

export function main(argv: string[] = []): void {
  const args = argv;
  const input = getArg(args, "--input", "D:/develop/DoctorateTs/reference/OpenBachelorS-master/tmp/player_data.json");
  const typesFile = getArg(args, "--types", "D:/develop/DoctorateTs/app/game/excel/types-playerdata.ts");
  const rootPath = getArg(args, "--root", "");

  console.log(`输入 JSON: ${input}`);
  if (rootPath) console.log(`玩家数据根路径: ${rootPath}`);
  console.log(`类型定义: ${typesFile}`);
  const parsed: JsonValue = JSON.parse(fs.readFileSync(input, "utf-8"));
  const json: JsonValue | undefined = rootPath
    ? rootPath
        .split(".")
        .reduce<JsonValue | undefined>(
          (acc, key) => (acc !== undefined && isJsonObject(acc) ? acc[key] : undefined),
          parsed,
        )
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
  walk(json, "PlayerDataModel", "playerData", report, interfaces, aliases, { iface: "PlayerDataModel" });

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

  console.log(`\n标量不匹配(number/string/boolean/枚举, 前 40 聚合): ${report.scalarMismatch.length}`);
  const scalarAgg = new Map<string, number>();
  report.scalarMismatch.forEach(m => {
    // 格式: Iface.field@path: 期望 X，实际 Y
    const key = m.replace(/@.*$/, "");
    scalarAgg.set(key, (scalarAgg.get(key) ?? 0) + 1);
  });
  [...scalarAgg.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40).forEach(([k, v]) => {
    console.log(`  SCALAR x${v} ${k}`);
  });

  if (args.includes("--full")) {
    const dump = [
      `=== SCALAR ALL (${report.scalarMismatch.length}) ===`,
      ...report.scalarMismatch,
      `=== MISSING ALL (${report.missing.length}) ===`,
      ...report.missing,
      `=== UNTYPED ALL (${report.untyped.length}) ===`,
      ...report.untyped,
    ].join("\n");
    const outFile = args[args.indexOf("--full") + 1] ?? "tmp/_audit-full.txt";
    fs.writeFileSync(outFile, dump);
    console.log(`完整报告写入: ${outFile}`);
  }

  console.log(`\n未覆盖路径(object/unknown 盲区, 前 30): ${report.untyped.length}`);
  report.untyped.slice(0, 30).forEach(m => console.log(`  UNTYPED ${m}`));
  console.log(`\n类型有、JSON 无(信息性,前 30): ${report.typeOnly.length}`);
  report.typeOnly.slice(0, 30).forEach(m => console.log(`  ONLY ${m}`));
}

// 直连执行入口（被 admin-cli tools 导入时不自动运行）
if (typeof require !== "undefined" && require.main === module) {
  main();
}
