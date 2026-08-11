import * as fs from "fs";
import * as path from "path";
import type { ClassDef } from "./playerdata-parser";
import { extractTypeNames } from "./playerdata-parser";
import { EXCEL_TABLE_ROOTS } from "./excel-server-adapt";

/**
 * excel 类型字段名与 JSON 实际键对照修正
 *
 * CS 反编译字段名与 data/excel/*.json 实际键存在大小写差异时（如 CS 类
 * GachaPoolClientData.LMTGSID vs JSON 键 lMTGSID），以 JSON 为运行时数据源
 * 为准——字段名改与 JSON 键一致。否则代码按 CS 名读取恒 undefined（历史坑：
 * 限定池寻访数据契约凭证从未入账，见 lmtgsid-case-divergence）。
 *
 * 对照方式：按表根类（EXCEL_TABLE_ROOTS）加载 JSON，沿类闭包字段递归定位
 * 每个类对应的 JSON 样本对象，逐字段大小写不敏感比对——仅大小写不同的键按
 * JSON 键重命名（不引入 JSON 缺失的字段、不改写类型）。
 */

/** 从 JSON 值提取"类样本对象"：数组取首元素；dict（值全为对象）取首值；对象取自身 */
function pickSample(val: unknown, cls?: ClassDef): Record<string, unknown> | undefined {
  if (Array.isArray(val)) return pickSample(val[0], cls);
  if (val && typeof val === "object") {
    const keys = Object.keys(val as object);
    if (cls && keys.length > 0) {
      const fieldNames = new Set(cls.fields.map((f) => f.name.toLowerCase()));
      // 键与类字段名有交集 → 该对象就是类实例（避免把全对象值字段误判为 dict）
      if (keys.some((k) => fieldNames.has(k.toLowerCase()))) {
        return val as Record<string, unknown>;
      }
    }
    const vals = Object.values(val as object);
    if (vals.length > 0 && vals.every((v) => v && typeof v === "object")) {
      // 全对象值 → dict（如 { charId: CharacterData }）→ 首值
      return pickSample(vals[0], cls);
    }
    return val as Record<string, unknown>;
  }
  return undefined;
}

/** 沿类字段递归定位子类的 JSON 样本（用原始字段名大小写不敏感匹配 JSON 键） */
function walkClass(
  className: string,
  json: Record<string, unknown>,
  classMap: Map<string, ClassDef>,
  samples: Map<string, Record<string, unknown>>,
): void {
  const cls = classMap.get(className);
  if (!cls) return;
  for (const f of cls.fields) {
    const key = Object.keys(json).find(
      (k) => k === f.name || k.toLowerCase() === f.name.toLowerCase(),
    );
    if (!key) continue;
    const val = json[key];
    for (const ref of extractTypeNames(f.rawType)) {
      const sub = classMap.get(ref);
      if (!sub || sub === cls || samples.has(ref)) continue;
      const sample = pickSample(val, sub);
      if (sample) {
        samples.set(ref, sample);
        walkClass(ref, sample, classMap, samples);
      }
    }
  }
}

/**
 * 修正类字段名与 JSON 实际键的大小写差异（原地修改字段名，返回同一数组）
 * @param classes - 已应用 excel 协议适配的类定义
 * @returns 对照修正后的类定义
 */
export function reconcileExcelJsonKeys(classes: ClassDef[]): ClassDef[] {
  const classMap = new Map(classes.map((c) => [c.name, c]));
  const samples = new Map<string, Record<string, unknown>>();
  const dataDir = path.join(__dirname, "../data/excel");

  for (const [table, rootRef] of Object.entries(EXCEL_TABLE_ROOTS)) {
    const file = path.join(dataDir, `${table}.json`);
    if (!fs.existsSync(file)) continue;
    let json: unknown;
    try {
      json = JSON.parse(fs.readFileSync(file, "utf-8"));
    } catch {
      continue;
    }
    if (!json || typeof json !== "object") continue;
    const roots: [string, unknown][] =
      typeof rootRef === "string"
        ? [[rootRef, json]]
        : Object.entries(rootRef).map(([k, cls]) => [cls, (json as any)[k]]);
    for (const [rootClass, rootJson] of roots) {
      const rootCls = classMap.get(rootClass);
      const sample = pickSample(rootJson, rootCls);
      if (sample) {
        samples.set(rootClass, sample);
        walkClass(rootClass, sample, classMap, samples);
      }
    }
  }

  // 重命名：字段与 JSON 键仅大小写不同 → 用 JSON 实际键（大小写敏感读取）
  let renamed = 0;
  for (const cls of classes) {
    const sample = samples.get(cls.name);
    if (!sample) continue;
    const jsonKeys = Object.keys(sample);
    for (const f of cls.fields) {
      const jsonKey = jsonKeys.find(
        (k) => k !== f.name && k.toLowerCase() === f.name.toLowerCase(),
      );
      if (jsonKey) {
        f.name = jsonKey;
        renamed++;
      }
    }
  }
  if (renamed > 0) {
    console.log(`JSON 键对照修正: ${renamed} 个字段名按 JSON 实际键重命名`);
  }
  return classes;
}
