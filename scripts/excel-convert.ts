/**
 * 枚举/键名转换（端口 hotupdate-excel.py 的 convert_enums）：
 * camelCase 首字母小写 + 丢弃 AsNumpy + 单键根解包 + 本地引导枚举 + FBS/cs 唯一值兜底 + null→容器。
 */
import * as fs from "fs";
import * as path from "path";

const ROOT = path.join(__dirname, "..");
const CS_PATH = path.join(ROOT, "reference/com.hypergryph.arknights_2.7.61.cs");
const FBS_SCHEMA_DIR = path.join(ROOT, "scripts/vendor/fbs-schemas");

/**
 * 路径级枚举覆盖：唯一值兜底对多义值（同一数值在多个枚举中重复）弃转，
 * 但这些字段由 CS 类明确类型化（如 roguelike_topic_table.details.*.init.modeId——
 * RoguelikeTopicMode：0 NONE / 1 EASY / 2 NORMAL / 3 HARD / 4 NORML_END / 5 MONTH_TEAM / 6 CHALLENGE）。
 * 路径为 stripIdx 后的 casefold 键（details.rogue_1.init.modeid），* 匹配任意主题。
 */
const PATH_ENUM_OVERRIDES: { pattern: string[]; map: Record<number, string> }[] = [
  {
    // 顶层多键表（Details/Modules...）的路径不含 "details" 段：...rogue_1.init.modeid
    pattern: ["*", "init", "modeid"],
    map: { 0: "NONE", 1: "EASY", 2: "NORMAL", 3: "HARD", 4: "NORML_END", 5: "MONTH_TEAM", 6: "CHALLENGE" },
  },
  {
    // stage_table.stages.<stageId>.stagetype：值 0 在多个 FBS 枚举中同为默认值（多义弃转），
    // 但 0 对 StageType 即 MAIN（官方序列化器省略等于默认值的字段——全部主线关卡缺省，
    // FBO 默认值解码补 0）；按路径强制转 StageType 枚举（对齐 ArknightsGameData）。
    // 注：convert 顶层循环把子表键从路径中去掉（out[k] = convert(v, table)），
    // 故真实路径为 stage_table.<stageId>.stagetype（2 段）。
    pattern: ["*", "stagetype"],
    map: { 0: "MAIN", 1: "DAILY", 2: "TRAINING", 3: "ACTIVITY", 4: "GUIDE", 5: "SUB", 6: "CAMPAIGN", 7: "SPECIAL_STORY", 8: "HANDBOOK_BATTLE", 9: "CLIMB_TOWER", 10: "ENUM" },
  },
];

function pathEnumOverride(pathStr: string): Record<number, string> | undefined {
  const p = pathStr.split(".").slice(1); // 去掉表名
  for (const { pattern, map } of PATH_ENUM_OVERRIDES) {
    if (pattern.length !== p.length) continue;
    let ok = true;
    for (let i = 0; i < pattern.length; i++) {
      if (pattern[i] === "*") continue;
      if (pattern[i] !== p[i]) {
        ok = false;
        break;
      }
    }
    if (ok) return map;
  }
  return undefined;
}

const PY_KEYWORDS = new Set([
  "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del",
  "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in",
  "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
  "with", "yield", "None", "True", "False",
]);

function normKey(k: string): string {
  // 全大写+下划线键（枚举值，如 REST/BATTLE_SHOP/ALCHEMY）保持原样——camelCase 会
  // 破坏枚举键（REST→rEST），导致 tempMap["REST"] 等键查找失败
  if (k && k === k.toUpperCase() && /[A-Z_]/.test(k)) return k;
  let out = k && k[0].toUpperCase() !== k[0] ? k : k.length ? k[0].toLowerCase() + k.slice(1) : k;
  if (out.endsWith("_") && PY_KEYWORDS.has(out.slice(0, -1))) out = out.slice(0, -1);
  return out;
}

function normNode(node: any): any {
  if (Array.isArray(node)) return node.map(normNode);
  if (node && typeof node === "object") {
    const out: any = {};
    for (const [k, v] of Object.entries(node)) {
      if (k.endsWith("AsNumpy")) continue;
      out[normKey(k)] = normNode(v);
    }
    return out;
  }
  return node;
}

function stripIdx(p: string): string {
  return p.replace(/\[\d+\]/g, "");
}

// FBS 枚举 + cs 枚举 → 全部 value→name
function loadEnumMaps(): Map<number, string | null> {
  const unique = new Map<number, string | null>();
  const add = (v: number, name: string) => {
    const cur = unique.get(v);
    if (cur !== undefined && cur !== name) unique.set(v, null); // 多义 → 弃
    else if (cur === undefined) unique.set(v, name);
  };
  // FBS schema JSON 中的枚举（数据格式的权威枚举来源）
  if (fs.existsSync(FBS_SCHEMA_DIR)) {
    for (const f of fs.readdirSync(FBS_SCHEMA_DIR).filter((x) => x.endsWith(".json"))) {
      try {
        const schema = JSON.parse(fs.readFileSync(path.join(FBS_SCHEMA_DIR, f), "utf-8"));
        for (const vmap of Object.values(schema.enums || {})) {
          for (const [name, val] of Object.entries(vmap as Record<string, number>)) add(val, name);
        }
      } catch { /* 跳过 */ }
    }
  }
  // cs 枚举：**仅补充 FBS 已有值的别名**，不引入新值——
  // 修复：CS 含大量与 excel 数据无关的枚举（LogChannel EDITOR_PROFILE=151/168、
  // 账号状态 AccountSuspended=128、NEITHER_FULL_NOR_EMPTY=-7 等），直接并入会把
  // 数值型数据字段（blackboard.value、playerApMap、characterExpMap、坐标等）错误
  // 转成枚举字符串（技能/AP 上限/经验曲线被破坏）。仅当值已存在于 FBS 枚举时才可能
  // 是数据枚举，CS 同值提供补充命名；CS 独有值一律不转。
  if (fs.existsSync(CS_PATH)) {
    const cs = fs.readFileSync(CS_PATH, "utf-8");
    const re = /public enum (Torappu\.[A-Za-z0-9_.]+)\s*:[^\{]*\{([^}]*)\}/g;
    for (const m of cs.matchAll(re)) {
      const body = m[2];
      const vals = body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)/g);
      for (const vm of vals) {
        const v = parseInt(vm[2]);
        // 仅补充 FBS 已有值的名字（含多义置 null 语义）
        if (unique.has(v)) add(v, vm[1]);
      }
    }
  }
  return unique;
}

export interface SchemaCompletion {
  fields: string[]; // FBS 原始字段名（PascalCase），归一化后补充 null
  applyTo: "root" | "values"; // values = SimpleKVTable 解包后的每个记录对象
  schema?: any; // 完整 schema（递归补全嵌套层用）
  recordType?: string; // 记录类型的 clz 名
}

export function convertTable(
  dec: any,
  loc: any, // 本地既有文件（枚举学习种子），可 null
  table: string,
  completion?: SchemaCompletion,
): any {
  const norm = (d: any): any => {
    if (Array.isArray(d)) return d.map(norm);
    if (d && typeof d === "object") {
      const out: any = {};
      for (const [k, v] of Object.entries(d)) {
        if (k.endsWith("AsNumpy")) continue;
        out[normKey(k)] = norm(v);
      }
      return out;
    }
    return d;
  };
  let decN = norm(dec);
  let locN = loc ? norm(loc) : null;

  // 单键根解包
  const unwrap = (d: any, l: any): [any, any] => {
    if (d && typeof d === "object" && !Array.isArray(d) && Object.keys(d).length === 1) {
      if (l && typeof l === "object" && !Array.isArray(l) && Object.keys(l).length !== 1) {
        return [Object.values(d)[0], l];
      }
      if (!l) return [Object.values(d)[0], null];
    }
    return [d, l];
  };
  [decN, locN] = unwrap(decN, locN);

  const valueMap = new Map<string, Map<number, string>>(); // 路径 → {value: name}
  const renameMap = new Map<string, string>(); // dec 键(casefold) → 本地键
  const emptyMap = new Map<string, "list" | "dict">(); // 路径 → 容器类型
  const normk2 = (k: string) => k.toLowerCase().replace(/_/g, "");
  // FBS 枚举值→名字集合（loc 学习过滤依据：loc 字符串必须是对应值的 FBS 枚举名，
  // 否则视为被 CS 枚举污染的脏数据——如 playerApMap 128→"AccountSuspended"、经验
  // 曲线 151→"EDITOR_PROFILE"、blackboard -7→"NEITHER_FULL_NOR_EMPTY"）
  const fbsNames = new Map<number, Set<string>>();
  if (fs.existsSync(FBS_SCHEMA_DIR)) {
    for (const f of fs.readdirSync(FBS_SCHEMA_DIR).filter((x) => x.endsWith(".json"))) {
      try {
        const schema = JSON.parse(fs.readFileSync(path.join(FBS_SCHEMA_DIR, f), "utf-8"));
        for (const vmap of Object.values(schema.enums || {})) {
          for (const [name, val] of Object.entries(vmap as Record<string, number>)) {
            if (!fbsNames.has(val)) fbsNames.set(val, new Set());
            fbsNames.get(val)!.add(name);
          }
        }
      } catch { /* 跳过 */ }
    }
  }

  if (locN && typeof locN === "object") {
    // 修复：rename 学习不再传播"坏 camelCase"键（首字母小写+其余大写，如 rELIC/
    // dEFAULT/tYPE_ACT3D0/cOLLECTION——旧管线 lowerFirst 全大写键的产物）。此类键
    // 若被学进 renameMap，每次重生成都把解码的规范 PascalCase 键（Relic→relic、
    // Default→default）污染回坏键，且 rlv2/活动代码读取被迫适配坏键。
    // 例外清单：lMTGSID 等官方 JSON 实际键（小写 l 前缀，代码/文档依赖，见 gacha_table.ts）。
    const BROKEN_KEY_RE = /^[a-z][A-Z]/;
    const RENAME_ALLOWLIST = new Set(["lmtgsid"]);
    const walkPairs = (d: any, l: any, p: string) => {
      if (d && typeof d === "object" && !Array.isArray(d) && l && typeof l === "object" && !Array.isArray(l)) {
        const lm = new Map<string, string>();
        for (const k of Object.keys(l)) lm.set(k.toLowerCase(), k);
        const dm = new Map<string, string>();
        for (const k of Object.keys(d)) dm.set(k.toLowerCase(), k);
        const done = new Set<string>();
        for (const lk of [...lm.keys()].sort()) {
          if (dm.has(lk)) {
            const dk = dm.get(lk)!, lkv = lm.get(lk)!;
            if (
              dk !== lkv &&
              (!BROKEN_KEY_RE.test(lkv) || RENAME_ALLOWLIST.has(lkv.toLowerCase()))
            ) {
              renameMap.set(dk.toLowerCase(), lkv);
            }
            walkPairs(d[dk], l[lkv], `${p}.${dk.toLowerCase()}`);
            done.add(lk);
          }
        }
        for (const lk of [...lm.keys()].sort()) {
          if (done.has(lk) || !lm.get(lk)!.includes("_")) continue;
          for (const dk of [...dm.keys()]) {
            if (normk2(dk) === normk2(lk)) {
              // 同第一个循环：坏 camelCase 键不学习（rELIC/dEFAULT/tYPE_ACT3D0 等）
              const lkv = lm.get(lk)!;
              if (
                dk !== lkv &&
                (!BROKEN_KEY_RE.test(lkv) || RENAME_ALLOWLIST.has(lkv.toLowerCase()))
              ) {
                renameMap.set(dk.toLowerCase(), lkv);
              }
              walkPairs(d[dm.get(dk)!], l[lkv], `${p}.${dm.get(dk)!.toLowerCase()}`);
              break;
            }
          }
        }
      } else if (Array.isArray(d) && Array.isArray(l)) {
        for (let i = 0; i < Math.min(d.length, l.length); i++) walkPairs(d[i], l[i], `${p}[${i}]`);
      } else if (d === null && (Array.isArray(l) || (l && typeof l === "object"))) {
        emptyMap.set(stripIdx(p), Array.isArray(l) ? "list" : "dict");
      } else if (typeof d === "number" && Number.isInteger(d) && typeof l === "string") {
        // 修复：loc 学习只接受"值是 FBS 枚举值 且 loc 字符串是该值的 FBS 枚举名"——
        // 本地旧数据可能含被 CS 枚举污染的错误字符串（playerApMap 128→
        // "AccountSuspended"、blackboard -7→"NEITHER_FULL_NOR_EMPTY"、经验曲线
        // 151→"EDITOR_PROFILE"），不匹配 FBS 枚举名则判定为污染，不学习
        //（否则 valueMap 优先于 uniqueName 持续输出污染）
        if (!fbsNames.get(d)?.has(l)) return;
        if (!valueMap.has(stripIdx(p))) valueMap.set(stripIdx(p), new Map());
        valueMap.get(stripIdx(p))!.set(d, l);
      }
    };
    const locKeys = Object.keys(locN).slice(0, 2000);
    for (const k of locKeys) walkPairs(decN?.[k] ?? {}, locN[k], table);
  }

  // 通用重命名（Undefinable）
  renameMap.set("mdefined", "m_defined");
  renameMap.set("mvalue", "m_value");
  const uniqueName = loadEnumMaps();

  const convert = (d: any, p: string): any => {
    if (d && typeof d === "object" && !Array.isArray(d)) {
      const out: any = {};
      for (const [k, v] of Object.entries(d)) {
        // 全大写+下划线键（枚举值，REST/BATTLE_SHOP 等）跳过 renameMap——本地脏种子
        // （此前 camelCase 损坏的 rEST）会污染 renameMap 导致枚举键二次破坏
        const isEnumKey = k && k === k.toUpperCase() && /[A-Z_]/.test(k);
        const nk = isEnumKey ? k : (renameMap.get(k.toLowerCase()) ?? k);
        out[nk] = convert(v, `${p}.${k.toLowerCase()}`);
      }
      return out;
    }
    if (Array.isArray(d)) return d.map((x, i) => convert(x, `${p}[${i}]`));
    if (d === null) {
      const et = emptyMap.get(stripIdx(p));
      if (et === "list") return [];
      if (et === "dict") return {};
      return null;
    }
    if (typeof d === "number" && Number.isInteger(d)) {
      const vm = valueMap.get(stripIdx(p));
      if (vm && vm.has(d)) return vm.get(d)!;
      // 路径级枚举覆盖：唯一值兜底对多义值（同一数值在多个枚举中重复）弃转，
      // 但这些字段由 CS 类明确类型化（如 roguelike_topic_table.details.*.init.modeId）
      const pe = pathEnumOverride(stripIdx(p));
      if (pe && d in pe) return pe[d];
      const u = uniqueName.get(d);
      if (u !== undefined && u !== null) return u;
    }
    return d;
  };

  if (decN && typeof decN === "object" && !Array.isArray(decN)) {
    const out: any = {};
    for (const [k, v] of Object.entries(decN)) out[k] = convert(v, table);
    // schema 字段补齐：与 ArknightsGameData/OpenArknightsFBS 对齐（缺省字段补 null）
    if (completion) completeFields(out, completion, renameMap);
    return out;
  }
  const result = convert(decN, table);
  if (completion) completeFields(result, completion, renameMap);
  return result;
}

function completeFields(
  result: any,
  completion: SchemaCompletion,
  renameMap: Map<string, string>,
): void {
  const lowerFirst = (s: string) => (s ? s[0].toLowerCase() + s.slice(1) : s);
  const targets: any[] =
    completion.applyTo === "values" &&
    result && typeof result === "object" && !Array.isArray(result)
      ? Object.values(result)
      : [result];
  for (const obj of targets) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) continue;
    for (const f of completion.fields) {
      const nk = renameMap.get(f.toLowerCase()) ?? lowerFirst(f);
      if (!(nk in obj)) obj[nk] = null;
    }
    // 递归补全嵌套层（与 OpenArknightsFBS 结构对齐）
    if (completion.schema && completion.recordType) {
      completeRecursive(obj, completion.recordType, completion.schema, renameMap);
    }
  }
}

/** 递归按 schema 类型补全缺失字段（null） */
function completeRecursive(
  obj: any,
  typeName: string,
  schema: any,
  renameMap: Map<string, string>,
): void {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return;
  const fields = schema.tables?.[typeName];
  if (!fields) return;
  const lowerFirst = (s: string) => (s ? s[0].toLowerCase() + s.slice(1) : s);
  for (const f of fields) {
    const nk = renameMap.get(f.name.toLowerCase()) ?? lowerFirst(f.name);
    if (!(nk in obj)) obj[nk] = null;
    const val = obj[nk];
    if (val === null || val === undefined) continue;
    const child = childTypeOf(f.type, schema);
    if (!child) continue;
    const dict = isDictContainer(f.type);
    // 修复：dict/kvp 容器（如 Missions = vec:dict__string__clz_Torappu_MissionData）的
    // **值**才是记录对象——原实现把整个 dict 当单条记录递归补字段，导致记录字段名以
    // null 键污染 dict 本身（periodicalRewards/missions/stages/groups 等表尾部出现
    // groupId/id/type/... = null；2026-08-14 每日刷新崩溃根因，且与 ArknightsGameData
    // 结构不符）。dict 类型统一逐值下钻。
    if (Array.isArray(val)) {
      for (const item of val) {
        if (dict && item && typeof item === "object" && !Array.isArray(item)) {
          for (const rec of Object.values(item)) {
            completeRecursive(rec, child, schema, renameMap);
          }
        } else {
          completeRecursive(item, child, schema, renameMap);
        }
      }
    } else if (typeof val === "object") {
      if (dict) {
        for (const rec of Object.values(val)) {
          completeRecursive(rec, child, schema, renameMap);
        }
      } else {
        completeRecursive(val, child, schema, renameMap);
      }
    }
  }
}

/** 字段类型是否为 dict/kvp 容器（vec: 前缀剥掉后判断） */
function isDictContainer(type: string): boolean {
  let t = type;
  if (t.startsWith("vec:")) t = t.slice(4);
  return t.startsWith("dict__") || t.startsWith("kvp__");
}

/** 字段类型 → 子对象类型（dict__K__V → V 类型；vec:X → X） */
function childTypeOf(type: string, schema: any): string | undefined {
  let t = type;
  if (t.startsWith("vec:")) t = t.slice(4);
  if (t.startsWith("dict__") || t.startsWith("kvp__")) {
    // dict__K__V / kvp__K__V：Value 字段类型
    const parts = t.split("__");
    const vt = parts[parts.length - 1];
    return schema.tables?.[vt] ? vt : undefined;
  }
  if (t.startsWith("clz_") && schema.tables?.[t]) return t;
  return undefined;
}
