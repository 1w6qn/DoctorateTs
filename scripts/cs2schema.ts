/**
 * 从 C# 反编译签名文件重生成 FBO schema JSON（字段与 vtable slot 由 C# 字段序推导）
 *
 * 原理：C# 运行时模型字段序 = 客户端 .fbs 声明序 = FBO vtable slot 序（slot = 4 + 2×字段序）。
 * 用途：官方客户端更新后，`scripts/vendor/fbs-schemas/*.json` 会与新版数据错位——字段一旦
 * 插入到表结构中部，其后所有字段的 slot 全体位移，解码会读到错误字段（典型症状：向量长度
 * 变成天文数字、`JSON.stringify` 触发 V8 "Invalid string length"、或解码 OOM）。
 * 例：2.7.71 的 `Torappu.ItemData` 在 `classifyType` 前新增 `reslockStatus`/`canReslock`，
 * 旧 schema 的 `StageDropList#30` 起全部前移 4 字节 → 实测向量长度 8192 / 196608。
 *
 * 用法:
 *   pnpm exec tsx scripts/cs2schema.ts --check               # 与现有 schema 逐字段比对（回归验证）
 *   pnpm exec tsx scripts/cs2schema.ts --write --table item_table
 *   pnpm exec tsx scripts/cs2schema.ts --write               # 全量重写（谨慎：改动即生效）
 * 输入：reference/com.hypergryph.arknights_<版本>.cs（默认取最新），可用 --cs 指定
 */
import * as fs from "fs";
import * as path from "path";

const ROOT = path.join(__dirname, "..");
const SCHEMA_DIR = path.join(ROOT, "scripts/vendor/fbs-schemas");
const args = process.argv.slice(2);
const doCheck = args.includes("--check");
const doWrite = args.includes("--write");
const tableArg = args.includes("--table") ? args[args.indexOf("--table") + 1] : undefined;
const diffLimit = args.includes("--diff") ? Number(args[args.indexOf("--diff") + 1]) : 0;

/** 解析 object 路径的 C# 签名文件：类 → 有序字段表；枚举名集合 */
function resolveCsFile(): string {
  const i = args.indexOf("--cs");
  if (i >= 0 && args[i + 1]) return args[i + 1];
  const dir = path.join(ROOT, "reference");
  const cands = fs
    .readdirSync(dir)
    .filter((f) => /^com\.hypergryph\.arknights_.+\.cs$/.test(f))
    .sort();
  if (!cands.length) throw new Error("reference/ 下找不到 com.hypergryph.arknights_*.cs");
  return path.join(dir, cands[cands.length - 1]);
}

interface CsField {
  type: string;
  name: string;
}

function parseCs(file: string): { classes: Map<string, CsField[]>; enums: Set<string> } {
  const classes = new Map<string, CsField[]>();
  const enums = new Set<string>();
  const lines = fs.readFileSync(file, "utf-8").split(/\r?\n/);
  const declRe = /^public (?:sealed |abstract |static )?(class|struct|enum) ([\w.`]+)/;
  for (let i = 0; i < lines.length; i++) {
    const m = declRe.exec(lines[i]);
    if (!m) continue;
    const kind = m[1];
    const name = m[2];
    if (kind === "enum") {
      enums.add(name);
      continue;
    }
    const fields: CsField[] = [];
    let inFields = false;
    for (let j = i + 1; j < lines.length; j++) {
      const line = lines[j];
      if (line.startsWith("}")) break;
      if (line.includes("// Fields")) { inFields = true; continue; }
      if (line.includes("// Methods")) break;
      if (!inFields) continue;
      // 仅实例字段（跳过 static/const/readonly 修饰）
      const fm = /^\tpublic (?!static )(?:readonly )?(.+?) ([\w@]+);/.exec(line);
      if (fm) fields.push({ type: fm[1].trim(), name: fm[2] });
    }
    classes.set(name, fields);
  }
  return { classes, enums };
}

const SCALAR: Record<string, string> = {
  "System.String": "string",
  "System.Boolean": "bool",
  "System.Int32": "int",
  "System.Int64": "long",
  "System.Single": "float",
  "System.Double": "double",
  "System.Int16": "int",
  "System.Byte": "int",
  "System.SByte": "int",
  "System.UInt16": "int",
  "System.UInt32": "int",
};

const clzKey = (full: string) => "clz_" + full.replace(/\./g, "_");

/**
 * 线上（fbs）类型覆盖表
 *
 * C# 运行时模型与线上 fbs 并非一一对应：
 * - 反作弊混淆包装（`CodeStage.AntiCheat.ObscuredTypes.*`）在线上就是普通标量
 *   （旧 schema 里 AttributesData.MaxHp 等写作 `enum`，即 i32）
 * - `Torappu.Blackboard` 运行时是包装类，线上是 `DataPair` 的**向量**
 */
const WIRE_OVERRIDE: Record<string, string> = {
  "CodeStage.AntiCheat.ObscuredTypes.ObscuredInt": "enum",
  "CodeStage.AntiCheat.ObscuredTypes.ObscuredShort": "enum",
  "CodeStage.AntiCheat.ObscuredTypes.ObscuredSByte": "enum",
  "CodeStage.AntiCheat.ObscuredTypes.ObscuredLong": "long",
  "CodeStage.AntiCheat.ObscuredTypes.ObscuredFloat": "float",
  "CodeStage.AntiCheat.ObscuredTypes.ObscuredDouble": "double",
  "CodeStage.AntiCheat.ObscuredTypes.ObscuredBool": "bool",
  "CodeStage.AntiCheat.ObscuredTypes.ObscuredString": "string",
  "Torappu.Blackboard": "vec:clz_Torappu_Blackboard_DataPair",
};

function main() {
  const csFile = resolveCsFile();
  const { classes, enums } = parseCs(csFile);
  console.log(`解析 ${path.basename(csFile)}：${classes.size} 个类 / ${enums.size} 个枚举`);

  /** C# 类型 → schema 类型 token */
  /** 按尖括号深度切分泛型实参（避免嵌套泛型被贪婪正则误拆） */
  function splitGenericArgs(inner: string): string[] {
    const out: string[] = [];
    let depth = 0;
    let cur = "";
    for (const ch of inner) {
      if (ch === "<") depth++;
      else if (ch === ">") depth--;
      if (ch === "," && depth === 0) {
        out.push(cur.trim());
        cur = "";
        continue;
      }
      cur += ch;
    }
    if (cur.trim()) out.push(cur.trim());
    return out;
  }
  function genericInner(t: string): string | null {
    const i = t.indexOf("<");
    if (i < 0 || !t.endsWith(">")) return null;
    return t.slice(i + 1, -1);
  }

  /**
   * 字段级类型映射
   *
   * 关键约定（对齐既有 vendored schema）：**字典字段带 `vec:` 前缀**
   * （FBO 的 map = 键值对表组成的向量，如 `Items: vec:dict__string__clz_Torappu_ItemData`）；
   * 嵌套字典的值用 `list_dict__...`（如 `PotentialItems: vec:dict__int__list_dict__string__string`）。
   */
  function mapType(csType: string, ctx: Set<string>): string {
    const t = csType.trim();
    if (WIRE_OVERRIDE[t]) return WIRE_OVERRIDE[t];
    if (SCALAR[t]) return SCALAR[t];
    // 定长数组与泛型集合在 FBO 中同为「向量」
    const arrM = /^(.+)\[\]$/.exec(t);
    if (arrM && !arrM[1].endsWith("[")) return `vec:${mapElem(arrM[1], ctx)}`;
    const listM = /^System\.Collections\.Generic\.(?:List|IList|IEnumerable)<(.+)>$/.exec(t);
    if (listM) return `vec:${mapElem(listM[1], ctx)}`;
    const dictInner = t.startsWith("System.Collections.Generic.Dictionary<") ? genericInner(t) : null;
    if (dictInner) {
      const [k, v] = splitGenericArgs(dictInner);
      return `vec:dict__${mapElem(k, ctx)}__${mapElem(v, ctx)}`;
    }
    const kvpInner = t.startsWith("System.Collections.Generic.KeyValuePair<") ? genericInner(t) : null;
    if (kvpInner) {
      const [k, v] = splitGenericArgs(kvpInner);
      return `kvp__${mapElem(k, ctx)}__${mapElem(v, ctx)}`;
    }
    if (enums.has(t)) return "enum";
    if (classes.has(t)) return clzKey(t);
    ctx.add(t);
    return "unknown";
  }
  function mapElem(csType: string, ctx: Set<string>): string {
    const t = csType.trim();
    if (WIRE_OVERRIDE[t]) return WIRE_OVERRIDE[t];
    // 嵌套字典（作为值出现）→ list_dict__K__V
    const dictInner = t.startsWith("System.Collections.Generic.Dictionary<") ? genericInner(t) : null;
    if (dictInner) {
      const [k, v] = splitGenericArgs(dictInner);
      return `list_dict__${mapElem(k, ctx)}__${mapElem(v, ctx)}`;
    }
    const arrM = /^(.+)\[\]$/.exec(t);
    if (arrM && !arrM[1].endsWith("[")) return `list_${mapElem(arrM[1], ctx)}`;
    if (SCALAR[t]) return SCALAR[t];
    if (enums.has(t)) return "enum";
    if (classes.has(t)) return clzKey(t);
    ctx.add(t);
    return "unknown";
  }

  const pascal = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
  // int/enum 在解码器中同义（fbo.ts 的 "int" 与 "enum" 都是 i32 读取）——比对时视作等价，
  // 写回时保留旧 token，避免产生无意义的全表 diff。
  const intLike = (t: string) => t === "int" || t === "enum";
  const eqType = (a: string, b: string) => a === b || (intLike(a) && intLike(b));
  const unresolved = new Set<string>();
  const changed: string[] = [];
  const perTable: { base: string; added: number; shifted: number; retyped: number; classes: number }[] = [];
  let fieldDiffs = 0;
  let slotDiffs = 0;
  let typeDiffs = 0;
  let checked = 0;
  let untouched = 0;
  let shown = 0;
  let protectedClasses = 0;

  for (const file of fs.readdirSync(SCHEMA_DIR).filter((f) => f.endsWith(".json"))) {
    const base = file.replace(/\.json$/, "");
    if (tableArg && base !== tableArg) continue;
    const p = path.join(SCHEMA_DIR, file);
    const schema = JSON.parse(fs.readFileSync(p, "utf-8"));
    const next = JSON.parse(JSON.stringify(schema));
    let fileChanged = false;
    let tAdded = 0, tShifted = 0, tRetyped = 0, tClasses = 0;
    for (const [key, oldFields] of Object.entries<{ name: string; type: string; slot: number }[]>(
      schema.tables as any,
    )) {
      if (!key.startsWith("clz_")) continue;
      const full = [...classes.keys()].find((n) => clzKey(n) === key);
      if (!full) {
        unresolved.add(key);
        continue;
      }
      const fields = classes.get(full)!;
      const ctx = new Set<string>();
      const oldByName = new Map(oldFields.map((f) => [f.name, f]));
      const fieldCtx = new Set<string>();
      const regenRaw = fields.map((f, i) => {
        const name = pascal(f.name);
        const mapped = mapType(f.type, fieldCtx);
        const old = oldByName.get(name);
        // int/enum 同义时保留旧 token（减少无谓 diff）
        const type = old && eqType(old.type, mapped) ? old.type : mapped;
        return { name, type, slot: 4 + 2 * i };
      });
      // 安全阀：字段类型或子类无法解析（泛型实例化类等）→ 保留旧字段表，避免把数据解成 null
      if (fieldCtx.size > 0) {
        protectedClasses++;
        continue;
      }
      const regen = regenRaw;
      checked++;
      const same =
        regen.length === oldFields.length &&
        regen.every((f, i) => f.name === oldFields[i].name && eqType(f.type, oldFields[i].type) && f.slot === oldFields[i].slot);
      if (!same) {
        fileChanged = true;
        if (!changed.includes(base)) changed.push(base);
        if (diffLimit > 0 && shown < diffLimit) {
          shown++;
          console.log(`\n[${base}] ${key}`);
          console.log("  old: " + oldFields.map((f) => `${f.name}#${f.slot}:${f.type}`).join(" | "));
          console.log("  new: " + regen.map((f) => `${f.name}#${f.slot}:${f.type}`).join(" | "));
        }
        const oldNames = new Set(oldFields.map((f) => f.name));
        const newNames = new Set(regen.map((f) => f.name));
        tClasses++;
        for (const n of newNames) if (!oldNames.has(n)) { fieldDiffs++; tAdded++; }
        for (const f of regen) {
          const o = oldFields.find((x) => x.name === f.name);
          if (!o) continue;
          if (o.slot !== f.slot) { slotDiffs++; tShifted++; }
          if (!eqType(o.type, f.type)) { typeDiffs++; tRetyped++; }
        }
      }
      next.tables[key] = regen;
    }
    if (fileChanged) perTable.push({ base, added: tAdded, shifted: tShifted, retyped: tRetyped, classes: tClasses });
    if (doWrite && fileChanged) fs.writeFileSync(p, JSON.stringify(next));
    if (!fileChanged) untouched++;
  }

  console.log(`比对表类: ${checked}；有差异的表文件: ${changed.length}（无差异 ${untouched}）`);
  console.log(`因未解析类型而保留旧字段表的类: ${protectedClasses}`);
  console.log(`差异统计: 新增字段 ${fieldDiffs} / slot 位移 ${slotDiffs} / 类型变化 ${typeDiffs}`);
  if (changed.length) console.log("差异表:", changed.join(", "));
  const slotTables = perTable.filter((t) => t.shifted > 0).sort((a, b) => b.shifted - a.shifted);
  console.log(`\n=== slot 位移（真正的结构漂移）${slotTables.length} 张表 ===`);
  for (const t of slotTables) console.log(`  ${t.base.padEnd(28)} 位移${String(t.shifted).padStart(4)} / 新增字段${String(t.added).padStart(3)} / 类型${String(t.retyped).padStart(4)} / 类${t.classes}`);
  const typeOnly = perTable.filter((t) => t.shifted === 0);
  console.log(`\n=== 仅类型 token 差异（int/enum 之外）${typeOnly.length} 张表 ===`);
  for (const t of typeOnly.slice(0, 20)) console.log(`  ${t.base.padEnd(28)} 类型${t.retyped} / 新增字段${t.added} / 类${t.classes}`);
  if (unresolved.size) console.log(`未在 C# 中找到的类 (${unresolved.size}):`, [...unresolved].slice(0, 10).join(", "));
  if (unresolved.size) console.log(`未识别类型 (${unresolved.size}):`, [...unresolved].slice(0, 10).join(", "));
  if (!doCheck && !doWrite) console.log("（未指定 --check/--write：仅试算，未写盘）");
  if (doWrite) console.log("已写回有差异的 schema 文件");
}

main();