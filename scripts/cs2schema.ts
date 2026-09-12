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
import { requireCsFile } from "./lib/cs-source";

const ROOT = path.join(__dirname, "..");
const SCHEMA_DIR = path.join(ROOT, "scripts/vendor/fbs-schemas");
const args = process.argv.slice(2);
const doCheck = args.includes("--check");
const doWrite = args.includes("--write");
const tableArg = args.includes("--table") ? args[args.indexOf("--table") + 1] : undefined;
const diffLimit = args.includes("--diff") ? Number(args[args.indexOf("--diff") + 1]) : 0;

/** 解析 object 路径的 C# 签名文件（统一走 scripts/lib/cs-source，禁止硬编码版本号） */
function resolveCsFile(): string {
  return requireCsFile({
    explicit: args.indexOf("--cs") >= 0 ? args[args.indexOf("--cs") + 1] : undefined,
  });
}

interface CsField {
  type: string;
  name: string;
}

function parseCs(file: string): {
  classes: Map<string, CsField[]>;
  enums: Set<string>;
  bases: Map<string, string>;
} {
  const classes = new Map<string, CsField[]>();
  const enums = new Set<string>();
  const bases = new Map<string, string>();
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
    // 记录基类（用于识别「列表来自泛型基类」的派生类，见 listDerived 判定）
    const baseM = /^[^:]+:\s*([\w.`]+)/.exec(lines[i]);
    if (baseM) bases.set(name, baseM[1]);
  }
  return { classes, enums, bases };
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
  const { classes, enums, bases } = parseCs(csFile);
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

  /**
   * 「列表来自泛型基类」判定。
   *
   * `Torappu.CharacterData.AttributesKeyFrame : Torappu.KeyFrames<Torappu.AttributesData>`
   * 自身**不声明任何字段**——元素列表在泛型基类
   * `KeyFrames<T> : List<KeyFrame<T,T>>` 上。FBO 会把继承来的列表**平铺**进该对象的
   * vtable，因此线上它实际是「KeyFrame 的向量」，vendored schema 用合成 token
   * `vec:clz_Torappu_KeyFrames_2_KeyFrame_<A>_<B>_` 表达（该合成表由 schema-gen 预置，
   * 不在 C# 中，故 cs2schema 一直把它列进"未在 C# 中找到的类"）。
   *
   * 反例（错误做法）：若按派生类名写成 `clz_Torappu_CharacterData_AttributesKeyFrame`，
   * 该键**不在 schema.tables 中**（零字段类被跳过），fbo 的 tableToJson 查不到 →
   * 返回 `{}`。实测：character_table 全部 2377 条 attributesKeyFrames 退化为
   * `{level: null, data: null}`（2026-09-11 首次 schema:write 即踩此坑）。
   * 故：此类字段必须保留**旧 token 原样**，不参与重生成。
   */
  function isListFromGenericBase(csType: string): boolean {
    let t = csType.trim();
    // 剥掉 vec:/List<> 包装，取元素类型
    const listM = /^System\.Collections\.Generic\.(?:List|IList|IEnumerable)<(.+)>$/.exec(t);
    if (listM) t = listM[1].trim();
    // 字段类型本身可能就是 KeyFrame<A,B> 这类泛型实参（此时直接看基类名）
    const own = t.split("<")[0];
    if (/^Torappu\.KeyFrames$/.test(own)) {
      // KeyFrames<T0,T1> 直接继承 List<KeyFrame<T0,T1>>
      return genericInner(t) !== null;
    }
    // 普通派生类：看它的基类是否为 Torappu.KeyFrames（含泛型实参，如 Torappu.KeyFrames<...>）
    const base = bases.get(t);
    if (!base) return false;
    return base === "Torappu.KeyFrames" || /^Torappu\.KeyFrames</.test(base);
  }


/**
 * 收集 schema 中被引用但缺失的键值对表定义（`dict__K__V` / `kvp__K__V`）
 *
 * 背景：字段类型按 CS 泛型映射为 `vec:dict__K__V`（FBO 的 map = 键值对表向量），
 * 但 `dict__K__V` 这类**键值对表定义不由 CS 类派生**（历史 vendored schema 自带）。
 * 当 K/V 组合是新的（如 `dict__string__enum`、`dict__enum__clz_X`、
 * `dict__string__vec:clz_X`）时 schema 里没有对应表 → fbo.ts 的「纯 KV 表折叠为 dict」
 * 判定（要求字段恰为 Key/Value）失效 → 解出「元素为空对象的数组」，字段整体静默失效。
 * 实测受影响：roguelike scrapItemToType、campaign dropGains、display_meta avatarTypeData、
 * battle_equip tokenAttributeBlackboard 等（2026-09-11）。
 *
 * 生成约定与既有 vendored 定义一致：`Key@4 = K`、`Value@6 = V`。
 * @param tables - 现有表定义（会被就地查询；返回值只含缺失项）
 * @returns 需要补齐的 { name, fields } 列表（含嵌套 dict 值的递归补齐）
 */
function collectMissingKvTables(
  tables: Record<string, { name: string; type: string; slot: number }[]>,
): { name: string; fields: { name: string; type: string; slot: number }[] }[] {
  const added = new Map<string, { name: string; type: string; slot: number }[]>();
  const consider = (type: string): void => {
    let t = type;
    if (t.startsWith("vec:")) t = t.slice(4);
    if (!(t.startsWith("dict__") || t.startsWith("kvp__"))) return;
    if (tables[t] || added.has(t)) return;
    const rest = t.slice(t.indexOf("__") + 2);
    const sep = rest.indexOf("__");
    if (sep <= 0) return;
    const key = rest.slice(0, sep);
    const value = rest.slice(sep + 2);
    if (!key || !value) return;
    added.set(t, [
      { name: "Key", type: key, slot: 4 },
      { name: "Value", type: value, slot: 6 },
    ]);
  };
  // 逐轮扫描到不动点：新补的表里可能还引用着别的缺失 KV 表（嵌套 dict 值）
  for (let round = 0; round < 8; round++) {
    const before = added.size;
    for (const fields of Object.values(tables)) {
      for (const f of fields) consider(f.type);
    }
    for (const fields of added.values()) {
      for (const f of fields) consider(f.type);
    }
    if (added.size === before) break;
  }
  return [...added.entries()].map(([name, fields]) => ({ name, fields }));
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
  let protectedLoss = 0;
  const lostSamples: { key: string; names: string[] }[] = [];

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
        // 泛型基类列表字段（AttributesKeyFrames 等）：保持旧合成 token——
        // 按派生类名重写会让 fbo 查不到子表而解成 {}（见 isListFromGenericBase 注释）
        if (isListFromGenericBase(f.type) && old && old.type.startsWith("vec:clz_")) {
          return { name, type: old.type, slot: old.slot };
        }
        return { name, type, slot: 4 + 2 * i };
      });
      // 安全阀 1：字段类型或子类无法解析（泛型实例化类等）→ 保留旧字段表，避免把数据解成 null
      if (fieldCtx.size > 0) {
        protectedClasses++;
        continue;
      }
      // 安全阀 2：重生成会丢掉旧字段（C# 运行时模型缺该字段，如 SkillData.unlockCond）→
      // 保留旧字段表。丢字段比错位更危险：整片数据静默消失（skin_table 曾丢 30953 处）。
      //
      // 但「旧字段名不再出现」有两种截然不同的成因，必须区分（2026-09-11 修复）：
      //   (a) 字段真的从线上结构移除 —— 槽位空出，必须保留旧表兜底；
      //   (b) 字段只是**改名**（官方重构，如 CharacterData.MainSkill 的
      //       LevelUpCostCond→SpecializeLevelUpData、UnlockCond→InitialUnlockCond）——
      //       槽位与类型都没变，只是名字换了。
      // 旧实现把 (b) 也当成丢字段，导致这些类**永久冻结在旧名**上：schema 里留着
      // 已不存在的名字，转换器再按 schema 补 null 伪键（levelUpCostCond/unlockCond 均为 null），
      // 而真实解码出的新名字（initialUnlockCond）反而成了"计划外"字段。消费者读旧名只拿到
      // null，静默失效——rlv2 招募技能裁剪即因此失效（精二降精一时三技能未被剔除）。
      // 判别依据：旧字段若能在**同槽位**上找到类型兼容的新字段，即判定为改名（允许重生成）。
      const lostFields = oldFields.filter((o) => {
        if (regenRaw.some((f) => f.name === o.name)) return false; // 同名保留
        const sameSlot = regenRaw.find((f) => f.slot === o.slot);
        // 同槽位存在且类型兼容 → 改名，不算丢失
        return !(sameSlot && eqType(sameSlot.type, o.type));
      });
      if (lostFields.length > 0) {
        protectedLoss++;
        if (!lostSamples.some((s) => s.key === key)) {
          lostSamples.push({ key, names: lostFields.map((f) => f.name).slice(0, 6) });
        }
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
    // 补齐缺失的键值对表定义（见 collectMissingKvTables 注释）——纯新增，不动 clz 字段表
    for (const kv of collectMissingKvTables(next.tables)) {
      next.tables[kv.name] = kv.fields as any;
      fileChanged = true;
    }
    if (fileChanged) perTable.push({ base, added: tAdded, shifted: tShifted, retyped: tRetyped, classes: tClasses });
    if (doWrite && fileChanged) fs.writeFileSync(p, JSON.stringify(next));
    if (!fileChanged) untouched++;
  }

  console.log(`比对表类: ${checked}；有差异的表文件: ${changed.length}（无差异 ${untouched}）`);
  console.log(`因未解析类型而保留旧字段表的类: ${protectedClasses}`);
  console.log(`因会丢失旧字段而保留旧字段表的类: ${protectedLoss}`);
  if (lostSamples.length) {
    console.log(`丢字段样例（前 ${Math.min(10, lostSamples.length)} 个）:`);
    for (const s of lostSamples.slice(0, 10)) console.log(`  ${s.key} 丢: ${s.names.join(", ")}`);
  }
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

  // --check 的退出码契约：检出 slot 位移即非 0 退出（供 decompile-client.sh / CI 作门禁）。
  // 仅「类型 token 差异」不计失败——int/enum 等 token 写法差异不改变 vtable 布局，
  // 真正会破坏解码的是 slot 位移（字段插入中部导致其后全体位移）。
  // `--table X` 定向检查时只看该表，便于局部验证；--check 与 --write 同时给出时以写入优先。
  if (doCheck && !doWrite) {
    const blockers = slotTables.filter((t) => !tableArg || t.base === `${tableArg}.json` || t.base === tableArg);
    if (blockers.length > 0) {
      console.error(
        `\n[FAIL] 检出 ${blockers.length} 张表存在 slot 位移（struct 布局已变，会解码错位）：` +
          blockers.map((t) => t.base).join(", ") +
          `\n       请执行 \`pnpm run schema:write\` 重写 schema，再用 \`pnpm run schema:check\` 复核。`,
      );
      process.exitCode = 1;
    } else {
      console.log("\n[OK] 未检出 slot 位移（结构布局与现有 schema 一致）");
    }
  }
}

main();