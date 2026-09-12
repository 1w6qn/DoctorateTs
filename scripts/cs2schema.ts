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
  /** 私有**序列化**字段（`m_xxx` / 自动属性 backing field）——仅泛型实例路径使用 */
  priv?: boolean;
}

/** fbs-schemas/*.json 中单张表的字段定义（槽位为 vtable offset） */
interface SchemaFieldDef {
  name: string;
  type: string;
  slot: number;
}

/** fbs-schemas/*.json 的落盘结构（由 scripts/schema-gen.ts 生成） */
interface FbsSchemaJson {
  root: string;
  tables: Record<string, SchemaFieldDef[]>;
  enums: Record<string, Record<string, number>>;
}

function parseCs(file: string): {
  classes: Map<string, CsField[]>;
  enums: Set<string>;
  bases: Map<string, string>;
  /** 完整基类/接口列表（泛型基类需要原文，如 `Dictionary<String, Dictionary<VoiceLangType, String>>`） */
  baseList: Map<string, string[]>;
} {
  const classes = new Map<string, CsField[]>();
  const enums = new Set<string>();
  const bases = new Map<string, string>();
  const baseList = new Map<string, string[]>();
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
      // 实例字段：跳过 static/const/readonly 修饰（const 曾被误当作字段，如 Vector3.kEpsilon）。
      // 私有字段也要收：游戏数据模型里有两类私有**序列化**字段，漏掉会整片丢数据
      //   1) 自动属性 backing field `<summaryActor>k__BackingField`（RL0x EndingText 的 Summary* 系列）
      //   2) `m_xxx` 形式的数据成员（SharedCharData.m_skillIndex、Undefinable.m_defined 等）
      const fm = /^\t(public|private|protected|internal) (?!static |const |readonly )(.+?) ([\w@<>]+);/.exec(line);
      if (fm) {
        const raw = fm[3];
        const backing = /^<(.+)>k__BackingField$/.exec(raw);
        const isPriv = fm[1] !== "public";
        if (isPriv && !backing && !/^m_[A-Za-z]/.test(raw)) continue;
        fields.push({ type: fm[2].trim(), name: backing ? backing[1] : raw, priv: isPriv });
      }
    }
    classes.set(name, fields);
    // 记录基类（用于识别「列表来自泛型基类」的派生类，见 listDerived 判定）
    const baseM = /^[^:]+:\s*([\w.`]+)/.exec(lines[i]);
    if (baseM) bases.set(name, baseM[1]);
    // 完整基类列表（按尖括号深度切分逗号）
    const colon = lines[i].indexOf(":", lines[i].indexOf(name) + name.length);
    if (colon >= 0) {
      const rest = lines[i].slice(colon + 1).trim();
      const parts: string[] = [];
      let depth = 0;
      let cur = "";
      for (const ch of rest) {
        if (ch === "<") depth++;
        else if (ch === ">") depth--;
        if (ch === "," && depth === 0) {
          parts.push(cur.trim());
          cur = "";
          continue;
        }
        cur += ch;
      }
      if (cur.trim()) parts.push(cur.trim());
      if (parts.length) baseList.set(name, parts);
    }
  }
  return { classes, enums, bases, baseList };
}

/**
 * C# 标量 → schema 类型 token
 *
 * 窄整型按线格式宽度映射（Byte/Int16 在 FBO 里就是 1/2 字节，读成 i32 会越读 2–3 字节，
 * 实测 `BuildingData.ObstaclePoint.edgeWalkableMask` 这类字段会被读成 32 位垃圾值）。
 * 解码器侧对应 token 见 `scripts/vendor/fbo.ts#readFieldValue`。
 */
const SCALAR: Record<string, string> = {
  "System.String": "string",
  "System.Boolean": "bool",
  "System.Int32": "int",
  "System.Int64": "long",
  "System.Single": "float",
  "System.Double": "double",
  "System.Int16": "short",
  "System.Byte": "ubyte",
  "System.SByte": "sbyte",
  "System.UInt16": "ushort",
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
  // 任意 JSON blob：运行时是 Newtonsoft JObject，线上是 `hg__internal__JObject`（base64 字符串）
  "Newtonsoft.Json.Linq.JObject": "hg__internal__JObject",
};

/**
 * 线上存在、但 CS 中没有对应类的表（由报文结构反推，见 `pnpm run schema:audit`）
 *
 * - `hg__internal__JObject`：任意 JSON 以 base64 字符串承载
 * - `hg__internal__MapData`：关卡地图矩阵（行/列 + i16 数组）
 */
const SYNTHETIC_TABLES: Record<string, { name: string; type: string; slot: number }[]> = {
  hg__internal__JObject: [{ name: "Base64", type: "string", slot: 4 }],
  hg__internal__MapData: [
    { name: "RowSize", type: "int", slot: 4 },
    { name: "ColumnSize", type: "int", slot: 6 },
    { name: "MatrixData", type: "vec:short", slot: 8 },
  ],
};

/**
 * CS 运行时模型里有、线上报文里没有的字段（不参与 schema 生成）
 *
 * 判定依据：`pnpm run schema:audit` 报告该表 wire 字段数 < schema 字段数，
 * 且这些字段在全部样本中从未命中。它们若留在 schema 里会**挤占中间 slot**，
 * 使其后字段整体位移（activity_table 的 DisplayDetailRewards 曾因此丢掉 type/id/dropType）。
 */
const NON_WIRE_TYPES = new Set([
  // 纯运行时对象：线上没有对应结构（FBS 的 ActionData/LevelData 均无这些字段）
  "System.Object",
  "Torappu.LevelData.ActionID",
  "Torappu.LevelData.RuntimeData",
  // 反作弊包装类型：线上是普通 Rect（实测 RangeData.BoundingBoxes 在报文里从未命中，wire 3 = 去掉它后的字段数）
  "CodeStage.AntiCheat.ObscuredTypes.ObscuredRect",
]);

const NON_WIRE_FIELDS: Record<string, string[]> = {
  "Torappu.StageData.DisplayDetailRewards": ["GetPercent", "CannotGetPercent", "Expectation", "SumOfCountWeight"],
  "Torappu.ActivityBossRushData.DisplayDetailRewards": ["GetPercent", "CannotGetPercent"],
  // 音频 Bank 族：CS 运行时模型比线上多出的字段（实测 SnapshotBank 5 字段解出正确配音数据、
  // 6 字段整体位移并把 Duration 读成 4.5e-44；SoundFXBank 的 mixerDesc 在报文里从未命中）
  "Torappu.Audio.Middleware.Data.SnapshotBank": ["targetFxBank"],
  "Torappu.Audio.Middleware.Data.SoundFXBank": ["mixerDesc"],
};

function main() {
  const csFile = resolveCsFile();
  const { classes, enums, bases, baseList } = parseCs(csFile);
  console.log(`解析 ${path.basename(csFile)}：${classes.size} 个类 / ${enums.size} 个枚举`);

  /**
   * 类的线上字段表 = 自身字段 + 基类链字段（自身在前）
   *
   * FBO 会把继承来的字段**平铺**进同一张表（实测 `FifthAnnivExploreMissionData : MissionData`
   * 线上 20 字段 = 自身 1 + 基类 19），旧实现只取自身字段，导致这类表只解出开头一两个字段。
   * 无字段的类（纯泛型集合派生，见 collectionBaseToken）不在此列。
   */
  /** 本次生成中出现的泛型实例（合成表名 → 泛型类 + 实参），供引用闭包补齐表定义 */
  const insts = new Map<string, { base: string; args: string[] }>();

  /**
   * 泛型实例化 → 合成表名
   *
   * CS 里 `Torappu.BuildingData.ControlRoomBean : Torappu.BuildingData.RoomBean<ControlRoomPhase>`
   * 这类继承，基类是**泛型实例**（`RoomBean` 的字段类型写作 `List<T0> phases`）。
   * FBO 会把基类字段平铺进派生表，因此必须按实例展开，否则 `Phases` 会被判成丢字段、
   * 整表冻结（实测 ManufactRoomBean 报文里 2 个字段都真实存在）。
   *
   * 合成表名沿用既有 vendored 约定：`clz_<Base>_<arity>_<arg1>_..._`，例如
   * `clz_Torappu_BuildingData_RoomBean_1_Torappu_BuildingData_ShopPhase_`、
   * `clz_Torappu_Undefinable_1_System_String_`（与旧 schema / FBS 同名，可直接复用既有定义）。
   * @param inst - 形如 `Torappu.BuildingData.RoomBean<Torappu.BuildingData.ShopPhase>`
   */
  function genericInst(inst: string): { table: string; base: string; args: string[] } | null {
    const m = /^([A-Za-z_][\w.]*)<(.+)>$/.exec(inst.trim());
    // `System.*` 是框架泛型（Dictionary/List/KeyValuePair…），各自有专门映射，不能当业务泛型类
    if (!m || m[1].startsWith("System.") || !classes.has(m[1])) return null;
    const args = splitGenericArgs(m[2]);
    if (!args.length) return null;
    const mangle = (t: string) => t.trim().replace(/[.[\]]/g, "_");
    return {
      table: `clz_${mangle(m[1])}_${args.length}_${args.map(mangle).join("_")}_`,
      base: m[1],
      args,
    };
  }

  /** 泛型参数替换：`T0`/`T1` → 实参 */
  function substGeneric(t: string, args: string[]): string {
    return t.replace(/\bT(\d+)\b/g, (whole, d) => args[Number(d)] ?? whole);
  }

  /** 泛型实例的线上字段表（基类自身字段，已做参数替换） */
  function wireFieldsInstance(base: string, args: string[]): CsField[] {
    // 泛型包装类（如 `Torappu.Undefinable<T>`）的线上字段是私有成员，这里必须带上私有字段
    const out: CsField[] = (classes.get(base) ?? [])
      .map((f) => ({ name: f.name, type: substGeneric(f.type, args) }))
      .filter((f) => !NON_WIRE_TYPES.has(f.type.trim()));
    for (const b of baseList.get(base) ?? []) if (classes.has(b)) out.push(...wireFields(b));
    const seenName = new Set<string>();
    return out.filter((f) => {
      if (seenName.has(f.name)) return false;
      seenName.add(f.name);
      return true;
    });
  }

  function wireFields(full: string, seen: Set<string> = new Set()): CsField[] {
    if (seen.has(full)) return [];
    seen.add(full);
    const nonWire = new Set((NON_WIRE_FIELDS[full] ?? []).map((n) => n.toLowerCase()));
    const own = (classes.get(full) ?? []).filter(
      (f) => !f.priv && !nonWire.has(f.name.toLowerCase()) && !NON_WIRE_TYPES.has(f.type.trim()),
    );
    const out: CsField[] = [...own];
    for (const b of baseList.get(full) ?? []) {
      if (classes.has(b)) {
        out.push(...wireFields(b, seen));
        continue;
      }
      const gen = genericInst(b);
      if (gen) out.push(...wireFieldsInstance(gen.base, gen.args));
    }
    // 同名去重（派生类重复声明基类字段时保留首次出现）
    // 注意：不能用 `!(seen.has(x) || seen.add(x))` —— Set.add 返回 Set（恒真），会把字段全部过滤掉
    const seenName = new Set<string>();
    return out.filter((f) => {
      if (seenName.has(f.name)) return false;
      seenName.add(f.name);
      return true;
    });
  }

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
    const listM = /^System\.Collections\.Generic\.(?:List|IList|IEnumerable|HashSet|ISet)<(.+)>$/.exec(t);
    if (listM) return `vec:${mapElem(listM[1], ctx)}`;
    const dictInner = t.startsWith("System.Collections.Generic.Dictionary<") ? genericInner(t) : null;
    if (dictInner) {
      const [k, v] = splitGenericArgs(dictInner);
      return `vec:dict__${mapElem(k, ctx)}__${mapElem(v, ctx)}`;
    }
    // Torappu.ListDict<K,V>：运行时是 List<KeyValuePair<K,V>> 且实现 IDictionary，线上就是 map
    const listDictInner = t.startsWith("Torappu.ListDict<") ? genericInner(t) : null;
    if (listDictInner) {
      const [k, v] = splitGenericArgs(listDictInner);
      return `vec:dict__${mapElem(k, ctx)}__${mapElem(v, ctx)}`;
    }
    const kvpInner = t.startsWith("System.Collections.Generic.KeyValuePair<") ? genericInner(t) : null;
    if (kvpInner) {
      const [k, v] = splitGenericArgs(kvpInner);
      return `kvp__${mapElem(k, ctx)}__${mapElem(v, ctx)}`;
    }
    if (enums.has(t)) return "enum";
    const coll = collectionBaseToken(t, ctx);
    if (coll) return coll;
    const genT = genericInst(t);
    if (genT) {
      insts.set(genT.table, { base: genT.base, args: genT.args });
      return genT.table;
    }
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
    // Torappu.ListDict<K,V>（作为值出现）→ list_dict__K__V
    const ldInner = t.startsWith("Torappu.ListDict<") ? genericInner(t) : null;
    if (ldInner) {
      const [k, v] = splitGenericArgs(ldInner);
      return `list_dict__${mapElem(k, ctx)}__${mapElem(v, ctx)}`;
    }
    // KeyValuePair<K,V> 作为值出现（如 List<KeyValuePair<String, List<X>>> 的元素）
    const kvpInner = t.startsWith("System.Collections.Generic.KeyValuePair<") ? genericInner(t) : null;
    if (kvpInner) {
      const [k, v] = splitGenericArgs(kvpInner);
      return `kvp__${mapElem(k, ctx)}__${mapElem(v, ctx)}`;
    }
    const arrM = /^(.+)\[\]$/.exec(t);
    if (arrM && !arrM[1].endsWith("[")) return `list_${mapElem(arrM[1], ctx)}`;
    // 泛型 List 作为值出现（如 Dictionary<String, List<String>> 的值）
    const listInner = /^System\.Collections\.Generic\.(?:List|IList|IEnumerable|HashSet|ISet)<(.+)>$/.exec(t);
    if (listInner) return `list_${mapElem(listInner[1], ctx)}`;
    if (SCALAR[t]) return SCALAR[t];
    if (enums.has(t)) return "enum";
    const coll = collectionBaseToken(t, ctx);
    if (coll) return coll;
    const genE = genericInst(t);
    if (genE) {
      insts.set(genE.table, { base: genE.base, args: genE.args });
      return genE.table;
    }
    if (classes.has(t)) return clzKey(t);
    ctx.add(t);
    return "unknown";
  }

  /**
   * 「泛型集合派生类」→ 线上集合 token
   *
   * 例：`Torappu.Audio.Middleware.Data.SoundFXVoiceLangData :
   *      Dictionary<String, Dictionary<Torappu.VoiceLangType, String>>`
   * 自身无字段，线上就是「字典的字典」（报文实测该字段为
   * `[dict__string__list_dict__enum__string]`）。若不特判，会生成一个查不到的
   * `clz_..._SoundFXVoiceLangData` 引用 → 解码得到 `{}`（实测 audio_data 该字段丢失）。
   * @param full - C# 全名
   * @param ctx - 未解析类型收集器
   */
  function collectionBaseToken(full: string, ctx: Set<string>): string | null {
    if ((classes.get(full) ?? []).length > 0) return null; // 自身有字段 → 按普通表处理
    if (isListFromGenericBase(full)) return null; // KeyFrames 系列保持旧合成 token（见下方注释）
    for (const b of baseList.get(full) ?? []) {
      const dictInner = b.startsWith("System.Collections.Generic.Dictionary<") ? genericInner(b) : null;
      if (dictInner) {
        const [k, v] = splitGenericArgs(dictInner);
        return `vec:dict__${mapElem(k, ctx)}__${mapElem(v, ctx)}`;
      }
      const listM = /^System\.Collections\.Generic\.(?:List|IList|IEnumerable|HashSet|ISet)<(.+)>$/.exec(b);
      if (listM) return `vec:${mapElem(listM[1], ctx)}`;
      const arrM = /^(.+)\[\]$/.exec(b);
      if (arrM) return `vec:${mapElem(arrM[1], ctx)}`;
    }
    return null;
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
    const listM = /^System\.Collections\.Generic\.(?:List|IList|IEnumerable|HashSet|ISet)<(.+)>$/.exec(t);
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
    const t = stripVec(type);
    if (!isKvName(t)) return;
    if (tables[t] || added.has(t)) return;
    const kv = splitKv(t);
    if (!kv) return;
    added.set(t, [
      { name: "Key", type: kv[0], slot: 4 },
      { name: "Value", type: normalizeKvValue(kv[1]), slot: 6 },
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

/** 去掉 `vec:` / `list_` 包装，取底层 token */
function stripVec(type: string): string {
  let t = type.trim();
  if (t.startsWith("vec:")) t = t.slice(4);
  return t;
}

/** token 是否是键值对表名（`dict__K__V` / `kvp__K__V` / `list_dict__K__V`） */
function isKvName(t: string): boolean {
  return t.startsWith("dict__") || t.startsWith("kvp__") || t.startsWith("list_dict__");
}

/**
 * 键值对表名切成 `[K, V]`
 *
 * 名称里 K 是原子（标量/枚举/类名，不含 `__`），V 可以是嵌套的 KV 名。
 * @param name - 形如 `dict__string__list_dict__int__clz_X`
 */
function splitKv(name: string): [string, string] | null {
  const m = /^(?:dict__|kvp__|list_dict__)(.+)$/.exec(name);
  if (!m) return null;
  const rest = m[1];
  let idx = rest.indexOf("__");
  while (idx >= 0) {
    const k = rest.slice(0, idx);
    const v = rest.slice(idx + 2);
    if (k && v && !k.includes("__")) return [k, v];
    idx = rest.indexOf("__", idx + 2);
  }
  return null;
}

/**
 * 键值对表里 Value 字段的类型 token
 *
 * 名称里的 `list_dict__K__V` / `list_X` 表示「向量形式的表引用」，
 * 而**字段位置**必须写成 `vec:dict__K__V` / `vec:X` 才能被解码器识别
 * （既有 vendored schema 即此约定：`dict__string__list_dict__int__X` 的 Value 是 `vec:dict__int__X`）。
 * @param value - 名称中的 V 片段
 */
function normalizeKvValue(value: string): string {
  if (value.startsWith("list_dict__")) return `vec:${value.slice("list_".length)}`;
  if (value.startsWith("list_")) return `vec:${value.slice("list_".length)}`;
  return value;
}

/** 从字段类型里抽出「必须存在的表名」 */
function referencedTables(type: string): string[] {
  const out: string[] = [];
  let t = stripVec(type);
  // `list_X` 是「向量表」写法：本地 schema 把向量内联为 `vec:X`，其元素类型才是真引用
  // （漏掉这一层会让 X 被判定为不可达而在清理阶段误删，引用方随后变成悬空 → 解码出 {}）
  if (t.startsWith("list_")) t = t.slice("list_".length);
  if (isKvName(t)) {
    out.push(t);
    const kv = splitKv(t);
    if (kv) {
      for (const part of [kv[0], normalizeKvValue(kv[1])]) out.push(...referencedTables(part));
    }
    return out;
  }
  if (/^(clz_|hg__internal__)/.test(t)) out.push(t);
  return out;
}

  const pascal = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

  /**
   * 字段的**线格式种类**：FBO 只关心标量宽度与「是否 uoffset 引用」，
   * 具体引用哪张表/哪个类不影响 slot 布局。
   *
   * 用于「改名」判定：同槽位 + 同线格式种类即视为同一字段换名，
   * 否则 `vec:clz_A` → `vec:clz_B`（如 GachaData 的 LinkageTenGachaTkt→LinkageGachaTkt）
   * 会被误判成丢字段，整表永久冻结在旧结构上。
   */
  function wireKind(t: string): string {
    if (t.startsWith("vec:")) return "offset";
    switch (t) {
      case "string": return "offset";
      case "bool": return "bool";
      case "float": return "f32";
      case "double": return "f64";
      case "long": return "i64";
      case "int":
      case "enum":
        return "i32";
      case "ubyte":
      case "sbyte":
        return "i8";
      case "short":
      case "ushort":
        return "i16";
      default:
        return "offset"; // clz_ / dict__ / kvp__ / hg__internal__（均为 uoffset 引用）
    }
  }
  // int/enum 在解码器中同义（fbo.ts 的 "int" 与 "enum" 都是 i32 读取）——比对时视作等价，
  // 写回时保留旧 token，避免产生无意义的全表 diff。
  const intLike = (t: string) => t === "int" || t === "enum";
  const eqType = (a: string, b: string) => a === b || (intLike(a) && intLike(b));
  const unresolved = new Set<string>();
  const unknownTypes = new Map<string, number>();
  const changed: string[] = [];
  const perTable: { base: string; added: number; shifted: number; retyped: number; classes: number; newTables: number }[] = [];
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
    const schema: FbsSchemaJson = JSON.parse(fs.readFileSync(p, "utf-8"));
    const next: FbsSchemaJson = JSON.parse(JSON.stringify(schema));
    let fileChanged = false;
    let tAdded = 0, tShifted = 0, tRetyped = 0, tClasses = 0, tNewTables = 0;
    for (const [key, oldFields] of Object.entries(schema.tables)) {
      if (!key.startsWith("clz_")) continue;
      const full = [...classes.keys()].find((n) => clzKey(n) === key);
      if (!full) {
        unresolved.add(key);
        continue;
      }
      const fields = wireFields(full);
      const ctx = new Set<string>();
      const oldByName = new Map(oldFields.map((f) => [f.name, f]));
      const fieldCtx = new Set<string>();
      const regenRaw = fields.map((f, i) => {
        let name = pascal(f.name);
        // 同槽位旧字段与新字段仅大小写不同（如 HeadUidata vs HeadUIData）→ 保留旧写法，
        // 避免无意义改名冲击下游按名取值；FBO 线格式不携带字段名，二者等价。
        const oldSameSlot = oldFields.find((o) => o.slot === 4 + 2 * i);
        const norm = (n: string) => n.toLowerCase().replace(/^m(?=_)/, "").replace(/_/g, "");
        if (
          oldSameSlot &&
          oldSameSlot.name !== name &&
          (oldSameSlot.name.toLowerCase() === name.toLowerCase() || norm(oldSameSlot.name) === norm(name))
        ) {
          name = oldSameSlot.name;
        }
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
        for (const u of fieldCtx) unknownTypes.set(u, (unknownTypes.get(u) ?? 0) + 1);
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
        // 历史合成字段（`*AsNumpy`，excel-convert 本就丢弃、解码器读作 null）不算「丢失」，
        // 否则这些表会被永久冻结、拿不到 CS 侧的新字段。
        if (o.name.endsWith("AsNumpy") && o.type === "unknown") return false;
        // 有意剔除的非线格式字段（见 NON_WIRE_FIELDS）不算「丢失」，否则表会被冻结、无法重生成
        if ((NON_WIRE_FIELDS[full] ?? []).some((n) => n.toLowerCase() === o.name.toLowerCase())) return false;
        const sameSlot = regenRaw.find((f) => f.slot === o.slot);
        // 同槽位存在且线格式种类一致 → 改名，不算丢失
        return !(sameSlot && (eqType(sameSlot.type, o.type) || wireKind(sameSlot.type) === wireKind(o.type)));
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
    /**
     * 补齐「被引用但 schema 里没有」的表
     *
     * 这是缺口长期不可见的根因：旧实现只重写**已存在**的键，CS 里新出现的类
     * （新版活动数据类、`UnityEngine.Vector2/3` 这类非 Torappu 结构）永远不会被写进 schema，
     * 而引用它们的字段会被 `fbo.ts#tableToJson` 解成 `{}`（实测：Act54SideData 整族内容丢失、
     * 27 个 Vector 字段为空对象）。这里按引用闭包递归补齐。
     */
    const ensureReferenced = (): number => {
      let added = 0;
      /** 内容一致（含 0 字段占位表）则不算变更，保证重生成幂等 */
      const differs = (name: string, fields: { name: string; type: string; slot: number }[]): boolean =>
        JSON.stringify(next.tables[name] ?? null) !== JSON.stringify(fields);
      for (let round = 0; round < 24; round++) {
        let progressed = false;
        const queue: string[] = [schema.root as string];
        for (const fields of Object.values(next.tables)) {
          for (const f of fields) queue.push(...referencedTables(f.type));
        }
        for (const name of queue) {
          if (!name) continue;
          // 已存在且非空 → 保持；空的占位表（历史上生成失败留下的）允许重新生成
          if (next.tables[name] && next.tables[name].length > 0) continue;
          const inst = insts.get(name);
          if (inst) {
            const ictx = new Set<string>();
            const ifields = wireFieldsInstance(inst.base, inst.args).map((f, i) => ({
              name: pascal(f.name),
              type: mapType(f.type, ictx),
              slot: 4 + 2 * i,
            }));
            if (ictx.size > 0) {
              unresolved.add(name);
              continue;
            }
            if (differs(name, ifields)) {
              next.tables[name] = ifields;
              fileChanged = true;
              tClasses++;
              added++;
              progressed = true;
            }
            continue;
          }
          if (SYNTHETIC_TABLES[name]) {
            const sfields = SYNTHETIC_TABLES[name].map((f) => ({ ...f }));
            if (differs(name, sfields)) {
              next.tables[name] = sfields;
              fileChanged = true;
              tClasses++;
              added++;
              progressed = true;
            }
            continue;
          }
          const fullM = [...classes.keys()].find((n) => clzKey(n) === name);
          if (!fullM) continue;
          const tctx = new Set<string>();
          const tfields = wireFields(fullM).map((f, i) => ({
            name: pascal(f.name),
            type: mapType(f.type, tctx),
            slot: 4 + 2 * i,
          }));
          if (tctx.size > 0) {
            unresolved.add(name);
            continue; // 含无法映射的类型 → 不生成半成品表
          }
          if (differs(name, tfields)) {
            next.tables[name] = tfields;
            fileChanged = true;
            tClasses++;
            added++;
            progressed = true;
          }
        }
        if (!progressed) break;
      }
      return added;
    };
    const cAdded = ensureReferenced();
    tNewTables += cAdded;
    /**
     * 清理从 root 不可达的表
     *
     * 旧 vendored schema 里积压了不少「类已改名/已废弃」的残留（如
     * `clz_Torappu_GachaData_LinkageTenGachaTkt`、`clz_..._SoundFXVoiceLangData`）。
     * 解码器只从 root 出发按字段引用查表，不可达表永远不会被读到，清掉可避免
     * 「FBS 对照时冒出一堆本地独有表」的噪声。
     */
    const pruneUnreachable = (): number => {
      const keep = new Set<string>();
      const visit = (name: string): void => {
        if (!name || keep.has(name)) return;
        keep.add(name);
        for (const f of next.tables[name] ?? []) for (const r of referencedTables(f.type)) visit(r);
      };
      visit(schema.root as string);
      let removed = 0;
      for (const key of Object.keys(next.tables)) {
        if (keep.has(key)) continue;
        delete next.tables[key];
        removed++;
        fileChanged = true;
      }
      return removed;
    };
    tNewTables -= pruneUnreachable();
    // 补齐缺失的键值对表定义（见 collectMissingKvTables 注释）——纯新增，不动 clz 字段表
    for (const kv of collectMissingKvTables(next.tables)) {
      next.tables[kv.name] = kv.fields;
      fileChanged = true;
      tNewTables++;
    }
    if (fileChanged) perTable.push({ base, added: tAdded, shifted: tShifted, retyped: tRetyped, classes: tClasses, newTables: tNewTables });
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
  console.log(`差异统计: 新增字段 ${fieldDiffs} / slot 位移 ${slotDiffs} / 类型变化 ${typeDiffs} / 新增表 ${perTable.reduce((a, t) => a + t.newTables, 0)}`);
  if (changed.length) console.log("差异表:", changed.join(", "));
  const slotTables = perTable.filter((t) => t.shifted > 0).sort((a, b) => b.shifted - a.shifted);
  console.log(`\n=== slot 位移（真正的结构漂移）${slotTables.length} 张表 ===`);
  for (const t of slotTables) console.log(`  ${t.base.padEnd(28)} 位移${String(t.shifted).padStart(4)} / 新增字段${String(t.added).padStart(3)} / 类型${String(t.retyped).padStart(4)} / 类${t.classes}`);
  const typeOnly = perTable.filter((t) => t.shifted === 0);
  console.log(`\n=== 仅类型 token 差异（int/enum 之外）${typeOnly.length} 张表 ===`);
  for (const t of typeOnly.slice(0, 20)) console.log(`  ${t.base.padEnd(28)} 类型${t.retyped} / 新增字段${t.added} / 类${t.classes}`);
  if (unresolved.size) console.log(`未在 C# 中找到的类 (${unresolved.size}):`, [...unresolved].slice(0, 10).join(", "));
  if (unknownTypes.size) {
    console.log(`未识别类型明细 (${unknownTypes.size} 种):`);
    for (const [t, n] of [...unknownTypes.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12)) {
      console.log(`   ${t} × ${n}`);
    }
  }
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