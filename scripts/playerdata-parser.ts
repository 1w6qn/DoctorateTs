import * as fs from "fs";

export interface FieldDef {
  name: string;
  rawType: string;
  type: string;
}

export interface ClassDef {
  fullName: string;
  name: string;
  fields: FieldDef[];
  /** 整接口覆盖为类型别名时使用（如服务端字典结构）：输出 export type X = aliasType; */
  aliasType?: string;
  /** 可选字段名（线格式中服务端常省略，如单抽池基础字段）；生成时输出 name?: type */
  optionalFields?: string[];
  /** 基类名（Torappu 继承，字段已合并入 fields） */
  baseName?: string;
  /** List 继承类（如 Blackboard : List<BlackboardDataPair>）：输出 export type X = element[] */
  arrayOfType?: string;
}

export interface EnumDef {
  fullName: string;
  name: string;
  values: string[];
}

export const CSHARP_TO_TS_TYPE_MAP: { [key: string]: string } = {
  "System.String": "string",
  "System.Int32": "number",
  "System.Int64": "number",
  "System.Boolean": "boolean",
  "System.DateTime": "number", // 线格式：unix 时间戳（int），非 string
  "System.Double": "number",
  "System.Single": "number",
  "System.Byte": "number",
  "System.UInt32": "number",
  "System.Char": "string",
  "System.Decimal": "number",
  "System.Object": "object",
  "System.ValueType": "object",
  "Newtonsoft.Json.Linq.JObject": "object",
  "Newtonsoft.Json.Linq.JToken": "object",
  "GridPosition": "object",
  "FP": "number",
  "SandboxV3TaskOption": "object",
  "Decimal": "number",
  "Vector2": "object",
  "Vector3": "object",
  "Vector4": "object",
  "Color": "object",
  "Rect": "object",
  "ObscuredInt": "number",
  "ObscuredFloat": "number",
  "ObscuredLong": "number",
};

/** 从 content[start]（须为 '{' 或 '<'）开始找配对闭合符索引 */
export function findMatchingBracket(content: string, start: number, open = "{", close = "}"): number {
  let depth = 1;
  for (let i = start + 1; i < content.length; i++) {
    if (content[i] === open) depth++;
    else if (content[i] === close) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** 解析泛型参数（逗号分隔，深度感知） */
export function parseGenericArguments(typeStr: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let currentArg = "";
  for (let i = 0; i < typeStr.length; i++) {
    const char = typeStr[i];
    if (char === "<") depth++;
    else if (char === ">") depth--;
    if (char === "," && depth === 0) {
      args.push(currentArg.trim());
      currentArg = "";
    } else {
      currentArg += char;
    }
  }
  if (currentArg.trim()) args.push(currentArg.trim());
  return args;
}

/** C# 类型 → TS 类型 */
export function mapType(csharpType: string): string {
  csharpType = csharpType.trim();
  if (CSHARP_TO_TS_TYPE_MAP[csharpType]) return CSHARP_TO_TS_TYPE_MAP[csharpType];

  const dictPrefix = "System.Collections.Generic.Dictionary<";
  if (csharpType.startsWith(dictPrefix)) {
    const inner = csharpType.slice(dictPrefix.length, csharpType.length - 1);
    const args = parseGenericArguments(inner);
    if (args.length === 2) {
      const keyType = mapType(args[0]);
      const valueType = mapType(args[1]);
      const safeKeyType = ["string", "number", "boolean"].includes(keyType) ? keyType : "string";
      return `{ [key: ${safeKeyType}]: ${valueType} }`;
    }
  }

  const listPrefix = "System.Collections.Generic.List<";
  if (csharpType.startsWith(listPrefix)) {
    const inner = csharpType.slice(listPrefix.length, csharpType.length - 1);
    const args = parseGenericArguments(inner);
    if (args.length === 1) return `${mapType(args[0])}[]`;
  }

  const hashSetPrefix = "System.Collections.Generic.HashSet<";
  if (csharpType.startsWith(hashSetPrefix)) {
    const inner = csharpType.slice(hashSetPrefix.length, csharpType.length - 1);
    const args = parseGenericArguments(inner);
    if (args.length === 1) return `${mapType(args[0])}[]`;
  }

  const listDictPrefix = "Torappu.ListDict<";
  if (csharpType.startsWith(listDictPrefix)) {
    const inner = csharpType.slice(listDictPrefix.length, csharpType.length - 1);
    const args = parseGenericArguments(inner);
    if (args.length === 2) {
      const keyType = mapType(args[0]);
      const valueType = mapType(args[1]);
      const safeKeyType = ["string", "number", "boolean"].includes(keyType) ? keyType : "string";
      // ListDict 的 JSON 序列化是字典（如 consumable: { [itemId]: { [instId]: item } }），非数组
      return `{ [key: ${safeKeyType}]: ${valueType} }`;
    }
  }

  // KeyValuePair<K,V>：Newtonsoft/Unity JSON 序列化为 { Key: K; Value: V }
  const kvpPrefix = "System.Collections.Generic.KeyValuePair<";
  if (csharpType.startsWith(kvpPrefix)) {
    const inner = csharpType.slice(kvpPrefix.length, csharpType.length - 1);
    const args = parseGenericArguments(inner);
    if (args.length === 2) {
      return `{ Key: ${mapType(args[0])}; Value: ${mapType(args[1])} }`;
    }
  }

  // 泛型 Torappu 类型：Undefinable<T> 透明展开（JSON 序列化为 T 或 null）；其余取类型名
  const genericTorappuMatch = csharpType.match(/^Torappu\.(.+?)<(.+)>$/);
  if (genericTorappuMatch) {
    const baseName = genericTorappuMatch[1];
    if (baseName === "Undefinable") return mapType(genericTorappuMatch[2]);
    return parseClassName(`Torappu.${baseName}`);
  }

  // C# 数组语法 X[]（excel 表类大量使用，playerdata 多为 List<X>）
  const arrMatch = csharpType.match(/^(.+)\[\]$/);
  if (arrMatch) return `${mapType(arrMatch[1])}[]`;

  const torappuMatch = csharpType.match(/^Torappu\.(.+)$/);
  if (torappuMatch) return torappuMatch[1].replace(/\./g, "_");

  if (csharpType.includes(".") && !csharpType.startsWith("System.")) {
    const short = csharpType.split(".").pop() || csharpType;
    if (CSHARP_TO_TS_TYPE_MAP[short]) return CSHARP_TO_TS_TYPE_MAP[short];
    return short;
  }
  // 泛型参数（如 RoomBean<TParam> 的 TParam）：抽象占位，JSON 中为具体结构
  if (/^[A-Z][A-Za-z0-9_]*$/.test(csharpType)) return "object";
  return csharpType;
}

/** 全限定名 → 类型名：Torappu.X.Y → X_Y */
export function parseClassName(fullName: string): string {
  const match = fullName.match(/^Torappu\.(.+)$/);
  if (match) return match[1].replace(/\./g, "_");
  return fullName;
}

/** 从类型字符串提取所有 Torappu.* 引用（短名），排除泛型容器类型 */
const TORAPPU_CONTAINER_TYPES = new Set(["Torappu.ListDict", "Torappu.Undefinable"]);

export function extractTypeNames(typeStr: string): string[] {
  const names: string[] = [];
  const re = /Torappu\.[A-Za-z0-9_.]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(typeStr)) !== null) {
    if (TORAPPU_CONTAINER_TYPES.has(m[0])) continue; // ListDict/Undefinable 等容器在 mapType 已展开
    const name = parseClassName(m[0]);
    if (!names.includes(name)) names.push(name);
  }
  return names;
}

/** 解析整个反编译文件：类 + 枚举（括号配对，无嵌套花括号假设）；含继承字段合并与 List 继承别名 */
export function parseFile(content: string): { classes: ClassDef[]; enums: EnumDef[] } {
  const classes: ClassDef[] = [];
  const enums: EnumDef[] = [];

  const classRe = /public (?:abstract )?(?:class|struct) (Torappu\.[A-Za-z0-9_.]+)(?:<[^>]*>)?\s*(?::([^\{]*))?\{/g;
  let m: RegExpExecArray | null;
  while ((m = classRe.exec(content)) !== null) {
    const fullName = m[1];
    const baseDecl = m[2] ? m[2].trim() : "";
    const braceStart = m.index + m[0].length - 1;
    const braceEnd = findMatchingBracket(content, braceStart);
    if (braceEnd === -1) continue;
    const body = content.slice(braceStart + 1, braceEnd);

    const fields: FieldDef[] = [];
    const fieldRe = /public\s+(?:static\s+)?(?:readonly\s+)?(?:const\s+)?([A-Za-z0-9_.<>,\s\[\]]+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/g;
    let fm: RegExpExecArray | null;
    while ((fm = fieldRe.exec(body)) !== null) {
      const rawType = fm[1].trim();
      const fieldName = fm[2];
      if (fieldName !== "value__") {
        fields.push({ name: fieldName, rawType, type: mapType(rawType) });
      }
    }

    const def: ClassDef = { fullName, name: parseClassName(fullName), fields };
    // List<T> 继承类 → 数组别名（允许多基类，如 : List<X>, Torappu.IHotfixable）
    const listBase = baseDecl.match(/^System\.Collections\.Generic\.List<(.+)>(?:,.*)?$/);
    if (listBase) {
      def.arrayOfType = mapType(listBase[1]);
    } else if (baseDecl.startsWith("Torappu.")) {
      def.baseName = parseClassName(baseDecl.split(",")[0].trim());
    }
    classes.push(def);
  }

  // 继承字段合并：基类字段在前，子类字段覆盖重名；List 继承沿链传递（含泛型基类与同名泛型变体）
  const byNameList = new Map<string, ClassDef[]>();
  for (const c of classes) {
    const list = byNameList.get(c.name) ?? [];
    list.push(c);
    byNameList.set(c.name, list);
  }
  const resolveChain = (baseName: string, seen: Set<ClassDef>): ClassDef[] => {
    const short = baseName.replace(/<.*$/, "");
    const variants = byNameList.get(short) ?? [];
    for (const v of variants) {
      if (seen.has(v)) continue;
      if (v.arrayOfType) return [v]; // 数组别名优先（List 继承终止）
      if (v.baseName) {
        const next = resolveChain(v.baseName, new Set([...seen, v]));
        if (next.length) return [v, ...next];
      } else {
        return [v]; // 基类无进一步基类：并入其字段
      }
    }
    return [];
  };
  for (const c of classes) {
    if (c.arrayOfType) continue; // 数组别名类无字段
    const chain = c.baseName ? resolveChain(c.baseName, new Set([c])) : [];
    // List 继承沿链传递：任一基类为数组别名，子类同
    for (const b of chain) {
      if (b.arrayOfType) {
        c.arrayOfType = b.arrayOfType;
        c.baseName = b.name;
        break;
      }
    }
    if (c.arrayOfType) continue;
    const merged: FieldDef[] = [];
    const seen = new Set<string>();
    for (const b of chain) {
      for (const f of b.fields) {
        if (!seen.has(f.name)) {
          seen.add(f.name);
          merged.push(f);
        }
      }
    }
    for (const f of c.fields) {
      if (!seen.has(f.name)) {
        seen.add(f.name);
        merged.push(f);
      }
    }
    if (merged.length > c.fields.length) c.fields = merged;
  }

  const enumRe = /public enum (Torappu\.[A-Za-z0-9_.]+)\s*:[^\{]*\{/g;
  while ((m = enumRe.exec(content)) !== null) {
    const fullName = m[1];
    const braceStart = m.index + m[0].length - 1;
    const braceEnd = findMatchingBracket(content, braceStart);
    if (braceEnd === -1) continue;
    const body = content.slice(braceStart + 1, braceEnd);

    const values: string[] = [];
    // 完整标识符：允许混合大小写/数字（None、SingleTicket、T1D5、SYS_Report）
    const valueRe = /public\s+const\s+[A-Za-z0-9_.]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*-?\d+/g;
    let vm: RegExpExecArray | null;
    while ((vm = valueRe.exec(body)) !== null) {
      values.push(vm[1]);
    }
    enums.push({ fullName, name: parseClassName(fullName), values });
  }

  return { classes, enums };
}
