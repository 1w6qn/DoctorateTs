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
  "System.DateTime": "string",
  "System.Double": "number",
  "System.Single": "number",
  "System.Byte": "number",
  "System.UInt32": "number",
  "System.Char": "string",
  "System.Decimal": "number",
  "Newtonsoft.Json.Linq.JObject": "object",
  "Newtonsoft.Json.Linq.JToken": "object",
  "GridPosition": "object",
  "FP": "number",
  "SandboxV3TaskOption": "object",
  "Decimal": "number",
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

  const torappuMatch = csharpType.match(/^Torappu\.(.+)$/);
  if (torappuMatch) return torappuMatch[1].replace(/\./g, "_");

  if (csharpType.includes(".") && !csharpType.startsWith("System.")) {
    return csharpType.split(".").pop() || csharpType;
  }
  return csharpType;
}

/** 全限定名 → 类型名：Torappu.X.Y → X_Y */
export function parseClassName(fullName: string): string {
  const match = fullName.match(/^Torappu\.(.+)$/);
  if (match) return match[1].replace(/\./g, "_");
  return fullName;
}

/** 从类型字符串提取所有 Torappu.* 引用（短名），排除泛型容器类型 */
const TORAPPU_CONTAINER_TYPES = new Set(["Torappu.ListDict"]);

export function extractTypeNames(typeStr: string): string[] {
  const names: string[] = [];
  const re = /Torappu\.[A-Za-z0-9_.]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(typeStr)) !== null) {
    if (TORAPPU_CONTAINER_TYPES.has(m[0])) continue; // ListDict 等容器在 mapType 已展开
    const name = parseClassName(m[0]);
    if (!names.includes(name)) names.push(name);
  }
  return names;
}

/** 解析整个反编译文件：类 + 枚举（括号配对，无嵌套花括号假设） */
export function parseFile(content: string): { classes: ClassDef[]; enums: EnumDef[] } {
  const classes: ClassDef[] = [];
  const enums: EnumDef[] = [];

  const classRe = /public (?:class|struct) (Torappu\.[A-Za-z0-9_.]+)\s*:[^\{]*\{/g;
  let m: RegExpExecArray | null;
  while ((m = classRe.exec(content)) !== null) {
    const fullName = m[1];
    const braceStart = m.index + m[0].length - 1;
    const braceEnd = findMatchingBracket(content, braceStart);
    if (braceEnd === -1) continue;
    const body = content.slice(braceStart + 1, braceEnd);

    const fields: FieldDef[] = [];
    const fieldRe = /public\s+(?:static\s+)?(?:readonly\s+)?(?:const\s+)?([A-Za-z0-9_.<>,\s]+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/g;
    let fm: RegExpExecArray | null;
    while ((fm = fieldRe.exec(body)) !== null) {
      const rawType = fm[1].trim();
      const fieldName = fm[2];
      if (fieldName !== "value__") {
        fields.push({ name: fieldName, rawType, type: mapType(rawType) });
      }
    }
    classes.push({ fullName, name: parseClassName(fullName), fields });
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
