import { parseFile, extractTypeNames, type ClassDef, type EnumDef } from "./playerdata-parser";

/**
 * 类型闭包构建共用模块（playerdata / excel 两个域共用）
 *
 * 从 C# 反编译内容构建「根类闭包」的 TS 类型定义：多根闭包、枚举补充、
 * 索引签名、未定义引用自检。各域只提供 roots/adapt/输出配置。
 */

/** 类型闭包（类），字段类型引用传递——多根版本 */
export function buildClassClosure(classes: ClassDef[], roots: string[]): Set<string> {
  const included = new Set<string>(roots);
  let changed = true;
  while (changed) {
    changed = false;
    for (const c of classes) {
      if (!included.has(c.name)) continue;
      // 字段类型引用
      for (const f of c.fields) {
        for (const ref of extractTypeNames(f.rawType)) {
          if (!included.has(ref)) {
            included.add(ref);
            changed = true;
          }
        }
      }
      // 数组别名元素（如 Blackboard = Blackboard_DataPair[]）
      if (c.arrayOfType && !included.has(c.arrayOfType)) {
        included.add(c.arrayOfType);
        changed = true;
      }
    }
  }
  return included;
}

export interface TypesBuildConfig {
  /** 根类名（闭包起点，多根） */
  roots: string[];
  /** 输出文件顶部的 import 行（生成文件不产生隐式全局依赖） */
  importLines?: string[];
  /**
   * 未建模字段（哨兵 `object`）归一化后的类型名
   *
   * 默认 `JsonValue`（递归，适用于只读的 excel 表数据）。
   * 玩家存档域必须传 `ServerPayload`：`Draft<PlayerDataModel>` 无法承受递归类型。
   */
  jsonTypeName?: string;
  /** 域适配函数（playerdata：服务端协议 + wire pass；excel：表结构适配）；第二个参数为闭包枚举名 */
  adapt: (classes: ClassDef[], enumNames: Set<string>) => ClassDef[];
  /** 枚举值补充（JSON 含客户端枚举未定义的新值） */
  enumAdditions?: Record<string, string[]>;
  /** 附加索引签名的接口（运行时以 dict 键访问） */
  indexSignatures?: string[];
  /** 输出头注行 */
  headerLines: string[];
}

export interface BuildResult {
  output: string;
  classes: string[];
  enums: string[];
}

/**
 * 把生成类型里的 `object` 关键字改写为严格的 JSON 域类型 `JsonValue`
 *
 * `object`（TS 关键字）既不可索引也不可取属性，调用方只能靠 `as any` 逃生，
 * 是历史类型债的主要来源。生成器把它统一收敛到 app/game/excel/json-value.ts
 * 的 `JsonValue` 递归联合——语义相同（未校验 JSON），但保持严格可检查。
 * 只匹配类型位置的裸 `object`：排除成员访问（`z.object`）与更长的标识符（`objectId`）。
 * @param type - 生成器内部的 TS 类型字符串（哨兵值可为 `object`）
 * @returns 归一化后的 TS 类型字符串（不再含裸 `object`）
 */
export function normalizeJsonType(type: string, jsonTypeName = "JsonValue"): string {
  return type.replace(/(?<![\w$.])object\b/g, jsonTypeName);
}

export function generateEnumCode(enumDef: EnumDef, additions: string[] = []): string {
  const values = [...new Set([...enumDef.values, ...additions])];
  if (values.length === 0) return `export type ${enumDef.name} = string;`;
  const joined = values.map(v => `"${v}"`).join(" | ");
  return `export type ${enumDef.name} = ${joined};`;
}

export function generateInterfaceCode(
  classDef: ClassDef,
  indexSignatures: string[] = [],
  jsonTypeName = "JsonValue",
): string {
  // 整接口覆盖为类型别名（服务端字典结构/继承类补全）
  if (classDef.aliasType !== undefined) {
    return `export type ${classDef.name} = ${normalizeJsonType(classDef.aliasType, jsonTypeName)};`;
  }
  // List 继承类 → 数组别名（如 Blackboard : List<BlackboardDataPair>）
  if (classDef.arrayOfType !== undefined) {
    return `export type ${classDef.name} = ${normalizeJsonType(classDef.arrayOfType, jsonTypeName)}[];`;
  }
  if (classDef.fields.length === 0 && !indexSignatures.includes(classDef.name)) {
    return `export interface ${classDef.name} {}`;
  }
  const optional = new Set(classDef.optionalFields ?? []);
  const fields = classDef.fields
    .map(
      f =>
        `    ${f.name}${optional.has(f.name) ? "?" : ""}: ${normalizeJsonType(f.type, jsonTypeName)};`,
    )
    .join("\n");
  const hasIndexSig = indexSignatures.includes(classDef.name);
  // 无字段：纯字典接口，直接给索引签名
  if (classDef.fields.length === 0) {
    return `export interface ${classDef.name} {\n    [key: string]: ${jsonTypeName};\n}`;
  }
  // 有字段 + 需要字典访问：用交叉类型而非在 interface 里塞索引签名。
  // interface 的索引签名要求所有已声明属性都可赋值给索引类型，而具名接口类型
  // 不具备隐式索引签名 → TS2411。交叉类型同时保留具名字段（精确）与任意键访问。
  if (hasIndexSig) {
    return `export type ${classDef.name} = {\n${fields}\n} & { [key: string]: ${jsonTypeName} };`;
  }
  return `export interface ${classDef.name} {\n${fields}\n}`;
}

/**
 * 从 C# 反编译内容构建类型闭包定义。
 * 自检：字段引用的 Torappu 类型必须全部已定义，否则抛错。
 */
export function buildTypes(content: string, config: TypesBuildConfig): BuildResult {
  const { classes, enums } = parseFile(content);
  const classByName = new Map(classes.map(c => [c.name, c]));

  const missingRoots = config.roots.filter(r => !classByName.has(r));
  if (missingRoots.length > 0) {
    throw new Error(`类型根类在 cs 中不存在: ${missingRoots.join(", ")}`);
  }

  const classClosure = buildClassClosure(classes, config.roots);
  const filteredClasses = classes.filter(c => classClosure.has(c.name));

  // 闭包枚举：闭包类的字段所引用的枚举
  const enumTypeNames = new Set<string>();
  filteredClasses.forEach(c => {
    c.fields.forEach(f => {
      extractTypeNames(f.rawType).forEach(t => enumTypeNames.add(t));
    });
  });
  const filteredEnums = enums.filter(e => enumTypeNames.has(e.name));

  // 自检：所有字段引用的 Torappu 类型都已定义
  const defined = new Set<string>([
    ...filteredClasses.map(c => c.name),
    ...filteredEnums.map(e => e.name),
    "string", "number", "boolean", "object",
  ]);
  const missing = new Set<string>();
  filteredClasses.forEach(c => {
    c.fields.forEach(f => {
      extractTypeNames(f.rawType).forEach(t => {
        if (!defined.has(t)) missing.add(t);
      });
    });
  });
  if (missing.size > 0) {
    throw new Error(`类型闭包存在未定义引用: ${[...missing].join(", ")}`);
  }

  // 域适配（服务端协议 / 表结构修正），传入闭包枚举名（wire pass 需要）
  const adaptedClasses = config.adapt(filteredClasses, new Set(filteredEnums.map(e => e.name)));
  const enumAdditions = config.enumAdditions ?? {};
  const indexSignatures = config.indexSignatures ?? [];

  let output = "/**\n";
  for (const line of config.headerLines) output += ` * ${line}\n`;
  output += " * 请勿手动修改此文件\n";
  output += " */\n";
  for (const line of config.importLines ?? []) output += `${line}\n`;
  output += "\n";

  filteredEnums.forEach(enumDef => {
    output += generateEnumCode(enumDef, enumAdditions[enumDef.name]);
    output += "\n\n";
  });
  adaptedClasses.forEach(classDef => {
    output += generateInterfaceCode(classDef, indexSignatures, config.jsonTypeName ?? "JsonValue");
    output += "\n\n";
  });

  return {
    output,
    classes: adaptedClasses.map(c => c.name),
    enums: filteredEnums.map(e => e.name),
  };
}
