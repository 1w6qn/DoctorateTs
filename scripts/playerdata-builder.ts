import { parseFile, extractTypeNames, type ClassDef, type EnumDef } from "./playerdata-parser";
import { applyServerAdapt, applyWireFormat } from "./playerdata-server-adapt";

/** PlayerDataModel 类型闭包（类），字段类型引用传递 */
function buildClassClosure(classes: ClassDef[], rootName: string): Set<string> {
  const included = new Set<string>([rootName]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const c of classes) {
      if (!included.has(c.name)) continue;
      for (const f of c.fields) {
        for (const ref of extractTypeNames(f.rawType)) {
          if (!included.has(ref)) {
            included.add(ref);
            changed = true;
          }
        }
      }
    }
  }
  return included;
}

function generateEnumCode(enumDef: EnumDef): string {
  if (enumDef.values.length === 0) return `export type ${enumDef.name} = string;`;
  const values = enumDef.values.map(v => `"${v}"`).join(" | ");
  return `export type ${enumDef.name} = ${values};`;
}

function generateInterfaceCode(classDef: ClassDef): string {
  // 整接口覆盖为类型别名（服务端字典结构，如 PlayerActivity）
  if (classDef.aliasType !== undefined) {
    return `export type ${classDef.name} = ${classDef.aliasType};`;
  }
  if (classDef.fields.length === 0) return `export interface ${classDef.name} {}`;
  const optional = new Set(classDef.optionalFields ?? []);
  const fields = classDef.fields
    .map(f => `    ${f.name}${optional.has(f.name) ? "?" : ""}: ${f.type};`)
    .join("\n");
  return `export interface ${classDef.name} {\n${fields}\n}`;
}

export interface BuildResult {
  output: string;
  classes: string[];
  enums: string[];
}

/**
 * 从 C# 反编译内容构建完整的 PlayerDataModel 类型定义。
 * 纯闭包：仅保留 PlayerDataModel 字段类型传递可达的类与枚举。
 * 自检：字段引用的 Torappu 类型必须全部已定义，否则抛错。
 */
export function buildPlayerDataTypes(content: string): BuildResult {
  const { classes, enums } = parseFile(content);

  const classClosure = buildClassClosure(classes, "PlayerDataModel");
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
    throw new Error(`PlayerDataModel 类型闭包存在未定义引用: ${[...missing].join(", ")}`);
  }

  // 服务端协议适配（客户端字段名 → 服务端 JSON key，补充/覆盖服务端独有结构）
  const adaptedClasses = applyServerAdapt(filteredClasses);

  // 线格式适配（枚举/布尔/DateTime → number，真实服务端 JSON 序列化格式）
  const enumNames = new Set(filteredEnums.map(e => e.name));
  const wireClasses = applyWireFormat(adaptedClasses, enumNames);

  let output = "/**\n";
  output += " * 自动生成的玩家数据类型定义文件\n";
  output += " * 从 reference/com.hypergryph.arknights_2.7.61.cs 反编译文件生成\n";
  output += " * （客户端闭包 + 服务端协议适配 + 线格式适配，见 scripts/playerdata-server-adapt.ts）\n";
  output += " * 生成命令: npm run generate:playerdata\n";
  output += " * 请勿手动修改此文件\n";
  output += " */\n\n";

  filteredEnums.forEach(enumDef => {
    output += generateEnumCode(enumDef);
    output += "\n\n";
  });
  wireClasses.forEach(classDef => {
    output += generateInterfaceCode(classDef);
    output += "\n\n";
  });

  return {
    output,
    classes: wireClasses.map(c => c.name),
    enums: filteredEnums.map(e => e.name),
  };
}
