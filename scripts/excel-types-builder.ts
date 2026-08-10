import { parseFile, extractTypeNames, type ClassDef, type EnumDef } from "./playerdata-parser";
import { applyExcelAdapt, allTableRoots, EXCEL_ENUM_ADDITIONS } from "./excel-server-adapt";

/** PlayerDataModel 类型闭包（类），字段类型引用传递——多根版本 */
function buildClassClosure(classes: ClassDef[], roots: string[]): Set<string> {
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

function generateEnumCode(enumDef: EnumDef): string {
  const additions = EXCEL_ENUM_ADDITIONS[enumDef.name] ?? [];
  const values = [...new Set([...enumDef.values, ...additions])];
  if (values.length === 0) return `export type ${enumDef.name} = string;`;
  const joined = values.map(v => `"${v}"`).join(" | ");
  return `export type ${enumDef.name} = ${joined};`;
}

function generateInterfaceCode(classDef: ClassDef): string {
  // 整接口覆盖为类型别名（excel 适配层用，如继承类补全）
  if (classDef.aliasType !== undefined) {
    return `export type ${classDef.name} = ${classDef.aliasType};`;
  }
  // List 继承类 → 数组别名（如 Blackboard : List<BlackboardDataPair>）
  if (classDef.arrayOfType !== undefined) {
    return `export type ${classDef.name} = ${classDef.arrayOfType}[];`;
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
  missingRoots: string[];
}

/**
 * 从 C# 反编译内容构建 excel 表类型定义。
 * 多根闭包：所有表根类的字段类型传递可达的类与枚举。
 * 自检：字段引用的 Torappu 类型必须全部已定义，否则抛错。
 */
export function buildExcelTypes(content: string): BuildResult {
  const { classes, enums } = parseFile(content);
  const classByName = new Map(classes.map(c => [c.name, c]));

  const missingRoots = allTableRoots().filter(r => !classByName.has(r));
  if (missingRoots.length > 0) {
    throw new Error(`excel 表根类在 cs 中不存在: ${missingRoots.join(", ")}`);
  }

  const roots = allTableRoots();
  const classClosure = buildClassClosure(classes, roots);
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
    throw new Error(`excel 类型闭包存在未定义引用: ${[...missing].join(", ")}`);
  }

  // excel 服务端协议适配（表结构修正，数据驱动）
  const adaptedClasses = applyExcelAdapt(filteredClasses);

  let output = "/**\n";
  output += " * 自动生成的 excel 表类型定义文件\n";
  output += " * 从 reference/com.hypergryph.arknights_2.7.61.cs 反编译文件生成\n";
  output += " * （客户端表类闭包 + excel 协议适配，见 scripts/excel-server-adapt.ts）\n";
  output += " * 生成命令: npm run generate:excel\n";
  output += " * 请勿手动修改此文件\n";
  output += " */\n\n";

  filteredEnums.forEach(enumDef => {
    output += generateEnumCode(enumDef);
    output += "\n\n";
  });
  adaptedClasses.forEach(classDef => {
    output += generateInterfaceCode(classDef);
    output += "\n\n";
  });

  return {
    output,
    classes: adaptedClasses.map(c => c.name),
    enums: filteredEnums.map(e => e.name),
    missingRoots,
  };
}
