import * as fs from "fs";
import * as path from "path";

interface FieldDef {
  name: string;
  rawType: string;
  type: string;
}

interface ClassDef {
  fullName: string;
  name: string;
  fields: FieldDef[];
}

interface EnumDef {
  fullName: string;
  name: string;
  values: string[];
}

const INPUT_FILE = path.join(__dirname, "../com.hypergryph.arknights_2.7.51.cs");
const OUTPUT_FILE = path.join(__dirname, "../app/excel/types-playerdata.ts");

const CSHARP_TO_TS_TYPE_MAP: { [key: string]: string } = {
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

function findMatchingBracket(str: string, startIndex: number): number {
  let depth = 1;
  for (let i = startIndex + 1; i < str.length; i++) {
    if (str[i] === "<") depth++;
    if (str[i] === ">") depth--;
    if (depth === 0) return i;
  }
  return str.length;
}

function parseGenericArguments(typeStr: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let currentArg = "";
  
  for (let i = 0; i < typeStr.length; i++) {
    const char = typeStr[i];
    if (char === "<") {
      depth++;
      currentArg += char;
    } else if (char === ">") {
      depth--;
      currentArg += char;
    } else if (char === "," && depth === 0) {
      args.push(currentArg.trim());
      currentArg = "";
    } else {
      currentArg += char;
    }
  }
  
  if (currentArg.trim()) {
    args.push(currentArg.trim());
  }
  
  return args;
}

function mapType(csharpType: string): string {
  csharpType = csharpType.trim();
  
  if (CSHARP_TO_TS_TYPE_MAP[csharpType]) {
    return CSHARP_TO_TS_TYPE_MAP[csharpType];
  }
  
  const dictIndex = csharpType.indexOf("System.Collections.Generic.Dictionary<");
  if (dictIndex !== -1) {
    const start = dictIndex + "System.Collections.Generic.Dictionary<".length;
    const end = findMatchingBracket(csharpType, start - 1);
    const inner = csharpType.substring(start, end);
    const args = parseGenericArguments(inner);
    if (args.length === 2) {
      const keyType = mapType(args[0]);
      const valueType = mapType(args[1]);
      const safeKeyType = ["string", "number", "boolean"].includes(keyType) ? keyType : "string";
      return `{ [key: ${safeKeyType}]: ${valueType} }`;
    }
  }
  
  const listIndex = csharpType.indexOf("System.Collections.Generic.List<");
  if (listIndex !== -1) {
    const start = listIndex + "System.Collections.Generic.List<".length;
    const end = findMatchingBracket(csharpType, start - 1);
    const inner = csharpType.substring(start, end);
    const args = parseGenericArguments(inner);
    if (args.length === 1) {
      const innerType = mapType(args[0]);
      return `${innerType}[]`;
    }
  }
  
  const hashSetIndex = csharpType.indexOf("System.Collections.Generic.HashSet<");
  if (hashSetIndex !== -1) {
    const start = hashSetIndex + "System.Collections.Generic.HashSet<".length;
    const end = findMatchingBracket(csharpType, start - 1);
    const inner = csharpType.substring(start, end);
    const args = parseGenericArguments(inner);
    if (args.length === 1) {
      const innerType = mapType(args[0]);
      return `${innerType}[]`;
    }
  }
  
  const listDictIndex = csharpType.indexOf("Torappu.ListDict<");
  if (listDictIndex !== -1) {
    const start = listDictIndex + "Torappu.ListDict<".length;
    const end = findMatchingBracket(csharpType, start - 1);
    const inner = csharpType.substring(start, end);
    const args = parseGenericArguments(inner);
    if (args.length === 2) {
      const keyType = mapType(args[0]);
      const valueType = mapType(args[1]);
      const safeKeyType = ["string", "number", "boolean"].includes(keyType) ? keyType : "string";
      return `{ [key: ${safeKeyType}]: ${valueType}[] }`;
    }
  }
  
  const torappuMatch = csharpType.match(/^Torappu\.(.+)$/);
  if (torappuMatch) {
    return torappuMatch[1].replace(/\./g, "_");
  }
  
  if (csharpType.includes(".") && !csharpType.startsWith("System.")) {
    return csharpType.split(".").pop() || csharpType;
  }
  
  if (csharpType === "Decimal") {
    return "number";
  }
  
  return csharpType;
}

function parseClassName(fullName: string): string {
  const match = fullName.match(/^Torappu\.(.+)$/);
  if (match) {
    return match[1].replace(/\./g, "_");
  }
  return fullName;
}

function parseFile(content: string): { classes: ClassDef[]; enums: EnumDef[] } {
  const classes: ClassDef[] = [];
  const enums: EnumDef[] = [];
  
  const classRegex = /public (?:class|struct) (Torappu\.[a-zA-Z0-9_.]+)\s*:\s*[^;]+\{([^}]+)\}/g;
  let classMatch;
  while ((classMatch = classRegex.exec(content)) !== null) {
    const fullName = classMatch[1];
    const body = classMatch[2];
    
    const fields: FieldDef[] = [];
    const fieldRegex = /public\s+(?:static\s+)?(?:readonly\s+)?(?:const\s+)?([a-zA-Z0-9_.<>,\s]+?)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;/g;
    let fieldMatch;
    while ((fieldMatch = fieldRegex.exec(body)) !== null) {
      const rawType = fieldMatch[1].trim();
      const fieldName = fieldMatch[2];
      
      if (fieldName !== "value__") {
        fields.push({
          name: fieldName,
          rawType,
          type: mapType(rawType),
        });
      }
    }
    
    const name = parseClassName(fullName);
    classes.push({
      fullName,
      name,
      fields,
    });
  }
  
  const enumRegex = /public enum (Torappu\.[a-zA-Z0-9_.]+)\s*:\s*[^;]+\{([^}]+)\}/g;
  let enumMatch;
  while ((enumMatch = enumRegex.exec(content)) !== null) {
    const fullName = enumMatch[1];
    const body = enumMatch[2];
    
    const values: string[] = [];
    const valueRegex = /public\s+const\s+[a-zA-Z0-9_.]+\s+([A-Z_]+)\s*=\s*\d+/g;
    let valueMatch;
    while ((valueMatch = valueRegex.exec(body)) !== null) {
      values.push(valueMatch[1]);
    }
    
    const name = parseClassName(fullName);
    enums.push({
      fullName,
      name,
      values,
    });
  }
  
  return { classes, enums };
}

function generateEnumCode(enumDef: EnumDef): string {
  if (enumDef.values.length === 0) {
    return `export type ${enumDef.name} = string;`;
  }
  const values = enumDef.values.map(v => `"${v}"`).join(" | ");
  return `export type ${enumDef.name} = ${values};`;
}

function generateInterfaceCode(classDef: ClassDef): string {
  if (classDef.fields.length === 0) {
    return `export interface ${classDef.name} {}`;
  }
  
  const fields = classDef.fields
    .map(f => `    ${f.name}: ${f.type};`)
    .join("\n");
  
  return `export interface ${classDef.name} {
${fields}
}`;
}

function main() {
  console.log("读取 C# 反编译文件...");
  const content = fs.readFileSync(INPUT_FILE, "utf-8");
  console.log(`文件大小: ${(content.length / 1024 / 1024).toFixed(2)} MB`);
  
  console.log("解析类和枚举定义...");
  const { classes, enums } = parseFile(content);
  console.log(`找到 ${classes.length} 个类，${enums.length} 个枚举`);
  
  console.log("过滤 PlayerDataModel 相关类型...");
  const playerDataModelClass = classes.find(c => c.name === "PlayerDataModel");
  if (!playerDataModelClass) {
    console.error("未找到 PlayerDataModel 类");
    process.exit(1);
  }
  
  function extractTypeNames(typeStr: string): string[] {
    const names: string[] = [];
    const torappuMatch = typeStr.match(/Torappu\.[a-zA-Z0-9_.]+/g);
    if (torappuMatch) {
      torappuMatch.forEach(t => {
        const name = parseClassName(t);
        if (!names.includes(name)) {
          names.push(name);
        }
      });
    }
    return names;
  }
  
  const allTypesToInclude = new Set<string>();
  allTypesToInclude.add("PlayerDataModel");
  
  let changed = true;
  let iteration = 0;
  while (changed && iteration < 20) {
    changed = false;
    iteration++;
    classes.forEach(c => {
      if (allTypesToInclude.has(c.name)) {
        c.fields.forEach(f => {
          const typeNames = extractTypeNames(f.rawType);
          typeNames.forEach(typeName => {
            if (!allTypesToInclude.has(typeName)) {
              allTypesToInclude.add(typeName);
              changed = true;
            }
          });
        });
      }
    });
  }
  
  const filteredClasses = classes.filter(c => allTypesToInclude.has(c.name));
  
  const enumTypeNames = new Set<string>();
  filteredClasses.forEach(c => {
    c.fields.forEach(f => {
      const typeNames = extractTypeNames(f.rawType);
      typeNames.forEach(typeName => {
        enumTypeNames.add(typeName);
      });
    });
  });
  
  const filteredEnums = enums.filter(e => enumTypeNames.has(e.name) || e.name.includes("Player") || e.name.includes("Charm") || 
    e.name.includes("Voice") || e.name.includes("NameCard") || e.name.includes("AutoChess") || 
    e.name.includes("Roguelike") || e.name.includes("Tower") || e.name.includes("Dormitory") ||
    e.name.includes("Building") || e.name.includes("Stage") || e.name.includes("Zone") ||
    e.name.includes("Mission") || e.name.includes("Campaign") || e.name.includes("Recruit") ||
    e.name.includes("Gacha") || e.name.includes("Skin") || e.name.includes("Medal") ||
    e.name.includes("Equip") || e.name.includes("Inventory") || e.name.includes("Ticket") ||
    e.name.includes("Consumable") || e.name.includes("Shop") || e.name.includes("Invite") ||
    e.name.includes("Social") || e.name.includes("Crisis") || e.name.includes("DeepSea") ||
    e.name.includes("Siracusa") || e.name.includes("Firework") || e.name.includes("Sandbox") ||
    e.name.includes("Emoticon") || e.name.includes("Collection") || e.name.includes("Training") ||
    e.name.includes("Home") || e.name.includes("AprilFool") || e.name.includes("CharRotation") ||
    e.name.includes("Gallery") || e.name.includes("Mainline") || e.name.includes("Limited") ||
    e.name.includes("Performance") || e.name.includes("Cart") || e.name.includes("Activity"));
  
  console.log(`过滤后: ${filteredClasses.length} 个类，${filteredEnums.length} 个枚举`);
  
  console.log("生成类型定义文件...");
  let outputContent = "/**\n";
  outputContent += " * 自动生成的玩家数据类型定义文件\n";
  outputContent += " * 从 com.hypergryph.arknights_2.7.51.cs 反编译文件生成\n";
  outputContent += " * 请勿手动修改此文件\n";
  outputContent += " */\n\n";
  
  filteredEnums.forEach(enumDef => {
    outputContent += generateEnumCode(enumDef);
    outputContent += "\n\n";
  });
  
  filteredClasses.forEach(classDef => {
    outputContent += generateInterfaceCode(classDef);
    outputContent += "\n\n";
  });
  
  fs.writeFileSync(OUTPUT_FILE, outputContent);
  console.log(`生成完成: ${OUTPUT_FILE}`);
  console.log(`文件大小: ${(outputContent.length / 1024).toFixed(2)} KB`);
}

main();