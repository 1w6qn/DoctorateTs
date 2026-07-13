import * as fs from "fs";
import * as path from "path";

interface EnumValue {
  name: string;
  value: number;
}

interface EnumDef {
  originalName: string;
  name: string;
  values: EnumValue[];
}

interface FieldDef {
  name: string;
  originalName: string;
  type: string;
  isArray: boolean;
  isOptional: boolean;
}

interface TableDef {
  originalName: string;
  name: string;
  fields: FieldDef[];
}

const FBS_DIR = path.join(__dirname, "../OpenArknightsFBS/FBS");
const OUTPUT_DIR = path.join(__dirname, "../app/excel");

function toCamelCase(str: string): string {
  return str.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

function parseEnumName(name: string): string {
  const match = name.match(/^enum__Torappu_(.+)$/);
  if (match) {
    return match[1];
  }
  return name;
}

function parseClassName(name: string): string {
  const match = name.match(/^clz_Torappu_(.+)$/);
  if (match) {
    let result = match[1];
    result = result.replace(/_(\w)/g, (_, c) => c.toUpperCase());
    result = result.replace(/\./g, "_");
    result = result.replace(/KeyFrames_(\d+)_KeyFrame_/g, "KeyFrames");
    result = result.replace(/_Torappu_/g, "_");
    result = result.replace(/__/g, "_");
    return result.replace(/_$/, "");
  }

  const hgMatch = name.match(/^hg__internal__(.+)$/);
  if (hgMatch) {
    let result = hgMatch[1];
    result = result.replace(/_(\w)/g, (_, c) => c.toUpperCase());
    return result;
  }

  return name;
}

function parseTypeName(type: string): string {
  type = type.trim();

  const typeMap: { [key: string]: string } = {
    int: "number",
    long: "number",
    float: "number",
    double: "number",
    bool: "boolean",
    string: "string",
    byte: "number",
    short: "number",
    int8: "number",
    int16: "number",
    int32: "number",
    int64: "number",
    uint8: "number",
    uint16: "number",
    uint32: "number",
    uint64: "number",
    float32: "number",
    float64: "number",
    ubyte: "number",
    ushort: "number",
    char: "string",
  };

  if (typeMap[type]) {
    return typeMap[type];
  }

  if (type.startsWith("list_")) {
    const innerType = type.substring(5);
    return `${parseTypeName(innerType)}[]`;
  }

  const dictMatch = type.match(/^dict__(\w+)__(\w+)$/);
  if (dictMatch) {
    let keyType = parseTypeName(dictMatch[1]);
    const valueType = parseTypeName(dictMatch[2]);
    if (keyType !== "string" && keyType !== "number" && keyType !== "symbol") {
      keyType = "string";
    }
    return `{ [key: ${keyType}]: ${valueType} }`;
  }

  const enumMatch = type.match(/^enum__Torappu_(.+)$/);
  if (enumMatch) {
    return enumMatch[1];
  }

  const classMatch = type.match(/^clz_Torappu_(.+)$/);
  if (classMatch) {
    let result = classMatch[1];
    result = result.replace(/_(\w)/g, (_, c) => c.toUpperCase());
    result = result.replace(/\./g, "_");
    result = result.replace(/KeyFrames_(\d+)_KeyFrame_/g, "KeyFrames");
    result = result.replace(/_Torappu_/g, "_");
    result = result.replace(/__/g, "_");
    return result.replace(/_$/, "");
  }

  const torappuPrefixMatch = type.match(/^Torappu_(.+)$/);
  if (torappuPrefixMatch) {
    return torappuPrefixMatch[1];
  }

  const hgMatch = type.match(/^hg__internal__(.+)$/);
  if (hgMatch) {
    let result = hgMatch[1];
    result = result.replace(/_(\w)/g, (_, c) => c.toUpperCase());
    return result;
  }

  const kvpMatch = type.match(/^kvp__(\w+)__(\w+)$/);
  if (kvpMatch) {
    const keyType = parseTypeName(kvpMatch[1]);
    const valueType = parseTypeName(kvpMatch[2]);
    return `{ Key: ${keyType}; Value: ${valueType} }`;
  }

  const nestedMatch = type.match(/^(\w+)__(.+)$/);
  if (nestedMatch) {
    let keyType = parseTypeName(nestedMatch[1]);
    const valueType = parseTypeName(nestedMatch[2]);
    if (keyType !== "string" && keyType !== "number" && keyType !== "symbol") {
      keyType = "string";
    }
    return `{ [key: ${keyType}]: ${valueType} }`;
  }

  return type;
}

function parseTableName(name: string): string {
  if (name.startsWith("dict__") || name.startsWith("list_")) {
    return "";
  }

  const kvpMatch = name.match(/^kvp__(\w+)__(\w+)$/);
  if (kvpMatch) {
    const keyType = parseClassName(kvpMatch[1]);
    const valueType = parseClassName(kvpMatch[2]);
    return `Kvp${keyType}${valueType}`;
  }

  return parseClassName(name);
}

function parseFieldType(type: string): { type: string; isArray: boolean } {
  const arrayMatch = type.match(/^\[(.+)\]$/);
  if (arrayMatch) {
    const innerType = arrayMatch[1].trim();
    if (innerType.startsWith("dict__")) {
      return { type: parseTypeName(innerType), isArray: false };
    }
    return { type: parseTypeName(innerType), isArray: true };
  }

  const keyMatch = type.match(/^(\w+)\(key\)$/);
  if (keyMatch) {
    return { type: parseTypeName(keyMatch[1]), isArray: false };
  }

  return { type: parseTypeName(type), isArray: false };
}

function parseFbsFile(content: string): { enums: EnumDef[]; tables: TableDef[] } {
  const enums: EnumDef[] = [];
  const tables: TableDef[] = [];

  const enumRegex = /enum\s+(\w+)\s*:\s*\w+\s*\{([^}]+)\}/g;
  let enumMatch;
  while ((enumMatch = enumRegex.exec(content)) !== null) {
    const originalName = enumMatch[1];
    const valuesStr = enumMatch[2];
    const values: EnumValue[] = [];

    const valueRegex = /(\w+)\s*=\s*(\d+)/g;
    let valueMatch;
    while ((valueMatch = valueRegex.exec(valuesStr)) !== null) {
      values.push({
        name: valueMatch[1],
        value: parseInt(valueMatch[2], 10),
      });
    }

    const name = parseEnumName(originalName);
    if (!enums.some(e => e.name === name)) {
      enums.push({ originalName, name, values });
    }
  }

  const tableRegex = /table\s+(\w+)\s*\{([^}]+)\}/g;
  let tableMatch;
  while ((tableMatch = tableRegex.exec(content)) !== null) {
    const originalName = tableMatch[1];
    const fieldsStr = tableMatch[2];
    const fields: FieldDef[] = [];
    const fieldNames = new Set<string>();

    const fieldRegex = /(\w+)\s*:\s*([^;]+);/g;
    let fieldMatch;
    while ((fieldMatch = fieldRegex.exec(fieldsStr)) !== null) {
      const originalFieldName = fieldMatch[1];
      const fieldTypeStr = fieldMatch[2].trim();

      const { type, isArray } = parseFieldType(fieldTypeStr);
      const fieldName = toCamelCase(originalFieldName);

      if (!fieldNames.has(fieldName)) {
        fieldNames.add(fieldName);
        fields.push({
          name: fieldName,
          originalName: originalFieldName,
          type,
          isArray,
          isOptional: false,
        });
      }
    }

    const name = parseTableName(originalName);
    if (name && !tables.some(t => t.name === name)) {
      tables.push({ originalName, name, fields });
    }
  }

  return { enums, tables };
}

function generateEnumCode(enumDef: EnumDef): string {
  const values = enumDef.values
    .map(v => `"${v.name}"`)
    .join(" | ");

  return `export type ${enumDef.name} = ${values};`;
}

const COMPATIBILITY_FIXES: { [key: string]: { [key: string]: string } } = {
  RoguelikeGameItemData: { value: "number" },
  RetroTrailRewardItem: { trailRewardID: "string" },
};

const TYPE_OVERRIDES: { [key: string]: { [key: string]: string } } = {
  MissionData: { toPage: "null | string" },
  StageDataConditionDesc: { completeState: "number" },
  StageDataDisplayDetailRewards: { occPercent: "number", dropType: "number" },
  CharacterData: { rarity: "number" },
  RoguelikeGameRecruitTicketData: { rarityList: "number[]", extraFreeRarity: "number[]" },
};

const INDEX_SIGNATURE_INTERFACES = ["SpCharMissionData", "CharacterData", "StoryReviewGroupClientData"];

function generateInterfaceCode(tableDef: TableDef): string {
  const fields = tableDef.fields
    .map(f => {
      const fieldName = f.name;
      let typeStr = f.isArray ? `${f.type}[]` : f.type;
      
      if (TYPE_OVERRIDES[tableDef.name] && TYPE_OVERRIDES[tableDef.name][fieldName]) {
        typeStr = TYPE_OVERRIDES[tableDef.name][fieldName];
      }
      
      const optionalStr = f.isOptional ? "?" : "";
      return `    ${fieldName}${optionalStr}: ${typeStr};`;
    })
    .join("\n");

  let extraFields = "";
  if (COMPATIBILITY_FIXES[tableDef.name]) {
    Object.entries(COMPATIBILITY_FIXES[tableDef.name]).forEach(([name, type]) => {
      if (!tableDef.fields.some(f => f.name === name)) {
        extraFields += `\n    ${name}: ${type};`;
      }
    });
  }

  let indexSignature = "";
  if (INDEX_SIGNATURE_INTERFACES.includes(tableDef.name)) {
    indexSignature = "\n    [key: string]: any;";
  }

  return `export interface ${tableDef.name} {
${fields}${extraFields}${indexSignature}
}`;
}

function main() {
  const fbsFiles = fs
    .readdirSync(FBS_DIR)
    .filter(file => file.endsWith(".fbs"));

  console.log(`Found ${fbsFiles.length} FBS files`);

  const allEnums: Map<string, EnumDef> = new Map();
  const allTables: Map<string, TableDef> = new Map();

  for (const fbsFile of fbsFiles) {
    const fbsPath = path.join(FBS_DIR, fbsFile);
    const content = fs.readFileSync(fbsPath, "utf-8");

    const parsed = parseFbsFile(content);

    parsed.enums.forEach(e => {
      if (!allEnums.has(e.name)) {
        allEnums.set(e.name, e);
      }
    });

    parsed.tables.forEach(t => {
      if (!allTables.has(t.name)) {
        allTables.set(t.name, t);
      }
    });

    console.log(`  - ${fbsFile}: ${parsed.enums.length} enums, ${parsed.tables.length} tables`);
  }

  console.log(`\nTotal (unique): ${allEnums.size} enums, ${allTables.size} tables`);

  const outputPath = path.join(OUTPUT_DIR, "types_auto_gen.ts");

  let outputContent = "/**\n";
  outputContent += " * 自动生成的类型定义文件\n";
  outputContent += " * 从 OpenArknightsFBS 仓库的 FBS 文件生成\n";
  outputContent += " * 请勿手动修改此文件\n";
  outputContent += " */\n\n";

  const enumArray = Array.from(allEnums.values()).sort((a, b) => a.name.localeCompare(b.name));
  const tableArray = Array.from(allTables.values()).sort((a, b) => a.name.localeCompare(b.name));

  enumArray.forEach(enumDef => {
    outputContent += generateEnumCode(enumDef);
    outputContent += "\n\n";
  });

  tableArray.forEach(tableDef => {
    outputContent += generateInterfaceCode(tableDef);
    outputContent += "\n\n";
  });

  fs.writeFileSync(outputPath, outputContent);
  console.log(`\nGenerated: ${outputPath}`);
  console.log(`File size: ${(outputContent.length / 1024 / 1024).toFixed(2)} MB`);
}

main();