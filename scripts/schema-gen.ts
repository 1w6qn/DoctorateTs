/**
 * 从 vendored flatbuffers Python schema（scripts/vendor/fbs/CN/*.py）提取 JSON 描述。
 * 一次性生成 → 提交 JSON（源 .py 已移除，仅当重新接入新 schema 时用）。输出：scripts/vendor/fbs-schemas/*.json
 * 用法: pnpm exec tsx scripts/schema-gen.ts
 */
import * as fs from "fs";
import * as path from "path";

const SRC_DIR = path.join(__dirname, "../scripts/vendor/fbs/CN");
const OUT_DIR = path.join(__dirname, "../scripts/vendor/fbs-schemas");

interface FieldInfo {
  name: string;
  type: string; // string | bool | int | long | float | double | vec:... | clz_... | dict__...
  slot: number; // vtable Offset 值
}

/** 单个 schema JSON 文件的落盘结构（`flatbuffers` 描述） */
interface SchemaModuleJson {
  root: string;
  tables: Record<string, FieldInfo[]>;
  enums: Record<string, Record<string, number>>;
}

function parseModule(src: string): { tables: Map<string, FieldInfo[]>; enums: Map<string, Map<string, number>>; root: string } {
  const tables = new Map<string, FieldInfo[]>();
  const enums = new Map<string, Map<string, number>>();
  let root = "";

  // ROOT_TYPE
  const rm = src.match(/ROOT_TYPE\s*=\s*(\w+)/);
  if (rm) root = rm[1];

  // 枚举类：class enum__X(object): NAME = value
  const enumRe = /class (enum__\w+)\(object\):\n((?:\s+\w+\s*=\s*-?\d+\n)+)/g;
  for (const m of src.matchAll(enumRe)) {
    const vmap = new Map<string, number>();
    for (const vm of m[2].matchAll(/^\s+(\w+)\s*=\s*(-?\d+)/gm)) {
      vmap.set(vm[1], parseInt(vm[2]));
    }
    enums.set(m[1], vmap);
  }

  // 表类：class clz_.../dict__...(object): ... def NAME(self[, j]):
  const clsRe = /class (clz_Torappu_\w+|dict__[\w_]+|kvp__[\w_]+)\(object\):[\s\S]*?(?=\nclass |\nROOT_TYPE)/g;
  for (const m of src.matchAll(clsRe)) {
    const clsName = m[1];
    const body = m[0];
    const fields: FieldInfo[] = [];
    const accRe = /def (\w+)\(self(?:,\s*j)?\):\n\s+o = flatbuffers\.number_types\.UOffsetTFlags\.py_type\(self\._tab\.Offset\((\d+)\)\)([\s\S]*?)(?=\n    def |$)/g;
    for (const am of body.matchAll(accRe)) {
      const name = am[1];
      const slot = parseInt(am[2]);
      const code = am[3];
      // 注意：不跳过 "Init"——flatbuffers 构造方法签名 (self, buf, pos) 不匹配
      // accRe 的 (self, j)，而字段访问器 def Init(self, j) 是真实 init 字段
      // （roguelike_topic_table.details.*.init——CS 类 RoguelikeTopicDetail.init）。
      // 此前跳过导致 init 数据缺失（客户端开局分队/初始数值全丢）。
      if (name.endsWith("Length") || name.endsWith("IsNone")) continue;
      if (code.includes("self._tab.Vector(o)")) {
        // 向量：先判断元素类型
        const objM = code.match(/obj\s*=\s*(\w+)\(\)/);
        if (objM) {
          fields.push({ name, type: `vec:${objM[1]}`, slot });
        } else if (code.includes("self._tab.String(")) {
          fields.push({ name, type: "vec:string", slot });
        } else if (code.includes("Get(flatbuffers.number_types.BoolFlags")) {
          fields.push({ name, type: "vec:bool", slot });
        } else if (code.includes("Get(flatbuffers.number_types.Int32Flags")) {
          fields.push({ name, type: "vec:int", slot });
        } else if (code.includes("Get(flatbuffers.number_types.Int64Flags")) {
          fields.push({ name, type: "vec:long", slot });
        } else if (code.includes("Get(flatbuffers.number_types.Float32Flags")) {
          fields.push({ name, type: "vec:float", slot });
        } else if (code.includes("Get(flatbuffers.number_types.Float64Flags")) {
          fields.push({ name, type: "vec:double", slot });
        } else {
          fields.push({ name, type: "vec:unknown", slot });
        }
      } else if (code.includes("self._tab.String(")) {
        fields.push({ name, type: "string", slot });
      } else if (code.includes("obj = ") && code.includes(".Init(")) {
        const objM = code.match(/obj\s*=\s*(\w+)\(\)/);
        fields.push({ name, type: objM ? objM[1] : "unknown", slot });
      } else if (code.includes("Get(flatbuffers.number_types.BoolFlags")) {
        fields.push({ name, type: "bool", slot });
      } else if (code.includes("Get(flatbuffers.number_types.Int64Flags")) {
        fields.push({ name, type: "long", slot });
      } else if (code.includes("Get(flatbuffers.number_types.Float32Flags")) {
        fields.push({ name, type: "float", slot });
      } else if (code.includes("Get(flatbuffers.number_types.Float64Flags")) {
        fields.push({ name, type: "double", slot });
      } else if (code.includes("Get(flatbuffers.number_types.Int32Flags")) {
        fields.push({ name, type: "enum", slot });
      } else if (code.includes("Get(flatbuffers.number_types.Int16Flags")) {
        fields.push({ name, type: "int", slot });
      } else if (code.includes("Get(flatbuffers.number_types.Uint8Flags")) {
        fields.push({ name, type: "int", slot });
      } else {
        fields.push({ name, type: "unknown", slot });
      }
    }
    tables.set(clsName, fields);
  }
  return { tables, enums, root };
}

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  let n = 0;
  for (const f of fs.readdirSync(SRC_DIR).filter((x) => x.endsWith(".py") && !x.startsWith("__"))) {
    const raw = fs.readFileSync(path.join(SRC_DIR, f), "utf-8");
    const src = raw.replace(/\r\n/g, "\n"); // Windows 行尾归一化
    const { tables, enums, root } = parseModule(src);
    if (!tables.size) continue;
    const out: SchemaModuleJson = { root, tables: {}, enums: {} };
    for (const [k, v] of tables) out.tables[k] = v;
    for (const [k, v] of enums) out.enums[k] = Object.fromEntries(v);
    fs.writeFileSync(path.join(OUT_DIR, f.replace(".py", ".json")), JSON.stringify(out));
    n++;
  }
  console.log(`生成 ${n} 个 schema JSON 到 ${OUT_DIR}`);
}

main();
