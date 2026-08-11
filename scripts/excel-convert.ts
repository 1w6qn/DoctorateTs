/**
 * 枚举/键名转换（端口 hotupdate-excel.py 的 convert_enums）：
 * camelCase 首字母小写 + 丢弃 AsNumpy + 单键根解包 + 本地引导枚举 + FBS/cs 唯一值兜底 + null→容器。
 */
import * as fs from "fs";
import * as path from "path";

const ROOT = path.join(__dirname, "..");
const CS_PATH = path.join(ROOT, "reference/com.hypergryph.arknights_2.7.61.cs");
const FBS_SCHEMA_DIR = path.join(ROOT, "scripts/vendor/fbs-schemas");

const PY_KEYWORDS = new Set([
  "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del",
  "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in",
  "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
  "with", "yield", "None", "True", "False",
]);

function normKey(k: string): string {
  let out = k && k[0].toUpperCase() !== k[0] ? k : k.length ? k[0].toLowerCase() + k.slice(1) : k;
  if (out.endsWith("_") && PY_KEYWORDS.has(out.slice(0, -1))) out = out.slice(0, -1);
  return out;
}

function normNode(node: any): any {
  if (Array.isArray(node)) return node.map(normNode);
  if (node && typeof node === "object") {
    const out: any = {};
    for (const [k, v] of Object.entries(node)) {
      if (k.endsWith("AsNumpy")) continue;
      out[normKey(k)] = normNode(v);
    }
    return out;
  }
  return node;
}

function stripIdx(p: string): string {
  return p.replace(/\[\d+\]/g, "");
}

// FBS 枚举 + cs 枚举 → 全部 value→name
function loadEnumMaps(): Map<number, string | null> {
  const unique = new Map<number, string | null>();
  const add = (v: number, name: string) => {
    const cur = unique.get(v);
    if (cur !== undefined && cur !== name) unique.set(v, null); // 多义 → 弃
    else if (cur === undefined) unique.set(v, name);
  };
  // FBS schema JSON 中的枚举
  if (fs.existsSync(FBS_SCHEMA_DIR)) {
    for (const f of fs.readdirSync(FBS_SCHEMA_DIR).filter((x) => x.endsWith(".json"))) {
      try {
        const schema = JSON.parse(fs.readFileSync(path.join(FBS_SCHEMA_DIR, f), "utf-8"));
        for (const vmap of Object.values(schema.enums || {})) {
          for (const [name, val] of Object.entries(vmap as Record<string, number>)) add(val, name);
        }
      } catch { /* 跳过 */ }
    }
  }
  // cs 枚举
  if (fs.existsSync(CS_PATH)) {
    const cs = fs.readFileSync(CS_PATH, "utf-8");
    const re = /public enum (Torappu\.[A-Za-z0-9_.]+)\s*:[^\{]*\{([^}]*)\}/g;
    for (const m of cs.matchAll(re)) {
      const body = m[2];
      const vals = body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)/g);
      for (const vm of vals) add(parseInt(vm[2]), vm[1]);
    }
  }
  return unique;
}

export function convertTable(
  dec: any,
  loc: any, // 本地既有文件（枚举学习种子），可 null
  table: string,
): any {
  const norm = (d: any): any => {
    if (Array.isArray(d)) return d.map(norm);
    if (d && typeof d === "object") {
      const out: any = {};
      for (const [k, v] of Object.entries(d)) {
        if (k.endsWith("AsNumpy")) continue;
        out[normKey(k)] = norm(v);
      }
      return out;
    }
    return d;
  };
  let decN = norm(dec);
  let locN = loc ? norm(loc) : null;

  // 单键根解包
  const unwrap = (d: any, l: any): [any, any] => {
    if (d && typeof d === "object" && !Array.isArray(d) && Object.keys(d).length === 1) {
      if (l && typeof l === "object" && !Array.isArray(l) && Object.keys(l).length !== 1) {
        return [Object.values(d)[0], l];
      }
      if (!l) return [Object.values(d)[0], null];
    }
    return [d, l];
  };
  [decN, locN] = unwrap(decN, locN);

  const valueMap = new Map<string, Map<number, string>>(); // 路径 → {value: name}
  const renameMap = new Map<string, string>(); // dec 键(casefold) → 本地键
  const emptyMap = new Map<string, "list" | "dict">(); // 路径 → 容器类型
  const normk2 = (k: string) => k.toLowerCase().replace(/_/g, "");

  if (locN && typeof locN === "object") {
    const walkPairs = (d: any, l: any, p: string) => {
      if (d && typeof d === "object" && !Array.isArray(d) && l && typeof l === "object" && !Array.isArray(l)) {
        const lm = new Map<string, string>();
        for (const k of Object.keys(l)) lm.set(k.toLowerCase(), k);
        const dm = new Map<string, string>();
        for (const k of Object.keys(d)) dm.set(k.toLowerCase(), k);
        const done = new Set<string>();
        for (const lk of [...lm.keys()].sort()) {
          if (dm.has(lk)) {
            const dk = dm.get(lk)!, lkv = lm.get(lk)!;
            if (dk !== lkv) renameMap.set(dk.toLowerCase(), lkv);
            walkPairs(d[dk], l[lkv], `${p}.${dk.toLowerCase()}`);
            done.add(lk);
          }
        }
        for (const lk of [...lm.keys()].sort()) {
          if (done.has(lk) || !lm.get(lk)!.includes("_")) continue;
          for (const dk of [...dm.keys()]) {
            if (normk2(dk) === normk2(lk)) {
              if (dk !== lm.get(lk)) renameMap.set(dk.toLowerCase(), lm.get(lk)!);
              walkPairs(d[dm.get(dk)!], l[lm.get(lk)!], `${p}.${dm.get(dk)!.toLowerCase()}`);
              break;
            }
          }
        }
      } else if (Array.isArray(d) && Array.isArray(l)) {
        for (let i = 0; i < Math.min(d.length, l.length); i++) walkPairs(d[i], l[i], `${p}[${i}]`);
      } else if (d === null && (Array.isArray(l) || (l && typeof l === "object"))) {
        emptyMap.set(stripIdx(p), Array.isArray(l) ? "list" : "dict");
      } else if (typeof d === "number" && Number.isInteger(d) && typeof l === "string") {
        if (!valueMap.has(stripIdx(p))) valueMap.set(stripIdx(p), new Map());
        valueMap.get(stripIdx(p))!.set(d, l);
      }
    };
    const locKeys = Object.keys(locN).slice(0, 2000);
    for (const k of locKeys) walkPairs(decN?.[k] ?? {}, locN[k], table);
  }

  // 通用重命名（Undefinable）
  renameMap.set("mdefined", "m_defined");
  renameMap.set("mvalue", "m_value");
  const uniqueName = loadEnumMaps();

  const convert = (d: any, p: string): any => {
    if (d && typeof d === "object" && !Array.isArray(d)) {
      const out: any = {};
      for (const [k, v] of Object.entries(d)) {
        const nk = renameMap.get(k.toLowerCase()) ?? k;
        out[nk] = convert(v, `${p}.${k.toLowerCase()}`);
      }
      return out;
    }
    if (Array.isArray(d)) return d.map((x, i) => convert(x, `${p}[${i}]`));
    if (d === null) {
      const et = emptyMap.get(stripIdx(p));
      if (et === "list") return [];
      if (et === "dict") return {};
      return null;
    }
    if (typeof d === "number" && Number.isInteger(d)) {
      const vm = valueMap.get(stripIdx(p));
      if (vm && vm.has(d)) return vm.get(d)!;
      const u = uniqueName.get(d);
      if (u !== undefined && u !== null) return u;
    }
    return d;
  };

  if (decN && typeof decN === "object" && !Array.isArray(decN)) {
    const out: any = {};
    for (const [k, v] of Object.entries(decN)) out[k] = convert(v, table);
    return out;
  }
  return convert(decN, table);
}
