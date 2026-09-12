/**
 * FBO schema 报文真值审计（wire truth audit）
 *
 * 与 `schema:check`（对照 CS 签名）和 `schema:crosscheck`（对照 OpenArknightsFBS 参考）不同，
 * 本工具**只看报文本身**：解码官方 bundle 时读取每个表对象的 vtable 声明字段数，
 * 与 `scripts/vendor/fbs-schemas/*.json` 的字段数比对，从而发现两类静默问题：
 *
 * - `wire > schema`：本地少字段 → 该表尾部数据解不出来（实测 FifthAnnivExploreMissionData 1/20）
 * - `wire < schema`：本地多字段 → 若多出的字段夹在中间，其后字段整体位移、读到错误槽位
 *   （实测 ActivityBossRushData_DisplayDetailRewards 的 DropCount 恒为 4）
 *
 * `neverHit` 列出「在全部样本中从未命中」的字段，用于判断多出的字段是否为尾部残留。
 *
 * 用法：
 *   pnpm run schema:audit                 # 打印不一致的表
 *   pnpm run schema:audit -- --json out.json   # 落盘全量结果
 *   pnpm run schema:audit -- --table X         # 只看某张 excel 表
 *
 * 依赖 `reference/hotupdate/`（gitignored）下的热更清单快照与已下载 bundle；
 * 缺失时直接跳过并提示，不报错。
 */
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { extractTextAsset } from "./vendor/unityfs";
import { FBO } from "./vendor/fbo";

const ROOT = path.join(__dirname, "..");
const HUL_DIR = path.join(ROOT, "reference/hotupdate");
const DL_DIR = path.join(HUL_DIR, "downloads");
const NAME_CACHE = path.join(HUL_DIR, "textasset-names.json");
const SCHEMA_DIR = path.join(ROOT, "scripts/vendor/fbs-schemas");

const argv = process.argv.slice(2);
const opt = (n: string): string | undefined => {
  const i = argv.indexOf(n);
  return i >= 0 ? argv[i + 1] : undefined;
};

/** 单表审计结果 */
interface TableAudit {
  file: string;
  cls: string;
  /** 报文中出现的最大 vtable 声明字段数 */
  wireFields: number;
  /** 本地 schema 字段数（剔除历史合成字段 AsNumpy） */
  schemaFields: number;
  records: number;
  /** 从未命中的 schema 字段名 */
  neverHit: string[];
}

/** 表定义所在的 schema 文件名 */
function findFile(cls: string): string {
  for (const f of fs.readdirSync(SCHEMA_DIR)) {
    const s = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, f), "utf-8"));
    if (s.tables[cls]) return f;
  }
  return "";
}

/** 取文件名内嵌时间戳最新的热更清单快照（与 official-excel.ts 一致） */
function resolveLatestHulSnapshot(): string | null {
  if (!fs.existsSync(HUL_DIR)) return null;
  const files = fs.readdirSync(HUL_DIR).filter((f) => /^hot_update_list_.*\.json$/.test(f));
  if (!files.length) return null;
  const ts = (f: string): number => {
    const m = f.match(/^hot_update_list_(\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})/);
    if (!m) return fs.statSync(path.join(HUL_DIR, f)).mtimeMs;
    return Date.UTC(
      2000 + Number(m[1].slice(0, 2)),
      Number(m[1].slice(3, 5)) - 1,
      Number(m[1].slice(6, 8)),
      Number(m[1].slice(9, 11)),
      Number(m[1].slice(12, 14)),
      Number(m[1].slice(15, 17)),
    );
  };
  return files.map((f) => ({ p: path.join(HUL_DIR, f), k: ts(f) })).sort((a, b) => a.k - b.k).pop()!.p;
}

/** 与 official-excel.ts 一致：anon/xxx → downloads/anon_xxx.dat */
function transName(name: string): string {
  return name.replace(/\.([^.]*)$/, ".dat").replace(/\//g, "_").replace(/#/g, "__");
}

async function main(): Promise<void> {
  const only = opt("--table");
  const jsonOut = opt("--json");
  if (!fs.existsSync(NAME_CACHE)) {
    console.log(`[SKIP] 无 TextAsset 名称缓存：${path.relative(ROOT, NAME_CACHE)}`);
    return;
  }
  const hulPath = resolveLatestHulSnapshot();
  if (!hulPath) {
    console.log("[SKIP] 无热更清单快照，无法定位 bundle");
    return;
  }
  const cache = JSON.parse(fs.readFileSync(NAME_CACHE, "utf-8")) as Record<string, { name: string }>;
  const hul = JSON.parse(fs.readFileSync(hulPath, "utf-8")) as { abInfos?: { name: string }[] };
  console.log(`快照: ${path.basename(hulPath)}`);

  /** 审计累积表：文件+表 → 结果 */
  const audit = new Map<string, TableAudit>();
  const hitCount = new Map<string, Map<string, number>>();
  FBO.observer = (cls, vtableFields, present) => {
    let rec = audit.get(cls);
    if (!rec) {
      const file = findFile(cls).replace(/\.json$/, "");
      if (!file) return;
      const schema = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, `${file}.json`), "utf-8"));
      const fields = (schema.tables[cls] as { name: string }[]).filter((f) => !f.name.endsWith("AsNumpy"));
      rec = { file, cls, wireFields: 0, schemaFields: fields.length, records: 0, neverHit: [] };
      audit.set(cls, rec);
      hitCount.set(cls, new Map(fields.map((f) => [f.name, 0])));
    }
    rec.records++;
    if (vtableFields > rec.wireFields) rec.wireFields = vtableFields;
    const hits = hitCount.get(cls)!;
    for (const name of hits.keys()) if (present(name)) hits.set(name, hits.get(name)! + 1);
  };

  let decoded = 0;
  let skipped = 0;
  for (const ab of hul.abInfos ?? []) {
    if (!ab.name.startsWith("anon/")) continue;
    const datFile = transName(ab.name);
    const info = cache[datFile];
    if (!info) {
      skipped++;
      continue;
    }
    const base = info.name.replace(/[0-9a-f]{6}$/, "");
    if (only && base !== only) continue;
    const datPath = path.join(DL_DIR, datFile);
    const schemaPath = path.join(SCHEMA_DIR, `${base}.json`);
    if (!fs.existsSync(datPath) || !fs.existsSync(schemaPath)) {
      skipped++;
      continue;
    }
    const zip = await JSZip.loadAsync(fs.readFileSync(datPath));
    const inner = await zip.files[Object.keys(zip.files)[0]].async("uint8array");
    const ta = extractTextAsset(inner);
    if (!ta) {
      skipped++;
      continue;
    }
    const script = ta.script;
    // AES 表：布局探测不成立，跳过（不走 schema）
    const rootOff = (script[128] | (script[129] << 8) | (script[130] << 16) | (script[131] << 24)) >>> 0;
    if (!(rootOff > 0 && rootOff < 4096)) {
      skipped++;
      continue;
    }
    new FBO(script.subarray(128), JSON.parse(fs.readFileSync(schemaPath, "utf-8"))).toJson();
    decoded++;
  }
  FBO.observer = null;

  for (const [cls, hits] of hitCount) {
    const rec = audit.get(cls)!;
    rec.neverHit = [...hits.entries()].filter(([, n]) => n === 0).map(([n]) => n);
  }
  const rows = [...audit.values()].sort((a, b) => b.schemaFields - b.wireFields - (a.schemaFields - a.wireFields));
  const bad = rows.filter((r) => r.wireFields !== r.schemaFields);
  console.log(`解码 ${decoded} 张（跳过 ${skipped}），审计 ${rows.length} 张表定义`);
  console.log(`字段数与报文 vtable 不一致的表: ${bad.length}`);
  for (const r of bad.slice(0, 60)) {
    const diff = r.schemaFields - r.wireFields;
    const kind = diff > 0 ? "本地多" : "本地少";
    console.log(
      `  [${kind}${Math.abs(diff)}] ${r.file.padEnd(22)} ${r.cls}  wire=${r.wireFields} schema=${r.schemaFields} 记录=${r.records}` +
        (r.neverHit.length ? `\n        从未命中(${r.neverHit.length}): ${r.neverHit.slice(0, 6).join(", ")}` : ""),
    );
  }
  if (jsonOut) {
    fs.writeFileSync(jsonOut, JSON.stringify(rows, null, 1));
    console.log(`已写出 ${jsonOut}`);
  }
  if (bad.length) {
    console.log(
      "\n提示：`本地少` → 用 `pnpm run schema:write` 从 CS 补齐；`本地多` 且多出字段夹在中间 → 记入\n" +
        "      `scripts/cs2schema.ts` 的 NON_WIRE_FIELDS（需先确认这些字段在样本中从未命中）。",
    );
  }
}

void main();
