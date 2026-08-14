/**
 * 官方热更 excel 管线（TS 实现，替代 hotupdate-excel.py，零 Python 依赖）：
 *   --download  拉取热更清单 + 下载 excel bundle
 *   --decode    UnityFS 解包 → FBO/AES 解码 → reference/hotupdate/excel_json/
 *   --convert   原始结果 → 服务端格式（camelCase + 枚举）→ data/excel/
 * 用法: pnpm exec tsx scripts/official-excel.ts --download --decode --convert [--offline] [--table X]
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import JSZip from "jszip";
import { createCipheriv, createDecipheriv, createHash } from "crypto";
import { extractTextAsset } from "./vendor/unityfs";
import { FBO } from "./vendor/fbo";
import { convertTable } from "./excel-convert";

const ROOT = path.join(__dirname, "..");
const HU = "https://ak.hycdn.cn/assetbundle/official";
const CONF_VERSION = "https://ak-conf.hypergryph.com/config/prod/official/Windows/version";
const HUL_DIR = path.join(ROOT, "reference/hotupdate");
const DL_DIR = path.join(ROOT, "reference/hotupdate/downloads");
const OUT_DIR = path.join(ROOT, "reference/hotupdate/excel_json");
const DATA_EXCEL_DIR = path.join(ROOT, "data/excel");
const SCHEMA_DIR = path.join(ROOT, "scripts/vendor/fbs-schemas");
const HUL_SNAPSHOT = path.join(HUL_DIR, "hot_update_list_26-08-07-10-51-39.json");
const NAME_CACHE = path.join(HUL_DIR, "textasset-names.json");

// 服务端加载的全部 excel 表
const TABLE_WHITELIST = new Set([
  "activity_table", "arkvent_table", "audio_data", "battle_equip_table",
  "building_data", "building_local_data", "campaign_table", "chapter_table",
  "char_master_table", "char_meta_table", "char_patch_table", "character_table",
  "charm_table", "charword_table", "checkin_table", "climb_tower_table",
  "clue_data", "cooperate_battle_table", "crisis_table", "crisis_v2_table",
  "display_meta_table", "enemy_database", "enemy_handbook_table",
  "ep_breakbuff_table", "extra_battlelog_table", "favor_table", "gacha_table",
  "gamedata_const", "handbook_info_table", "handbook_table", "handbook_team_table",
  "hotupdate_meta_table", "init_text", "item_table", "legion_mode_buff_table",
  "level_script_table", "main_text", "medal_table", "meta_ui_table",
  "mission_table", "open_server_table", "player_avatar_table", "range_table",
  "replicate_table", "retro_table", "roguelike_table", "roguelike_topic_table",
  "sandbox_perm_table", "sandbox_table", "shop_client_table", "skill_table",
  "skin_table", "special_operator_table", "stage_table", "story_review_meta_table",
  "story_review_table", "story_table", "tech_buff_table", "tip_table",
  "token_table", "uniequip_data", "uniequip_table", "zone_table",
]);

interface AbInfo {
  name: string;
  totalSize: number;
}

function transName(name: string): string {
  return name.replace(/\.([^.]*)$/, ".dat").replace(/\//g, "_").replace(/#/g, "__");
}

async function fetchHotUpdateList(): Promise<{ hul: any; resVersion: string }> {
  const verRes = await fetch(CONF_VERSION);
  const ver = await verRes.json();
  const resVersion: string = ver.resVersion;
  const url = `${HU}/Windows/assets/${resVersion}/hot_update_list.json`;
  const res = await fetch(url);
  const hul = await res.json();
  const hulPath = path.join(HUL_DIR, `hot_update_list_${resVersion}.json`);
  fs.writeFileSync(hulPath, JSON.stringify(hul));
  return { hul, resVersion };
}

async function downloadBundle(ab: AbInfo, resVersion: string): Promise<string | null> {
  const fn = transName(ab.name);
  const dat = path.join(DL_DIR, fn);
  if (fs.existsSync(dat) && fs.statSync(dat).size > 1000) return dat;
  const url = `${HU}/Windows/assets/${resVersion}/${fn}`;
  const res = await fetch(url, { headers: { "User-Agent": "BestHTTP" } });
  if (!res.ok) return null;
  fs.writeFileSync(dat, Buffer.from(await res.arrayBuffer()));
  return fs.existsSync(dat) && fs.statSync(dat).size > 1000 ? dat : null;
}

async function readTextAssetName(dat: string): Promise<string | null> {
  try {
    const zip = await JSZip.loadAsync(fs.readFileSync(dat));
    const entry = Object.keys(zip.files)[0];
    const inner = await zip.files[entry].async("uint8array");
    const ta = extractTextAsset(inner);
    return ta ? ta.name : null;
  } catch {
    return null;
  }
}

// TextAsset 名缓存（key=bundle 文件名，value={name, mtime}）——避免每次启动全量解包 63 个 bundle
let nameCache: Record<string, { name: string; mtime: number }> = {};
try {
  nameCache = JSON.parse(fs.readFileSync(NAME_CACHE, "utf-8"));
} catch { /* 无缓存 */ }

async function readTextAssetNameCached(dat: string): Promise<string | null> {
  const key = path.basename(dat);
  try {
    const st = fs.statSync(dat);
    const hit = nameCache[key];
    if (hit && hit.mtime === st.mtimeMs) return hit.name; // 文件未变 → 用缓存
    const name = await readTextAssetName(dat);
    nameCache[key] = { name: name ?? "", mtime: st.mtimeMs };
    return name;
  } catch {
    return null;
  }
}

function saveNameCache(): void {
  try {
    fs.writeFileSync(NAME_CACHE, JSON.stringify(nameCache));
  } catch { /* 缓存写入失败不影响主流程 */ }
}

function aesDecrypt(script: Uint8Array): { json?: any; bson?: any } {
  const mask = Buffer.from("UITpAi82pHAWwnzqHRMCwPonJLIB3WCl");
  const data = script.subarray(128);
  const key = mask.subarray(0, 16);
  const iv = Buffer.from(data.subarray(0, 16).map((d, i) => d ^ mask[16 + i]));
  const decipher = createDecipheriv("aes-128-cbc", key, iv);
  decipher.setAutoPadding(false);
  const dec = Buffer.concat([decipher.update(Buffer.from(data.subarray(16))), decipher.final()]);
  // 去 PKCS7 填充
  const pad = dec[dec.length - 1];
  const plain = pad >= 1 && pad <= 16 ? dec.subarray(0, dec.length - pad) : dec;
  const str = plain.toString("utf-8");
  try {
    return { json: JSON.parse(str) };
  } catch {
    return { bson: plain }; // BSON 未支持时返回 null
  }
}

/** 解码单个 bundle：FBO（schema JSON）或 AES-JSON */
async function decodeBundle(dat: string, base: string): Promise<any | null> {
  const zip = await JSZip.loadAsync(fs.readFileSync(dat));
  const entry = Object.keys(zip.files)[0];
  const inner = await zip.files[entry].async("uint8array");
  const ta = extractTextAsset(inner);
  if (!ta) return null;
  const script = ta.script;
  // 判断 FBO 还是 AES：script[128:132] 的 uoffset 是否合理
  const rootOff = (script[128] | (script[129] << 8) | (script[130] << 16) | (script[131] << 24)) >>> 0;
  if (rootOff > 0 && rootOff < 4096) {
    // FBO
    const schemaPath = path.join(SCHEMA_DIR, `${base}.json`);
    if (!fs.existsSync(schemaPath)) return null;
    const schema = JSON.parse(fs.readFileSync(schemaPath, "utf-8"));
    return new FBO(script.subarray(128), schema).toJson();
  }
  // AES
  const { json } = aesDecrypt(script);
  return json ?? null;
}

async function main() {
  const args = process.argv.slice(2);
  const doDownload = args.includes("--download");
  const doDecode = args.includes("--decode");
  const doConvert = args.includes("--convert");
  const offline = args.includes("--offline");
  const ti = args.indexOf("--table");
  const tableArg = ti >= 0 ? args[ti + 1] : undefined;

  let hul: any;
  let resVersion = "26-08-07-10-51-39";
  if (doDownload && !offline) {
    try {
      ({ hul, resVersion } = await fetchHotUpdateList());
      console.log(`热更清单: resVersion=${resVersion}`);
    } catch {
      console.log("[warn] 拉取热更清单失败，使用本地快照");
      hul = JSON.parse(fs.readFileSync(HUL_SNAPSHOT, "utf-8"));
    }
  } else {
    hul = JSON.parse(fs.readFileSync(HUL_SNAPSHOT, "utf-8"));
  }

  fs.mkdirSync(DL_DIR, { recursive: true });
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.mkdirSync(DATA_EXCEL_DIR, { recursive: true });

  // 发现 excel bundle（仅 download/decode 需要；convert 直接用 excel_json）
  const bundleMap = new Map<string, string>(); // base → dat
  if (doDownload || doDecode) {
    const abInfos: AbInfo[] = hul.abInfos || [];
    for (const ab of abInfos) {
      if (!ab.name.startsWith("anon/")) continue;
      const dat = path.join(DL_DIR, transName(ab.name));
      if (!fs.existsSync(dat)) continue;
      const name = await readTextAssetNameCached(dat);
      if (!name) continue;
      const base = name.replace(/[0-9a-f]{6}$/, "");
      if (TABLE_WHITELIST.has(base)) bundleMap.set(base, dat);
    }
    saveNameCache();
    if (tableArg && bundleMap.has(tableArg)) {
      for (const k of bundleMap.keys()) {
        if (k !== tableArg) bundleMap.delete(k);
      }
    }
    console.log(`excel 表: ${bundleMap.size}`);
  }

  if (doDownload) {
    let n = 0;
    for (const [base, dat] of bundleMap) {
      if (fs.existsSync(dat) && fs.statSync(dat).size > 1000) continue;
      const ab = abInfos.find((a) => transName(a.name) === path.basename(dat));
      if (ab && (await downloadBundle(ab, resVersion))) {
        n++;
        console.log(`  已下载 ${base}`);
      }
    }
    console.log(`下载完成: ${n}`);
  }

  if (doDecode) {
    let ok = 0, fail = 0;
    for (const [base, dat] of [...bundleMap.entries()].sort()) {
      const out = path.join(OUT_DIR, `${base}.json`);
      if (fs.existsSync(out) && fs.statSync(out).size > 100) continue;
      try {
        const dic = await decodeBundle(dat, base);
        if (dic === null) {
          console.log(`  跳过 ${base}`);
          continue;
        }
        fs.writeFileSync(out, JSON.stringify(dic));
        ok++;
        console.log(`  解码 ${base}: ${(fs.statSync(out).size / 1024).toFixed(0)}KB`);
      } catch (e) {
        fail++;
        console.log(`  解码失败 ${base}: ${(e as Error).message.slice(0, 60)}`);
      }
    }
    console.log(`解码完成: ${ok} ok, ${fail} fail`);
  }

  if (doConvert) {
    let ok = 0, fail = 0, skipped = 0;
    const allTables = fs.readdirSync(OUT_DIR).filter((x) => x.endsWith(".json")).map((x) => x.slice(0, -5)).sort();
    const targets = tableArg ? allTables.filter((n) => n === tableArg) : allTables;
    // 并行转换：需转换的表数较多时用 worker_threads（首次/新版本全量）；否则内联
    const needConvert = targets.filter((name) => {
      const f = `${name}.json`;
      const out = path.join(DATA_EXCEL_DIR, f);
      const schemaPath = path.join(SCHEMA_DIR, f);
      try {
        const decStat = fs.statSync(path.join(OUT_DIR, f));
        const outStat = fs.existsSync(out) ? fs.statSync(out) : null;
        const schemaStat = fs.existsSync(schemaPath) ? fs.statSync(schemaPath) : null;
        return !(
          outStat &&
          decStat.mtimeMs <= outStat.mtimeMs &&
          (!schemaStat || schemaStat.mtimeMs <= outStat.mtimeMs)
        );
      } catch {
        return true;
      }
    });
    skipped = targets.length - needConvert.length;

    if (needConvert.length === 0) {
      // 全部最新
    } else if (needConvert.length >= 4 && !tableArg) {
      // worker 并行（worker_threads 独立进程，避开单线程 CPU 瓶颈）
      const { Worker } = await import("worker_threads");
      const workerPath = path.join(__dirname, "convert-worker.ts");
      const workers = Math.min(4, Math.max(1, Math.floor((os.cpus().length || 4) / 2)));
      const chunks: string[][] = Array.from({ length: workers }, () => []);
      needConvert.forEach((n, i) => chunks[i % workers].push(n));
      const results = await Promise.all(
        chunks.map(
          (tables) =>
            new Promise<void>((resolve) => {
              const w = new Worker(workerPath, {
                workerData: { tables, outDir: OUT_DIR, dataDir: DATA_EXCEL_DIR, schemaDir: SCHEMA_DIR },
              });
              w.on("message", (m: any) => {
                if (m.done) { w.terminate(); resolve(); }
                else if (m.status === "ok") ok++;
                else if (m.status === "fail") { fail++; console.log(`  转换失败 ${m.name}: ${m.error}`); }
              });
              w.on("error", () => resolve());
            }),
        ),
      );
      void results;
    } else {
      // 内联转换（少量表）
      for (const name of needConvert) {
        const f = `${name}.json`;
        const out = path.join(DATA_EXCEL_DIR, f);
        const schemaPath = path.join(SCHEMA_DIR, f);
        try {
          const dec = JSON.parse(fs.readFileSync(path.join(OUT_DIR, f), "utf-8"));
          const loc = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf-8")) : null;
          const completion = buildCompletion(schemaPath);
          const result = convertTable(dec, loc, name, completion);
          fs.writeFileSync(out, JSON.stringify(result));
          ok++;
        } catch (e) {
          fail++;
          console.log(`  转换失败 ${name}: ${(e as Error).message.slice(0, 60)}`);
        }
      }
    }
    console.log(`转换完成: ${ok} ok, ${fail} fail${skipped ? `（跳过 ${skipped} 张未变更表）` : ""}`);
  }
}

/** 从 schema JSON 推导记录级字段清单（OpenArknightsFBS 结构） */
function buildCompletion(schemaPath: string): { fields: string[]; applyTo: "root" | "values"; schema?: any; recordType?: string } | undefined {
  if (!fs.existsSync(schemaPath)) return undefined;
  let schema: any;
  try {
    schema = JSON.parse(fs.readFileSync(schemaPath, "utf-8"));
  } catch {
    return undefined;
  }
  const root: string = schema.root || "";
  let recordType = root;
  let applyTo: "root" | "values" = "root";
  if (root.startsWith("clz_Torappu_SimpleKVTable_")) {
    recordType = root.slice("clz_Torappu_SimpleKVTable_".length);
    applyTo = "values";
  }
  const fields = (schema.tables?.[recordType] || []).map((x: any) => x.name);
  if (!fields.length) return undefined;
  return { fields, applyTo, schema, recordType };
}

main().catch((e) => {
  console.error("管线失败:", e);
  process.exit(1);
});
