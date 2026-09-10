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
import { LUACRYPT_MASK } from "./vendor/lua-crypt";
import { convertTable, buildCompletion, isUpToDate } from "./excel-convert";
import { assetRegistry } from "@asset/asset-service";

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
  // mask 与 lua 加密共用同一常量（vendor/lua-crypt LUACRYPT_MASK = excel 管线 MASK_V2），单点维护
  const mask = LUACRYPT_MASK;
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
  const abInfos: AbInfo[] = hul.abInfos || [];
  const bundleMap = new Map<string, string>(); // base → dat
  /**
   * 扫描 DL_DIR 中**已存在**的 anon bundle，按内部 TextAsset 名匹配 excel 表白名单
   *
   * 表名只能从 bundle 本体读出（readTextAssetNameCached），故该函数天然只能发现
   * 已下载的文件；下载完成后需再次调用以收录新文件。
   */
  async function scanBundleMap(): Promise<Map<string, string>> {
    const map = new Map<string, string>();
    for (const ab of abInfos) {
      if (!ab.name.startsWith("anon/")) continue;
      const dat = path.join(DL_DIR, transName(ab.name));
      if (!fs.existsSync(dat)) continue;
      const name = await readTextAssetNameCached(dat);
      if (!name) continue;
      const base = name.replace(/[0-9a-f]{6}$/, "");
      if (TABLE_WHITELIST.has(base)) map.set(base, dat);
    }
    saveNameCache();
    return map;
  }
  if (doDownload || doDecode) {
    for (const [k, v] of await scanBundleMap()) bundleMap.set(k, v);
    if (tableArg) {
      if (bundleMap.has(tableArg)) {
        for (const k of bundleMap.keys()) {
          if (k !== tableArg) bundleMap.delete(k);
        }
      } else {
        // 修复（2026-09-09）：`--table X` 未命中时原实现静默忽略过滤条件 → 退化为全量解码
        // （大批量场景直接 OOM）。未命中即无可解码目标，明确退出并提示。
        console.log(`未找到表 ${tableArg}（不在本批 bundle 中）`);
        bundleMap.clear();
      }
    }
    console.log(`excel 表: ${bundleMap.size}`);
  }

  if (doDownload) {
    // S7：下载由串行改为有界并发池——downloadBundle 是网络 IO，逐个等待造成瓶颈；
    // 并发池让多个 bundle 的 HTTP + 落盘重叠。并发数 cap 6（IO 密集，略高于 decode）。
    //
    // 修复（2026-09-09）：待下载集合原先取自 bundleMap，而 bundleMap 只收录**已存在**的
    // bundle（表名必须读出 bundle 本体才知道）→ pending 恒空，管线**永远下载不到新文件**，
    // 只能消费预置缓存（新 clone / 官方新增表都会静默 0 下载）。现按清单遍历全部 anon 条目，
    // 下载缺失文件，下载完成后重建 bundleMap 供 decode 使用。
    let n = 0;
    const pending = abInfos.filter(
      (ab) =>
        ab.name.startsWith("anon/") &&
        !((): boolean => {
          const dat = path.join(DL_DIR, transName(ab.name));
          return fs.existsSync(dat) && fs.statSync(dat).size > 1000;
        })(),
    );
    console.log(`待下载 anon bundle: ${pending.length}/${abInfos.length}`);
    let idx = 0;
    async function downloadWorker(): Promise<void> {
      while (idx < pending.length) {
        const i = idx++;
        const ab = pending[i];
        if (await downloadBundle(ab, resVersion)) {
          n++;
          console.log(`  已下载 ${ab.name}`);
        }
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(6, Math.max(1, os.cpus().length || 4)) }, downloadWorker),
    );
    console.log(`下载完成: ${n}`);
    // 重建 excel 表映射：新下载的 bundle 需重新识别 TextAsset 名并按白名单收录
    bundleMap.clear();
    for (const [k, v] of await scanBundleMap()) bundleMap.set(k, v);
    console.log(`excel 表: ${bundleMap.size}`);
    // 溯源：官方 excel 数据获取留痕（batch 脚本阻塞写可接受）
    try {
      await assetRegistry.recordEvent({
        asset: { name: "官方excel数据集", category: "excel", source: HU, version: resVersion, size: n },
        action: "acquire",
        actor: "official-excel",
        source: HU,
        version: resVersion,
        detail: { downloadedBundles: n, resVersion },
      });
    } catch { /* 溯源失败不阻断管线 */ }
  }

  if (doDecode) {
    // S7：解码由串行改为有界并发池——decodeBundle 为 async（JSZip 解压即 IO），
    // 原先 for...of 逐个等待造成串行 IO；并发池让多个 bundle 的解压/解密/读写重叠。
    // 并发数取 CPU 核数（cap 4）：decoder 同步 CPU 段（FBO/AES）仍占主线程，
    // 核数外并发无额外 CPU 收益；IO 侧异步重叠已足够摊薄总耗时。
    let ok = 0, fail = 0;
    const entries = [...bundleMap.entries()].sort();
    let idx = 0;
    // 并发度可用 EXCEL_DECODE_CONCURRENCY 覆盖（大数据表解码内存峰值高，串行化可显著降低峰值）
    const decodeConcurrency = Math.max(
      1,
      Number(process.env.EXCEL_DECODE_CONCURRENCY) ||
        Math.min(4, Math.max(1, os.cpus().length || 4)),
    );
    async function decodeWorker(): Promise<void> {
      while (idx < entries.length) {
        // Node 单线程：idx++ 无竞态，各 worker 顺序取任务
        const i = idx++;
        const [base, dat] = entries[i];
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
    }
    await Promise.all(Array.from({ length: decodeConcurrency }, decodeWorker));
    console.log(`解码完成: ${ok} ok, ${fail} fail`);
  }

  if (doConvert) {
    let ok = 0, fail = 0, skipped = 0;
    const allTables = fs.readdirSync(OUT_DIR).filter((x) => x.endsWith(".json")).map((x) => x.slice(0, -5)).sort();
    const targets = tableArg ? allTables.filter((n) => n === tableArg) : allTables;
    // 并行转换：需转换的表数较多时用 worker_threads（首次/新版本全量）；否则内联
    const needConvert = targets.filter((name) => {
      const f = `${name}.json`;
      return !isUpToDate(
        path.join(OUT_DIR, f),
        path.join(DATA_EXCEL_DIR, f),
        path.join(SCHEMA_DIR, f),
      );
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
    // 溯源：官方 excel 转换（transform）留痕
    try {
      await assetRegistry.recordEvent({
        asset: { name: "官方excel数据集", category: "excel", source: HU, version: resVersion },
        action: "transform",
        actor: "official-excel",
        source: "FBO/AES 解码 → data/excel",
        version: resVersion,
        detail: { ok, fail, skipped, resVersion, tableCount: ok + skipped },
      });
    } catch { /* 溯源失败不阻断管线 */ }
  }
}

main().catch((e) => {
  console.error("管线失败:", e);
  process.exit(1);
});
