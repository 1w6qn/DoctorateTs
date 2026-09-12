/**
 * 官方热更清单 Lua 自动提取器
 *
 * 自动抓取官方 hot_update_list 中所有「anon/」开头的资源，解包 UnityFS 并提取其中的 Lua
 * TextAsset（明文写入 <项目根>/data/[uc]lua/）。供 repack-lua-bundle --from-ref 等消费；
 * 与 extract-lua-bundle.ts（针对内置 base bundle）互为补充。
 *
 * 数据源说明（对齐官方热更语义）：
 *   - 官方 hot_update_list 的 abInfos 中，名称以 "anon/" 开头者为可热更的增量 AssetBundle。
 *   - 其中绝大多数为 excel 表 / 关卡 / 皮肤 / 自动战斗录像等非 Lua 资产；经 UnityFS 解包后，
 *     TextAsset 名单中仅少数 .lua（如任务收藏 holder CollectionTimedTaskItem.lua）。
 *   - 游戏逻辑主 Lua（anon/7d91430e114d86fef7d3b3511151e12d.bin，523 条属客户端 base 资产）
 *     **不在清单内**，由 extract-lua-bundle.ts 单独处理；两脚本互补覆盖全部 Lua 来源。
 *
 * 用法：
 *   pnpm run extract:lua:hot [--fetch] [--downloads <目录>] [--out <目录>] [--ref <lua参考目录>] [--size-cap <MB>]
 *   --fetch      先拉取官方热更清单并下载缺失的 anon 资源（有界并发池；体积超 size-cap 的跳过）
 *   --downloads  anon 资源目录（缺省 <项目根>/reference/hotupdate/downloads，兼容 excel 管线共用目录）
 *   --out        明文 Lua 输出目录（缺省 <项目根>/data/[uc]lua）
 *   --ref        Lua 参考目录（缺省 <项目根>/reference/ArknightsGameData/zh_CN/gamedata/[uc]lua），
 *                用于把热更 anon 中的平铺裸名自动还原到游戏内的分层路径（像 ArknightsGameData 一样）；
 *                目录不存在时平铺裸名保持原样。
 *   --size-cap   自动下载体积上限（MB，缺省 6；lua/text 类 bundle 较小，避免拉取 GB 级媒体）
 *   不加 --fetch 时，仅解包已存在的本地 anon 资源（incremental，复用 excel 管线已下载内容）。
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import JSZip from "jszip";
import { extractTextAssets, type TextAssetData } from "./vendor/unityfs";
import { decryptLuaScript, isLuaEncrypted } from "./vendor/lua-crypt";

/** 官方热更 CDN 根 */
const HU = "https://ak.hycdn.cn/assetbundle/official";
/** 官方版本配置（Windows resVersion） */
const CONF_VERSION = "https://ak-conf.hypergryph.com/config/prod/official/Windows/version";
/** 热更清单快照（无法联网时的回退） */
const HUL_SNAPSHOT = path.join(
  __dirname,
  "..",
  "reference",
  "hotupdate",
  "hot_update_list_26-08-07-10-51-39.json",
);
/** 默认下载目录（与 excel 管线共用 reference/hotupdate/downloads） */
function defaultDownloadsDir(): string {
  return path.join(__dirname, "..", "reference", "hotupdate", "downloads");
}
/** 默认输出目录（明文 Lua 入库位置） */
function defaultOutDir(): string {
  return path.join(__dirname, "..", "data", "[uc]lua");
}
/** 默认 Lua 参考目录（ArknightsGameData 分层目录，用于自动还原平铺裸名的真实路径） */
function defaultRefDir(): string {
  return path.join(
    __dirname,
    "..",
    "reference",
    "ArknightsGameData",
    "zh_CN",
    "gamedata",
    "[uc]lua",
  );
}
/** Lua 资产名前缀（对齐客户端资源名约定） */
const LUA_PREFIX = "gamedata/[uc]lua/";

/** 热更清单中的单个 AssetBundle 条目（官方 hot_update_list.json） */
interface AbInfo {
  name: string;
  /** 清单里可能缺省（消费侧按 undefined 放行） */
  totalSize?: number;
}

/** 官方热更清单（仅声明本脚本读取的字段） */
interface HotUpdateList {
  abInfos?: AbInfo[];
}

/** 提取统计 */
export interface ExtractLuaHotStats {
  scanned: number;      // 扫描的 anon 资源数
  written: number;      // 写入的 lua 文件数
  downloaded: number;   // 自动下载的资源数（--fetch）
  assetsTotal: number;  // 解包出的 TextAsset 总数（含非 lua）
}

/**
 * 客户端资源名 → .dat 文件名（与 excel 管线 transName 一致：/→_，#→__，扩展名→.dat）。
 * @param name - 客户端资源名（如 anon/xxx.bin）
 * @returns 本地 .dat 文件名
 */
function transName(name: string): string {
  return name.replace(/\.([^.]*)$/, ".dat").replace(/\//g, "_").replace(/#/g, "__");
}

/**
 * 拉取官方热更清单（失败回退本地快照）。
 * @returns 清单对象与 resVersion
 */
async function fetchHotUpdateList(): Promise<{ hul: HotUpdateList; resVersion: string }> {
  try {
    const verRes = await fetch(CONF_VERSION);
    const ver = (await verRes.json()) as { resVersion: string };
    const url = `${HU}/Windows/assets/${ver.resVersion}/hot_update_list.json`;
    const res = await fetch(url);
    const hul: HotUpdateList = await res.json();
    return { hul, resVersion: ver.resVersion };
  } catch {
    const hul: HotUpdateList = JSON.parse(fs.readFileSync(HUL_SNAPSHOT, "utf-8"));
    return { hul, resVersion: "26-08-07-10-51-39" };
  }
}

/**
 * 下载单个 anon 资源（已存在且体积>1KB 则跳过，返回 null 表示未下载）。
 * @param ab - 热更清单条目
 * @param resVersion - 资源版本号
 * @param downloadsDir - 下载目录
 * @returns 下载是否发生
 */
async function downloadAnon(ab: AbInfo, resVersion: string, downloadsDir: string): Promise<boolean> {
  const fn = transName(ab.name);
  const dat = path.join(downloadsDir, fn);
  if (fs.existsSync(dat) && fs.statSync(dat).size > 1000) return false;
  const url = `${HU}/Windows/assets/${resVersion}/${fn}`;
  const res = await fetch(url, { headers: { "User-Agent": "BestHTTP" } });
  if (!res.ok) return false;
  fs.writeFileSync(dat, Buffer.from(await res.arrayBuffer()));
  return fs.existsSync(dat) && fs.statSync(dat).size > 1000;
}

/**
 * 从 .dat/.bin 读取 UnityFS bundle 字节：.dat 结构为 zip（取首个非目录条目内层 bytes），
 * .bin 为裸 UnityFS。
 * @param file - 资源文件路径（.dat 或 .bin）
 * @returns UnityFS bundle 字节
 */
async function readBundleBytes(file: string): Promise<Uint8Array> {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".dat") {
    const zip = await JSZip.loadAsync(fs.readFileSync(file));
    const entries = Object.keys(zip.files).find((n) => !zip.files[n].dir);
    if (!entries) throw new Error(`.dat 内无条目: ${path.basename(file)}`);
    const inner = await zip.files[entries].async("uint8array");
    return new Uint8Array(inner);
  }
  return new Uint8Array(fs.readFileSync(file));
}

/**
 * 判断某 TextAsset 是否为 Lua 资产（兼容带 gamedata/[uc]lua/ 前缀与裸 .lua 两种布局）。
 * @param name - TextAsset 名
 * @returns 是否为 Lua
 */
function isLuaAsset(name: string): boolean {
  const lower = name.toLowerCase();
  return lower.startsWith(LUA_PREFIX) || lower.endsWith(".lua");
}

/**
 * 从 Lua 参考目录构建 basename → 完整相对路径 的映射（像 ArknightsGameData 一样分层）。
 * 用于把热更 anon 中「平铺裸名」的 lua 自动还原到其在游戏中的真实路径（如 base/utils/、
 * feature/operation/.../）。映射 key 为小写 basename，value 为相对 [uc]lua 目录的路径。
 * @param refDir - Lua 参考目录（如 reference/ArknightsGameData/zh_CN/gamedata/[uc]lua）
 * @returns basename(小写) → 相对路径 映射；目录不存在影返回空映射
 */
function buildPathMap(refDir?: string): Map<string, string> {
  const map = new Map<string, string>();
  if (!refDir || !fs.existsSync(refDir)) return map;
  const walk = (cur: string): void => {
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.toLowerCase().endsWith(".lua")) {
        const rel = path.relative(refDir, full).split(path.sep).join("/");
        map.set(rel.split("/").pop()!.toLowerCase(), rel);
      }
    }
  };
  walk(refDir);
  return map;
}

/**
 * 解析某个 lua TextAsset 的相对输出路径：
 *   1) 资产名本身带 gamedata/[uc]lua/ 前缀 → 直接剥前缀；
 *   2) 否则为平铺裸名 → 用参考映射还原分层路径（命中则还原，未命中保持裸名平铺）。
 * @param name   - TextAsset 名
 * @param pathMap - basename → 相对路径 映射
 * @returns 相对输出路径
 */
function resolveLuaRelPath(name: string, pathMap: Map<string, string>): string {
  const lower = name.toLowerCase();
  if (lower.startsWith(LUA_PREFIX)) return name.slice(LUA_PREFIX.length);
  const mapped = pathMap.get(lower);
  return mapped ?? name;
}

/**
 * 从单个 anon 资源解包并提取 Lua，写入 outDir。
 * @param file - .dat/.bin 资源路径
 * @param outDir - 明文输出目录
 * @param pathMap - basename → 相对路径 映射（用于把平铺裸名还原为分层路径；可为空映射）
 * @returns 该资源内写入的 lua 条数与 TextAsset 总数（null 表示非 UnityFS，跳过）
 */
async function extractLuaFromBundle(
  file: string,
  outDir: string,
  pathMap: Map<string, string>,
): Promise<{ written: number; total: number } | null> {
  let bytes: Uint8Array;
  let assets: TextAssetData[];
  try {
    bytes = await readBundleBytes(file);
    // UnityFS 魔数校验：占位/损坏文件绕过，避免 extractTextAssets 在无空字节缓冲区上死循环
    if (
      bytes.length < 7 ||
      String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]) !==
        "UnityFS"
    ) {
      return null;
    }
    assets = extractTextAssets(bytes);
  } catch {
    return null; // 非 UnityFS 或损坏，跳过
  }
  let written = 0;
  for (const asset of assets) {
    if (!isLuaAsset(asset.name)) continue;
    // 解密（Android CRYPTIC_A 加密；明文原样保留）
    let script = asset.script;
    try {
      if (isLuaEncrypted(script)) script = decryptLuaScript(script);
    } catch {
      /* 解密失败视为明文，保留原始字节供人工分析 */
    }
    const rel = resolveLuaRelPath(asset.name, pathMap);
    if (!rel) continue; // 空相对路径（如恰好名称为 "gamedata/[uc]lua/"）忽略
    const outPath = path.join(outDir, rel);
    if (!outPath.startsWith(outDir + path.sep)) continue; // 路径穿越防护
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, Buffer.from(script));
    written++;
  }
  return { written, total: assets.length };
}

/**
 * 扫描本地已有 anon 资源，逐一解包提取 Lua。
 * @param downloadsDir - anon 资源目录
 * @param outDir - 明文输出目录
 * @param refDir - Lua 参考目录（可选；用于自动还原平铺裸名的分层路径）
 * @returns 已扫描 / 已写入统计
 */
async function extractFromLocal(
  downloadsDir: string,
  outDir: string,
  refDir?: string,
): Promise<ExtractLuaHotStats> {
  const pathMap = buildPathMap(refDir);
  const files = fs
    .readdirSync(downloadsDir, { withFileTypes: true })
    .filter((d) => {
      if (!d.isFile()) return false;
      const name = d.name.toLowerCase();
      return (
        (name.startsWith("anon_") || name.startsWith("anon-")) &&
        (name.endsWith(".dat") || name.endsWith(".bin"))
      );
    })
    .map((d) => path.join(downloadsDir, d.name));
  let written = 0;
  let assetsTotal = 0;
  for (const file of files) {
    const result = await extractLuaFromBundle(file, outDir, pathMap);
    if (result) {
      assetsTotal += result.total;
      written += result.written;
    }
  }
  return { scanned: files.length, written, downloaded: 0, assetsTotal };
}

/**
 * 主流程：抓取清单（可选）→ 下载缺失 anon 资源（可选）→ 解包本地资源提取 Lua。
 * @param opts - 提取选项
 * @returns 统计信息
 */
export async function extractLuaFromHotUpdate(opts: {
  fetch?: boolean;
  downloadsDir?: string;
  outDir?: string;
  refDir?: string;
  sizeCapMB?: number;
}): Promise<ExtractLuaHotStats> {
  const downloadsDir = opts.downloadsDir ?? defaultDownloadsDir();
  const outDir = opts.outDir ?? defaultOutDir();
  fs.mkdirSync(downloadsDir, { recursive: true });
  fs.mkdirSync(outDir, { recursive: true });

  let downloaded = 0;
  if (opts.fetch) {
    const sizeCapByte = (opts.sizeCapMB ?? 6) * 1024 * 1024;
    const { hul, resVersion } = await fetchHotUpdateList();
    const candidates = (hul.abInfos || []).filter(
      (ab) =>
        ab.name.startsWith("anon/") &&
        (ab.totalSize === undefined || ab.totalSize <= sizeCapByte),
    );
    // 有界并发下载（IO 密集，并发上限 6）
    let idx = 0;
    const n = Math.min(6, Math.max(1, os.cpus().length || 4));
    async function worker(): Promise<void> {
      while (idx < candidates.length) {
        const i = idx++;
        if (await downloadAnon(candidates[i], resVersion, downloadsDir)) downloaded++;
      }
    }
    await Promise.all(Array.from({ length: n }, () => worker()));
  }

  const local = await extractFromLocal(downloadsDir, outDir, opts.refDir ?? defaultRefDir());
  return { ...local, downloaded };
}

/** CLI 入口 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const fetch = args.includes("--fetch");
  const di = args.indexOf("--downloads");
  const oi = args.indexOf("--out");
  const si = args.indexOf("--size-cap");
  const ri = args.indexOf("--ref");
  const downloadsDir = di >= 0 ? args[di + 1] : defaultDownloadsDir();
  const outDir = oi >= 0 ? args[oi + 1] : defaultOutDir();
  const sizeCapMB = si >= 0 ? Number(args[si + 1]) : 6;
  const refDir = ri >= 0 ? args[ri + 1] : defaultRefDir();

  const stats = await extractLuaFromHotUpdate({ fetch, downloadsDir, outDir, refDir, sizeCapMB });
  console.log(`扫描 anon 资源: ${stats.scanned} 个`);
  if (stats.downloaded > 0) console.log(`自动下载: ${stats.downloaded} 个`);
  console.log(`提取 TextAsset: ${stats.assetsTotal} 条`);
  console.log(`写入明文 Lua: ${stats.written} 条 → ${outDir}`);
  if (fs.existsSync(refDir)) {
    console.log(`路径还原: 已按参考目录 ${refDir} 自动还原平铺裸名 → 分层路径`);
  } else {
    console.log(`提示: 参考目录不存在（${refDir}），平铺裸名未还原；存在时可按 ArknightsGameData 分层自动还原。`);
  }
  if (stats.written === 0) {
    console.log("提示: 官方热更清单 anon 中当前未发现 Lua；游戏逻辑主 Lua 请用 `pnpm run extract:lua`。");
  }
}

if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error("提取失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}