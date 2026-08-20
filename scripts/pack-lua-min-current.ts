/**
 * 针对当前版本的 Lua 最小更新包构建脚本
 *
 * 依据官方热更机制（全量清单 + 内容寻址 + md5 差异增量下载）：
 * 1. 拉取**当前**官服 Windows hot_update_list。
 * 2. **检测清单中所有承载 DefinedFix.lua 的 bundle**（下载候选 anon/*.bin 并逐个解包验证），
 *    官方当前版本实测为单一热更 Lua bundle anon/6edf14bb...bin；若未来出现多处则逐一覆盖。
 * 3. 复用 pack-lua-min 构建最小更新包（补丁后 DefinedFix + 全部插件资产），哈希命名。
 * 4. 输出「清单 diff 补丁」JSON：对**每个**含 DefinedFix 的官方 bundle 生成一条替换补丁
 *    （name 沿用官方 bundle、md5/totalSize 换成最小包值）——客户端届时
 *    _CheckIfAssetDirty(md5 != oldMd5) 即为"有更新"而重新下载私服提供的最小包。
 *
 * 落盘：
 *   - mod 产物：mods/anon_<内容md5>.dat       （zip 单条目 anon/<内容md5>.bin，可直接被 asset 注入）
 *   - 补丁描述：mods/lua-min-current.patch.json（含 patches[] 逐一覆盖清单）
 *
 * 用法：
 *   pnpm run pack:lua:min:current [--platform <windows|android|all>] [--plugin <插件目录>] [--out <mods目录>] [--offline] [--no-scan]
 *   --platform 目标平台：windows / android / all（缺省 windows）——all 一键同时打包两平台
 *   --plugin   插件源码目录（缺省 lua/plugin）
 *   --out      mods 根目录（缺省 mods/）
 *   --offline  不联网，用本地 data/config.json 的平台 resVersion 快照定位；扫描复用本地下载桶
 *   --no-scan  跳过「下载并解包检测 DefinedFix」（仅用已知 hash 前缀/回退，更快但可能漏新 bundle）
 *   每次构建后自动移除 <平台> 目录中的旧 anon_<hash>.dat（哈希命名 Lua mod 残留）。
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import JSZip from "jszip";
import config from "../app/config";
import { extractTextAssets } from "./vendor/unityfs";
import { buildLuaMinPack } from "./pack-lua-min";

/** 官方热更 CDN 根 */
const HU = "https://ak.hycdn.cn/assetbundle/official";
/** 官方 Windows 版本配置 */
const CONF_VERSION = "https://ak-conf.hypergryph.com/config/prod/official/Windows/version";
/** 清单快照目录（reference/hotupdate） */
const HUL_DIR = path.join(__dirname, "..", "reference", "hotupdate");
/** 检测用临时下载桶（gitignore 之外，保留供重复跑） */
const DETECT_DL_DIR = path.join(HUL_DIR, "downloads-min");
/** 缺省插件目录 */
function defaultPluginDir(): string {
  return path.join(__dirname, "..", "lua", "plugin");
}
/** 缺省 mods 目录 */
function defaultOutDir(): string {
  return path.join(__dirname, "..", "mods");
}

interface AbInfo {
  name: string;
  hash?: string;
  md5?: string;
  totalSize?: number;
  abSize?: number;
}

/** 当前 Lua 主 bundle 名（兜底，用于历史/已知 base 名） */
const FALLBACK_LUA_NAME = "anon/7d91430e114d86fef7d3b3511151e12d.bin";

/** 已知的官方热更 Lua bundle hash 前缀（各版本演化；--no-scan / Windows 兜底时用） */
const KNOWN_LUA_HASH_PREFIXES = [
  "6edf14bbd79243eb61e288ff28e446c3", // 26-08-17 Windows 热更 Lua bundle
  "5c28e2180b6ed701022b9e99cd8b33b4", // 26-08-07 Windows 热更 Lua bundle
];

/** live 模式检测并发上限（网络 IO 密集） */
const DETECT_CONCURRENCY = 6;

/** 客户端资源名 → 本地 .dat 文件名（/→_、扩名→.dat，与 asset/loadMods 语义一致） */
function transName(name: string): string {
  return name.replace(/\.([^.]*)$/, ".dat").replace(/\//g, "_").replace(/#/g, "__");
}

/** 哈希命名 anon mod 的文件名判定（anon_<32位hex>.dat） */
const ANON_HASH_RE = /^anon_[0-9a-f]{32}\.dat$/i;
/** 平台 → 专属 mod 子目录（对齐 app/asset.ts PLATFORM_DIRS） */
const PLATFORM_DIRS: Record<string, string> = { Windows: "windows", Android: "android" };

/**
 * 解析平台对应的当前 resVersion。
 * Windows → config.version.windows.resVersion；Android/其它 → config.version.resVersion。
 * @param platform - 平台键（Windows/Android）
 * @returns resVersion
 */
function platformResVersion(platform: string): string {
  if (platform === "Windows") {
    return config.version?.windows?.resVersion ?? config.version?.resVersion ?? "";
  }
  return config.version?.resVersion ?? "";
}

/**
 * 拉取指定平台当前官服 hot_update_list 并落盘快照。
 * Windows/Android 资源各自独立 CDN 目录与版本号。
 * @param platform - 平台键（Windows/Android）
 * @returns 清单对象与 resVersion
 */
async function fetchCurrentHotUpdateList(platform: string): Promise<{ hul: any; resVersion: string }> {
  const verRes = await fetch(CONF_VERSION.replace("/Windows/", `/${platform}/`));
  if (!verRes.ok) throw new Error(`拉取版本失败: HTTP ${verRes.status}`);
  const ver = (await verRes.json()) as { resVersion: string };
  const url = `${HU}/${platform}/assets/${ver.resVersion}/hot_update_list.json`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`拉取热更清单失败: HTTP ${res.status} @ ${url}`);
  const hul = await res.json();
  fs.mkdirSync(HUL_DIR, { recursive: true });
  const fp = path.join(HUL_DIR, `hot_update_list_${ver.resVersion}.json`);
  fs.writeFileSync(fp, JSON.stringify(hul, null, 2));
  return { hul, resVersion: ver.resVersion };
}

/**
 * 读取 .dat/.bin 为 UnityFS bundle 字节：.dat 为 zip 包裹，取首条目内层；.bin 直读。
 * @param file - 文件路径
 * @returns UnityFS bundle 字节
 */
async function readBundleBytes(file: string): Promise<Uint8Array> {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".dat") {
    const z = await JSZip.loadAsync(fs.readFileSync(file));
    const entry = Object.keys(z.files).find((n) => !z.files[n].dir);
    if (!entry) throw new Error(`.dat 空: ${path.basename(file)}`);
    return new Uint8Array(await z.files[entry].async("uint8array"));
  }
  return new Uint8Array(fs.readFileSync(file));
}

/**
 * 解包本地 .dat/.bin，判断是否含 DefinedFix.lua 资产。
 * @param file - .dat/.bin 路径
 * @returns 含 DefinedFix 为 true
 */
function bundleHasDefinedFix(bytes: Uint8Array): boolean {
  if (bytes.length < 7 || String.fromCharCode(...bytes.slice(0, 7)) !== "UnityFS") return false;
  const assets = extractTextAssets(bytes);
  return assets.some((a) => /definedfix\.lua$/i.test(a.name));
}

/**
 * 下载单个 anon bundle 到本地桶（已存在则跳过）。
 * @param ab   - 清单条目
 * @param resVersion - 资源版本号
 * @param platform - 平台键（Windows/Android）
 * @param dlDir - 下载目录
 * @returns 本地文件路径（下载失败返回 null）
 */
async function ensureDownloaded(
  ab: AbInfo,
  resVersion: string,
  platform: string,
  dlDir: string,
): Promise<string | null> {
  const fn = transName(ab.name);
  const dat = path.join(dlDir, fn);
  if (fs.existsSync(dat) && fs.statSync(dat).size > 1000) return dat;
  const url = `${HU}/${platform}/assets/${resVersion}/${fn}`;
  const res = await fetch(url, { headers: { "User-Agent": "BestHTTP" } });
  if (!res.ok) return null;
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length <= 1000) return null;
  fs.writeFileSync(dat, buf);
  return dat;
}

/**
 * 从清单候选（anon/*.bin，观察体积）中检测所有含 DefinedFix 的 bundle。
 * live：下载候选并逐个解包检测（按平台隔离下载目录）；offline：扫本地桶，否则回退已知 hash（仅 Windows）。
 * @param hul - 热更清单
 * @param resVersion - 资源版本号
 * @param platform - 平台键（Windows/Android）
 * @param offline - 是否离线
 * @param allowScan - 是否全量下载检测
 * @returns 含 DefinedFix 的官方 bundle 名（保持清单顺序）
 */
async function detectDefinedFixBundles(
  hul: any,
  resVersion: string,
  platform: string,
  offline: boolean,
  allowScan: boolean,
): Promise<string[]> {
  const abInfos: AbInfo[] = hul.abInfos || [];
  // 候选：anon/开头 .bin，体积 0.5KB~4MB（排除 excel 大表与极小占位，着眼脚本类）
  const cands = abInfos.filter(
    (a) =>
      /^anon\/[0-9a-f]+\.bin$/i.test(a.name) &&
      (a.totalSize ?? 0) > 500 &&
      (a.totalSize ?? 0) < 4 * 1024 * 1024,
  );
  if (cands.length === 0) return [];

  // ① 已知 hash 前缀命中（仅 Windows 有确认 hash；作为 --no-scan / live 兜底保底）
  const result = new Set<string>();
  if (platform === "Windows") {
    for (const a of cands)
      if (KNOWN_LUA_HASH_PREFIXES.some((p) => a.name.includes(p))) result.add(a.name);
  }

  // ② 全量检测（live 且允许联网扫描，或 offline 且本地桶可判断）
  if (allowScan) {
    const dlDir = path.join(DETECT_DL_DIR, platform.toLowerCase());
    fs.mkdirSync(dlDir, { recursive: true });
    const toCheck = offline
      ? // offline：仅检测本地桶中已存在的候选文件（避免联网）
        cands.filter((a) => fs.existsSync(path.join(dlDir, transName(a.name))))
      : // live：全部候选下载并检测
        cands;

    let idx = 0;
    const results = new Map<string, boolean>();
    async function worker(): Promise<void> {
      while (idx < toCheck.length) {
        const i = idx++;
        const ab = toCheck[i];
        let dat: string | null;
        try {
          dat = offline
            ? path.join(dlDir, transName(ab.name))
            : await ensureDownloaded(ab, resVersion, platform, dlDir);
        } catch {
          dat = null;
        }
        if (!dat) continue;
        try {
          const has = bundleHasDefinedFix(await readBundleBytes(dat));
          results.set(ab.name, has);
        } catch {
          results.set(ab.name, false);
        }
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(DETECT_CONCURRENCY, Math.max(1, os.cpus().length || 4)) }, worker),
    );
    for (const [name, has] of results) if (has) result.add(name);
  }

  // 按清单原顺序返回
  return [...result].sort((a, b) => a.localeCompare(b));
}

/** 单个替换补丁描述 */
export interface LuaMinPatch {
  name: string;
  md5: string;
  totalSize: number;
  abSize: number;
  replaceOf: string;
}

/**
 * 移除某平台 mods 目录中的旧 anon 哈希命名 Lua mod。
 * 保留：新产物（其文件名 = 传入的 datName）、以及非 anon_<32hex>.dat 的其它 mod（皮肤等）。
 * @param platformModsDir - 平台 mods 目录（如 mods/windows）
 * @param keepDatName     - 新产物 mod 文件名（予以保留）
 * @returns 被移除的文件名列表
 */
function removeOldAnonMods(platformModsDir: string, keepDatName: string): string[] {
  const removed: string[] = [];
  if (!fs.existsSync(platformModsDir)) return removed;
  for (const name of fs.readdirSync(platformModsDir)) {
    // 旧 anon 最小/整包：哈希命名且非新产物；保留其它（placeholder / 皮肤 mod / 非哈希 anon）
    if (ANON_HASH_RE.test(name) && name !== keepDatName) {
      const p = path.join(platformModsDir, name);
      fs.rmSync(p, { force: true });
      removed.push(name);
    }
  }
  return removed;
}

/**
 * 针对当前版本，为指定平台构建最小 Lua 更新包并生成清单补丁
 * （逐一覆盖该平台清单中所有含 DefinedFix 的 bundle），并自动移除该平台旧 anon。
 * @param pluginDir - 插件目录
 * @param outRoot   - mods 根目录（产物写入 <outRoot>/<platform> 平台子目录）
 * @param platform  - 平台键（Windows/Android）
 * @param offline   - 是否离线（用 config 平台 resVersion + 本地快照；扫描仅用本地桶）
 * @param allowScan - 是否执行「下载并解包检测 DefinedFix」（缺省 true）
 * @returns 补丁信息（resVersion / 产物 / 清单一至覆盖 patches[]）
 */
export async function buildMinForCurrentVersion(
  pluginDir: string,
  outRoot: string,
  platform: string,
  offline: boolean = false,
  allowScan: boolean = true,
): Promise<{
  platform: string;
  resVersion: string;
  source: "live" | "snapshot";
  dat: string;
  bundleName: string;
  replaceOf: string;
  patch: LuaMinPatch;
  patches: LuaMinPatch[];
  removedOld: string[];
}> {
  // 平台专属输出目录（mods/windows | mods/android，对齐 asset.ts 平台 mod 目录）
  const platformOut = path.join(outRoot, PLATFORM_DIRS[platform] ?? platform.toLowerCase());
  fs.mkdirSync(platformOut, { recursive: true });

  // 1. 定位当前平台适配的版本清单
  let hul: any;
  let resVersion: string;
  let source: "live" | "snapshot";
  if (!offline) {
    try {
      ({ hul, resVersion } = await fetchCurrentHotUpdateList(platform));
      source = "live";
    } catch (error) {
      console.warn(
        `[warn] 联网拉取 ${platform} 清单失败（${(error as Error).message}），回退 config 快照`,
      );
      resVersion = platformResVersion(platform);
      if (!resVersion) throw new Error(`无 ${platform} 当前 resVersion（config.version 缺失），无法定位清单`);
      const fp = path.join(HUL_DIR, `hot_update_list_${resVersion}.json`);
      if (!fs.existsSync(fp)) throw new Error(`本地无该版本清单快照: ${fp}`);
      hul = JSON.parse(fs.readFileSync(fp, "utf8"));
      source = "snapshot";
    }
  } else {
    resVersion = platformResVersion(platform);
    if (!resVersion) throw new Error(`offline 模式需要 config.version 提供 ${platform} resVersion`);
    const fp = path.join(HUL_DIR, `hot_update_list_${resVersion}.json`);
    if (!fs.existsSync(fp)) throw new Error(`本地无该版本清单快照: ${fp}`);
    hul = JSON.parse(fs.readFileSync(fp, "utf8"));
    source = "snapshot";
  }

  // 2. 检测该平台所有含 DefinedFix 的 bundle（逐一覆盖目标）
  const dfBundles = await detectDefinedFixBundles(hul, resVersion, platform, offline, allowScan);
  if (dfBundles.length === 0) {
    throw new Error(
      `未在 ${platform} 版本清单中检测到含 DefinedFix 的 bundle（resVersion=${resVersion}）。` +
        `请确认清单源正确，或去掉 --no-scan 以全量下载检测。`,
    );
  }

  // 3. 构建最小更新包（DefinedFix 补丁 + 插件），哈希命名，写入平台目录
  const pack = await buildLuaMinPack(undefined, pluginDir, platformOut);

  // 4. 自动移除平台目录中的旧 anon 哈希命名 mod（保留新产物与其它非哈希 mod）
  const removedOld = removeOldAnonMods(platformOut, pack.datName);

  // 5. 生成逐一覆盖补丁：对每个含 DefinedFix 的官方 bundle 生成一条 patch
  const bundleHash = pack.bundleName.replace(/^anon\//, "").replace(/\.bin$/, "");
  const totalSize = fs.statSync(pack.dat).size;
  const makePatch = (replaceOf: string): LuaMinPatch => ({
    name: pack.bundleName,
    md5: bundleHash,
    totalSize,
    abSize: pack.bundle.length,
    replaceOf,
  });
  const patches = dfBundles.map(makePatch);

  // 6. 写补丁描述 JSON（平台专属）
  const patchPath = path.join(platformOut, "lua-min-current.patch.json");
  const payload = {
    platform,
    resVersion,
    source,
    builtAt: new Date().toISOString(),
    pluginDir,
    dat: path.relative(process.cwd(), pack.dat),
    datName: pack.datName,
    bundleName: pack.bundleName,
    bundleBytes: pack.bundle.length,
    pluginCount: pack.pluginCount,
    definedFixBundles: dfBundles,
    patches,
    removedOld,
    note:
      "client 判定约定：官方清单中各 replaceOf 条目 name 的 md5 与本地不同 → 下载私服最小包。" +
      "请把热更清单 abInfos 中对 patches[].replaceOf 的每条条目替换为对应 patch（同 name、新 md5/totalSize），" +
      "或直接把该 .dat 作为 mod 注入（asset.ts 会自动建条目）。patches[] 已覆盖全部含 DefinedFix 的 bundle。",
  };
  fs.writeFileSync(patchPath, JSON.stringify(payload, null, 2));

  return {
    platform,
    resVersion,
    source,
    dat: pack.dat,
    bundleName: pack.bundleName,
    replaceOf: dfBundles[0],
    patch: patches[0],
    patches,
    removedOld,
  };
}

/**
 * 打印单个平台的最小包构建结果摘要。
 * @param outRoot - mods 根目录
 * @param result  - 单平台构建结果
 */
function printResult(outRoot: string, result: ReturnType<typeof buildMinForCurrentVersion> extends Promise<infer T> ? T : never): void {
  console.log(`平台: ${result.platform}`);
  console.log(`当前版本(resVersion): ${result.resVersion}  (来源: ${result.source})`);
  console.log(`最小 Lua 更新包: ${result.dat}`);
  console.log(`  bundle: ${result.bundleName} (补丁 DefinedFix + 插件)`);
  console.log(`检测到含 DefinedFix 的 bundle: ${result.patches.length} 个`);
  result.patches.forEach((p, i) => console.log(`  [${i + 1}] 覆盖 ${p.replaceOf}`));
  if (result.removedOld.length) {
    console.log(`已移除旧 anon mod: ${result.removedOld.length} 个`);
    result.removedOld.forEach((n) => console.log(`  - ${n}`));
  } else {
    console.log("无旧 anon mod 待移除");
  }
  const patchOut = path.join(outRoot, PLATFORM_DIRS[result.platform] ?? result.platform.toLowerCase());
  console.log(`补丁描述已写: ${path.join(patchOut, "lua-min-current.patch.json")}`);
}

/** CLI 入口 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const pluginIdx = args.indexOf("--plugin");
  const outIdx = args.indexOf("--out");
  const platformIdx = args.indexOf("--platform");
  const offline = args.includes("--offline");
  const allowScan = !args.includes("--no-scan");
  const pluginDir = pluginIdx >= 0 ? args[pluginIdx + 1] : defaultPluginDir();
  const outRoot = outIdx >= 0 ? args[outIdx + 1] : defaultOutDir();

  // 平台键规范化：windows→Windows、android→Android、all→同时两平台
  const rawPlatform = platformIdx >= 0 ? (args[platformIdx + 1] ?? "Windows") : "Windows";
  const platformArg = rawPlatform.toLowerCase();
  const platforms =
    platformArg === "all" ? ["Windows", "Android"] : platformArg === "android" ? ["Android"] : ["Windows"];

  console.log(`一键构建平台: ${platforms.join(" + ")}${offline ? "（offline）" : ""}\n`);
  let allOk = true;
  for (const platform of platforms) {
    console.log(`========== ${platform} ==========`);
    try {
      const result = await buildMinForCurrentVersion(pluginDir, outRoot, platform, offline, allowScan);
      printResult(outRoot, result);
      console.log();
    } catch (error) {
      allOk = false;
      console.error(`[ERROR] ${platform} 构建失败: ${(error as Error).message}\n`);
    }
  }

  console.log(`\n启用：将 .dat 放入 mods/ 下各自平台目录（asset 自动注入清单），客户端按补丁 md5 差异逐一重新下载。`);
  if (!allOk) process.exitCode = 1;
}

if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error("构建失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}