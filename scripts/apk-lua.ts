/**
 * 自动抓取最新版官服 Android APK 并注入 Lua 引导（工作流）
 *
 * 背景：内置 Lua 主 bundle（如 anon/7d91430e114d86fef7d3b3511151e12d.bin）是客户端 base 资产，
 * 不在官方 hot_update_list 中、CDN 亦 404，唯一取数源是已装客户端 / 安装包。本脚本把
 * 「下载 APK → 解包定位 Lua bundle → 提取明文 → 注入插件引导（merge lua/plugin + patch DefinedFix）」
 * 全链路自动化，产出 mods/anon_*.dat 供 app/asset.ts 热更下发。
 *
 * 下载源（多级回退）：
 *   1. 官方稳定链接 https://ak.hypergryph.com/downloads/android_lastest（302 跟随 → 最新 APK）
 *   2. gryph-links 跟踪链接（GitHub raw 文本直链，社区定时维护：SkyBird233/gryph-links）
 *   3. 用户手动：--apk <本地路径|URL>
 *
 * 用法：
 *   pnpm run apk:lua                              # 自动下载最新 APK → 解包 → 提取明文 → 注入引导
 *   pnpm run apk:lua -- --apk ./arknights.apk     # 用本地 APK（跳过下载）
 *   pnpm run apk:lua -- --extract-only            # 只解包提取明文 Lua 到参考目录（不 repack）
 *   pnpm run apk:lua -- --repack-only <bundle.bin> [--bundle-name <客户端资源名>]  # 只做注入（已有 bundle）
 *   pnpm run apk:lua -- --force                   # 忽略缓存，强制重新下载 APK
 *   pnpm run apk:lua -- --no-extract              # 跳过明文提取（仅注入）
 *   pnpm run apk:lua -- --out <mods目录>           # 输出 mods 目录（缺省 <项目根>/mods）
 */
import * as fs from "fs";
import * as path from "path";
import { Readable } from "stream";
import yauzl from "yauzl";
import { extractTextAssets } from "./vendor/unityfs";
import { extractLuaBundle } from "./extract-lua-bundle";
import { repackBuiltinLua } from "./repack-lua-bundle";

/** 官方稳定下载链接（302 重定向到最新版 APK） */
const OFFICIAL_STABLE_URL = "https://ak.hypergryph.com/downloads/android_lastest";
/** gryph-links 跟踪链接（GitHub raw，返回单行最新直链） */
const TRACKING_URL = "https://raw.githubusercontent.com/SkyBird233/gryph-links/main/links/arknights";
/** 官方版本 API（clientVersion 等） */
const VERSION_URL = "https://ak-conf.hypergryph.com/config/prod/official/Android/version";

/** web ReadableStream → 管道写入（Node 24 fetch body 转写文件） */
async function pipelineStream(body: ReadableStream<Uint8Array>, dest: fs.WriteStream): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    Readable.fromWeb(body as unknown as import("stream/web").ReadableStream<Uint8Array>)
      .on("error", reject)
      .pipe(dest)
      .on("error", reject)
      .on("finish", resolve);
  });
}

/** Lua 资产名特征（任意前缀，兼容 Windows 带 gamedata/[uc]lua/ 前缀与 Android 裸文件名） */
const LUA_ASSET_RE = /\.lua$/i;
/** UnityFS bundle 魔数（7 字节签名 "UnityFS"） */
const UNITYFS_MAGIC = Buffer.from("UnityFS");
/** APK 内 Unity bundle 候选扩展名 */
const CANDIDATE_EXTS = new Set([".bin", ".dat", ".bundle", ".unity3d", ".bytes", ".ab", ".asset"]);
/** 判定 Lua 主 bundle 的锚点资产（按优先级） */
const LUA_ANCHORS = ["entry.lua", "definedfix.lua", "base/basemodule.lua"];

const ROOT = path.join(__dirname, "..");
/** APK 下载目录（按版本隔离，复用缓存） */
const APK_DIR = path.join(ROOT, "tmp", "apk");
/** 工作目录：落盘的 Lua bundle 副本 */
const WORK_DIR = path.join(ROOT, "tmp", "apk-work");
/** 明文 Lua 参考目录（extract-lua-bundle 的默认输出；Windows 版参考，勿覆盖） */
const REF_LUA_DIR = path.join(
  ROOT,
  "reference",
  "ArknightsGameData",
  "zh_CN",
  "gamedata",
  "[uc]lua",
);
/** Android 明文 Lua 提取目录（平台隔离，避免与 Windows 参考混写/覆盖） */
function androidLuaPlainDir(verDir: string): string {
  return path.join(WORK_DIR, verDir, "lua-plain");
}
/** Lua 插件源码目录（repack 合并） */
const PLUGIN_DIR = path.join(ROOT, "lua", "plugin");
/** 默认 mods 输出目录 */
const DEFAULT_MODS_DIR = path.join(ROOT, "mods");

/** 解包定位结果 */
interface LuaBundleFound {
  /** APK 内条目完整路径（如 assets/bin/Data/anon/xxx.bin） */
  entryPath: string;
  /** 推断的客户端资源名（zip 条目名，如 anon/xxx.bin） */
  resourceName: string;
  /** bundle 字节 */
  bytes: Uint8Array;
  /** 承载的 Lua 资产名列表 */
  luaAssets: string[];
}

interface CliArgs {
  apk: string;
  force: boolean;
  extractOnly: boolean;
  repackOnly: string;
  noExtract: boolean;
  bundleName: string;
  out: string;
}

/** 解析 CLI 参数 */
function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    apk: "",
    force: false,
    extractOnly: false,
    repackOnly: "",
    noExtract: false,
    bundleName: "",
    out: DEFAULT_MODS_DIR,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--apk") args.apk = argv[++i] ?? "";
    else if (a === "--force") args.force = true;
    else if (a === "--extract-only") args.extractOnly = true;
    else if (a === "--repack-only") args.repackOnly = argv[++i] ?? "";
    else if (a === "--no-extract") args.noExtract = true;
    else if (a === "--bundle-name") args.bundleName = argv[++i] ?? "";
    else if (a === "--out") args.out = argv[++i] ?? "";
    else if (a === "--help" || a === "-h") {
      console.log(
        "用法: pnpm run apk:lua [--apk <路径|URL>] [--force] [--extract-only] [--repack-only <bundle.bin>]\n" +
          "            [--bundle-name <客户端资源名>] [--no-extract] [--out <mods目录>]",
      );
      process.exit(0);
    }
  }
  return args;
}

/** 尝试获取官方最新 clientVersion（失败不阻断，返回空串） */
async function getClientVersion(): Promise<string> {
  try {
    const res = await fetch(VERSION_URL);
    if (!res.ok) return "";
    const data = (await res.json()) as { clientVersion?: string };
    return data.clientVersion ?? "";
  } catch {
    return "";
  }
}

/**
 * 获取最新 APK 直链：官方稳定链接（302 跟随）优先，gryph-links 跟踪链接回退。
 * @returns APK 直链 URL
 */
async function resolveApkUrl(): Promise<string> {
  // 1. 官方稳定链接：redirect: "follow" 后 res.url 即最终直链
  try {
    const res = await fetch(OFFICIAL_STABLE_URL, {
      redirect: "follow",
      headers: { "User-Agent": "Mozilla/5.0 (Linux; Android 13)" },
    });
    if (res.ok && /\.apk($|\?)/i.test(res.url)) {
      console.log(`[apk-lua] 官方稳定链接解析成功: ${res.url}`);
      return res.url;
    }
    console.warn("[apk-lua] 官方稳定链接未返回 APK 直链，回退 gryph-links…");
  } catch (e) {
    console.warn(`[apk-lua] 官方稳定链接不可用（${(e as Error).message}），回退 gryph-links…`);
  }
  // 2. gryph-links 跟踪链接（GitHub raw 单行直链）
  const res = await fetch(TRACKING_URL);
  if (!res.ok) {
    throw new Error(
      `APK 直链解析失败：官方与 gryph-links 均不可用（HTTP ${res.status}）。` +
        "请手动下载最新版官服 APK 并用 --apk <路径> 传入。",
    );
  }
  const url = (await res.text()).trim().split(/\s+/)[0];
  if (!/^https?:\/\//.test(url)) {
    throw new Error(`gryph-links 返回内容异常: ${url}`);
  }
  console.log(`[apk-lua] gryph-links 直链解析成功: ${url}`);
  return url;
}

/**
 * 下载 APK 到目标路径（流式写盘）。已存在且非 --force 时复用（按大小粗判完整）。
 * @param url   - APK 直链
 * @param dest  - 目标路径
 * @param force - 强制重下
 * @returns 是否发生了实际下载（false = 复用缓存）
 */
async function downloadApk(url: string, dest: string, force: boolean): Promise<boolean> {
  if (!force && fs.existsSync(dest) && fs.statSync(dest).size > 50 * 1024 * 1024) {
    console.log(`[apk-lua] 复用已下载 APK: ${dest}（${fs.statSync(dest).size} B）`);
    return false;
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  console.log(`[apk-lua] 下载 APK: ${url}`);
  const res = await fetch(url, {
    redirect: "follow",
    headers: { "User-Agent": "Mozilla/5.0 (Linux; Android 13)" },
  });
  if (!res.ok || !res.body) {
    throw new Error(`APK 下载失败：HTTP ${res.status} @ ${url}`);
  }
  const total = Number(res.headers.get("content-length") ?? 0);
  await pipelineStream(res.body, fs.createWriteStream(dest));
  const size = fs.statSync(dest).size;
  if (size < 50 * 1024 * 1024) {
    throw new Error(`APK 下载不完整（${size} B），疑似被拦截或重定向到非 APK 内容`);
  }
  // 校验 zip 魔数（APK 本质是 zip）
  const fd = fs.openSync(dest, "r");
  const head = Buffer.alloc(4);
  fs.readSync(fd, head, 0, 4, 0);
  fs.closeSync(fd);
  if (head[0] !== 0x50 || head[1] !== 0x4b) {
    throw new Error(`APK 文件头非法（${head.toString("hex")}），不是有效 zip`);
  }
  console.log(`[apk-lua] 下载完成: ${dest}（${size} B${total ? ` / 预期 ${total} B` : ""}）`);
  return true;
}

/**
 * 用 yauzl 遍历 APK（zip），定位承载内置 Lua 资产的 UnityFS bundle。
 * 策略：按扩展名过滤候选 → 读前 6 字节验证 UnityFS 魔数（非命中立即终止流）→
 * 对命中条目完整解包确认 Lua 资产；命中多个时按锚点资产
 * （entry.lua / definedfix.lua / base/basemodule.lua）优先级选主 bundle。
 * @param apkPath - APK 路径
 * @returns 命中的 Lua bundle 信息
 */
export function findLuaBundleInApk(apkPath: string): Promise<LuaBundleFound> {
  return new Promise((resolve, reject) => {
    const candidates: { entryPath: string; bytes: Uint8Array; luaAssets: string[] }[] = [];
    const unityFsNames: string[] = [];

    yauzl.open(apkPath, { lazyEntries: true, autoClose: true }, (err, zf) => {
      if (err || !zf) {
        reject(new Error(`APK 打开失败: ${(err as Error).message}`));
        return;
      }

      zf.readEntry();
      zf.on("entry", (entry: yauzl.Entry) => {
        // 跳过目录
        if (/\/$/.test(entry.fileName)) {
          zf.readEntry();
          return;
        }
        const ext = path.extname(entry.fileName).toLowerCase();
        if (!CANDIDATE_EXTS.has(ext)) {
          zf.readEntry();
          return;
        }
        // 读首个 chunk 判断 UnityFS 魔数：命中则继续收集完整内容并确认 Lua 资产；
        // 未命中立即终止流（大文件只读一个 chunk）。finish() 保证 readEntry 只推进一次。
        zf.openReadStream(entry, (openErr, rs) => {
          if (openErr || !rs) {
            zf.readEntry();
            return;
          }
          let handled = false;
          const finish = (): void => {
            if (!handled) {
              handled = true;
              zf.readEntry();
            }
          };
          rs.once("data", (chunk: Buffer) => {
            if (chunk.length >= UNITYFS_MAGIC.length && chunk.subarray(0, UNITYFS_MAGIC.length).equals(UNITYFS_MAGIC)) {
              unityFsNames.push(entry.fileName);
              const chunks: Buffer[] = [chunk];
              rs.on("data", (c: Buffer) => chunks.push(c));
              rs.on("end", () => {
                try {
                  const assets = extractTextAssets(new Uint8Array(Buffer.concat(chunks)));
                  const luaAssets = assets
                    .map((a) => a.name)
                    .filter((n) => LUA_ASSET_RE.test(n));
                  if (luaAssets.length > 0) {
                    candidates.push({ entryPath: entry.fileName, bytes: new Uint8Array(Buffer.concat(chunks)), luaAssets });
                    console.log(
                      `[apk-lua] 候选 bundle: ${entry.fileName}（${luaAssets.length} 条 Lua，${chunks.reduce((n, c) => n + c.length, 0)} B）`,
                    );
                  }
                } catch {
                  // 解包失败：非目标 bundle，忽略
                }
                finish();
              });
            } else {
              rs.destroy(); // 非 UnityFS，终止流（close 触发 finish）
            }
          });
          rs.on("error", finish);
          rs.on("close", finish);
        });
      });
      zf.on("end", () => {
        if (candidates.length === 0) {
          reject(
            new Error(
              `APK 中未找到承载内置 Lua 的 UnityFS bundle（UnityFS 候选 ${unityFsNames.length} 个，均无 gamedata/[uc]lua 资产）。` +
                "版本结构可能变化，请检查 APK 内容或联系维护。",
            ),
          );
          return;
        }
        // 锚点优先级选择主 bundle
        const scored = candidates.map((c) => {
          const lower = c.luaAssets.map((n) => n.toLowerCase());
          const score = LUA_ANCHORS.reduce((acc, anchor, i) => {
            return lower.some((n) => n.endsWith(anchor)) ? acc + (LUA_ANCHORS.length - i) : acc;
          }, 0);
          return { ...c, score };
        });
        scored.sort((a, b) => b.score - a.score || b.luaAssets.length - a.luaAssets.length);
        const best = scored[0];
        resolve({
          entryPath: best.entryPath,
          resourceName: inferResourceName(best.entryPath),
          bytes: best.bytes,
          luaAssets: best.luaAssets,
        });
      });
      zf.on("error", (e) => reject(new Error(`APK 扫描失败: ${e.message}`)));
    });
  });
}

/**
 * 由 APK 内条目路径推断客户端资源名（zip 条目名 = 客户端请求名）：
 *   assets/bin/Data/anon/xxx.bin → anon/xxx.bin（取 anon/ 起）
 *   assets/xxx.bin               → xxx.bin（去掉 assets/ 前缀）
 *   anon/xxx.bin                 → 原样
 * @param entryPath - APK 内完整条目路径
 * @returns 客户端资源名
 */
export function inferResourceName(entryPath: string): string {
  const normalized = entryPath.split("\\").join("/");
  const anonIdx = normalized.indexOf("/anon/");
  if (anonIdx >= 0) return normalized.slice(anonIdx + 1);
  if (normalized.startsWith("assets/")) return normalized.slice("assets/".length);
  // 无 assets/ 前缀 → 已相对路径，视为客户端资源名原样返回
  return normalized;
}

/** 生成目标文件名：arknights-hg-<版本>.apk 或基于 URL 回退 */
function apkFileNameFromUrl(url: string, clientVersion: string): string {
  const fromUrl = url.split("?")[0].split("/").pop() ?? "";
  if (/\.apk$/i.test(fromUrl)) return fromUrl;
  return clientVersion ? `arknights-${clientVersion}.apk` : "arknights-latest.apk";
}

/** 汇总打印 */
function printSummary(info: {
  clientVersion: string;
  apkPath: string;
  resourceName: string;
  bundleBytes: number;
  luaCount: number;
  refDir: string;
  modDat: string;
}): void {
  console.log("\n=================== 工作流完成 ===================");
  console.log(`  客户端版本:  ${info.clientVersion || "未知"}`);
  console.log(`  APK:         ${info.apkPath}`);
  console.log(`  Lua bundle:  ${info.resourceName}（${info.bundleBytes} B，${info.luaCount} 条 Lua）`);
  console.log(`  明文参考:    ${info.refDir}`);
  console.log(`  注入 mod:    ${info.modDat}`);
  console.log("==================================================");
  console.log("下一步：重启服务（或等待 assets.refreshModsIfChanged 检测），");
  console.log("客户端下次拉取热更清单即下载覆盖内置 Lua bundle，插件随启动加载。");
}

/** CLI 入口 */
async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  // ---------- 模式 3：--repack-only（已有 bundle 文件，只做注入） ----------
  if (args.repackOnly) {
    const binPath = path.resolve(args.repackOnly);
    if (!fs.existsSync(binPath)) {
      console.error(`[apk-lua] bundle 文件不存在: ${binPath}`);
      process.exit(1);
    }
    const resourceName = args.bundleName || inferResourceName(path.resolve(binPath));
    if (!args.bundleName && !resourceName.includes("/")) {
      console.warn(`[apk-lua] 提示: 未提供 --bundle-name，资源名推断为 "${resourceName}"；` +
        "若客户端请求名不同（如 anon/xxx.bin），请用 --bundle-name 显式指定。");
    }
    console.log(`[apk-lua] repack-only: ${binPath} → ${resourceName}`);
    const result = await repackBuiltinLua(binPath, PLUGIN_DIR, args.out, resourceName);
    console.log(`[apk-lua] 已注入引导 mod: ${result.dat}（${result.assetCount} 条 Lua）`);
    return;
  }

  // ---------- 模式 1/2：下载（或本地 APK）→ 解包 → 提取 → 注入 ----------
  const clientVersion = await getClientVersion();
  if (clientVersion) console.log(`[apk-lua] 官方最新客户端版本: ${clientVersion}`);

  // 1. 获取 APK
  let apkPath = "";
  if (args.apk) {
    if (/^https?:\/\//.test(args.apk)) {
      const dest = path.join(APK_DIR, clientVersion || "latest", apkFileNameFromUrl(args.apk, clientVersion));
      await downloadApk(args.apk, dest, args.force);
      apkPath = dest;
    } else {
      apkPath = path.resolve(args.apk);
      if (!fs.existsSync(apkPath)) {
        console.error(`[apk-lua] APK 文件不存在: ${apkPath}`);
        process.exit(1);
      }
      console.log(`[apk-lua] 使用本地 APK: ${apkPath}`);
    }
  } else {
    const url = await resolveApkUrl();
    const dest = path.join(APK_DIR, clientVersion || "latest", apkFileNameFromUrl(url, clientVersion));
    await downloadApk(url, dest, args.force);
    apkPath = dest;
  }

  // 2. 解包扫描定位 Lua bundle
  const found = await findLuaBundleInApk(apkPath);
  const resourceName = args.bundleName || found.resourceName;
  console.log(
    `[apk-lua] 定位内置 Lua bundle: ${found.entryPath}\n` +
      `[apk-lua] 客户端资源名: ${resourceName}（--bundle-name 可覆盖）`,
  );

  // 3. 落盘 bundle 副本到工作目录
  const verDir = clientVersion || "latest";
  const binBase = resourceName.split("/").pop() ?? "builtin-lua.bin";
  const binPath = path.join(WORK_DIR, verDir, binBase);
  fs.mkdirSync(path.dirname(binPath), { recursive: true });
  fs.writeFileSync(binPath, Buffer.from(found.bytes));
  console.log(`[apk-lua] bundle 副本: ${binPath}`);

  // 4. 提取明文 Lua（--no-extract 跳过；--extract-only 也提取但不注入）。
  //    输出到平台隔离目录（Android 与 Windows 参考分离，避免同名覆盖）。
  const plainDir = androidLuaPlainDir(verDir);
  let refDir = plainDir;
  if (!args.noExtract) {
    const ext = await extractLuaBundle(binPath, plainDir);
    console.log(
      `[apk-lua] 明文提取: ${ext.written} 条写入 ${plainDir}（跳过 ${ext.skipped} 条非 Lua/插件资产）`,
    );
  } else {
    refDir = "(跳过提取)";
  }

  // 5. 注入 Lua 引导（--extract-only 时跳过）
  let modDat = "";
  if (!args.extractOnly) {
    const result = await repackBuiltinLua(binPath, PLUGIN_DIR, args.out, resourceName);
    modDat = result.dat;
    console.log(`[apk-lua] 注入完成: ${modDat}（${result.assetCount} 条 Lua）`);
  }

  // 6. 启用 assets.enableMods
  if (!args.extractOnly) {
    const configPath = path.join(ROOT, "data", "config.json");
    const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    if (!config.assets?.enableMods) {
      config.assets = config.assets || {};
      config.assets.enableMods = true;
      config.assets.downloadLocally = true;
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
      console.log("[apk-lua] 已启用 assets.enableMods（data/config.json）");
    } else {
      console.log("[apk-lua] assets.enableMods 已启用");
    }
  }

  printSummary({
    clientVersion,
    apkPath,
    resourceName,
    bundleBytes: found.bytes.length,
    luaCount: found.luaAssets.length,
    refDir,
    modDat,
  });
}

if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error("[apk-lua] 工作流失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
