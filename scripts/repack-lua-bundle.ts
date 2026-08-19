/**
 * 内置 Lua bundle 重打包器（方案 A）
 *
 * 目标：把客户端内置 Lua 主 bundle（anon/7d91430e114d86fef7d3b3511151e12d.bin）重打包，
 * 将 lua/plugin/ 插件脚本 merge 进去，并在 DefinedFix.lua 中逐条注入各插件 hotfixer 条目
 * （Plugin/<X>，经游戏原生 HotfixProcesser.Do 管线 new() + Init() 驱动加载），
 * 最后覆盖下发为 mods/anon_7d91430e114d86fef7d3b3511151e12d.dat，客户端热更即加载插件。
 *
 * 输入：内置 bundle（.bin UnityFS 或 .dat zip 单条目）。
 *   - 从已装客户端提取内置 bundle（ArkUnpacker 解包后定位 anon/7d91430e114d86fef7d3b3511151e12d.bin）。
 *   - 或直接给出该 bundle 的 .dat/.bin 路径。
 *
 * 用法：
 *   pnpm run repack:lua -- --bundle <内置bundle.dat|.bin>
 *   --bundle  必填，内置 Lua bundle 路径
 *   --from-ref 从官方明文 Lua 参考目录重建（需先 pnpm run extract:lua 生成本地参考）
 *   --platform <windows|android>  输出到 mods/<platform>/ 平台专属目录（缺省输出到 mods/ 根，
 *              Windows/Android 同时生效；不同平台 base 内置 bundle 可能不同，建议指定平台）
 *   --out     输出 mods 目录（缺省 <项目根>/mods）
 *   --official 按官方热更语义命名：bundle 名 = anon/<内容md5>.bin（内容变 → 名变 → 客户端
 *              重新下载），dat 名 anon_<md5>.dat；对齐官方 hot_update_list 的 lua bundle
 *              重建替换方式（如 8.17 更新 5c28e218→6edf14bb），替代旧的「覆盖内置同名 bundle」
 *              模式（固定 7d91430e）。缺省保持旧行为（--bundle-name 覆盖内置名）。
 */
import * as fs from "fs";
import * as path from "path";
import { createHash } from "crypto";
import JSZip from "jszip";
import { packLuaBundle, type LuaAsset } from "./pack-lua-bundle";
import { extractTextAssets } from "./vendor/unityfs";
import { decryptLuaScript, encryptLuaScript, isLuaEncrypted } from "./vendor/lua-crypt";

/** 内置 Lua 主 bundle 名（zip 条目名 = 客户端资源名） */
const BUILTIN_BUNDLE_NAME = "anon/7d91430e114d86fef7d3b3511151e12d.bin";

/**
 * 由 bundle 名推导 mod 下载名（客户端资源名 → .dat 文件名）：
 * 目录分隔符 / → _、# → __、扩展名 → .dat，与 app/asset.ts loadMods 的 downloadName 语义一致。
 * @param bundleName - 客户端资源名（如 anon/xxx.bin）
 * @returns 对应 .dat 文件名（如 anon_xxx.dat）
 */
export function bundleToModName(bundleName: string): string {
  return bundleName.replace(/\//g, "_").replace(/#/g, "__").replace(/\.[^.]*$/, "") + ".dat";
}
/**
 * zip 条目固定时间戳：保证插件内容不变时重打包产物字节一致（md5 稳定，
 * 客户端不会因每次启动自动重建而重复全量下载）。
 */
const LUA_ZIP_DATE = new Date("2024-01-01T00:00:00.000Z");
/** 插件源码根目录 */
const PLUGIN_DIR = path.join(__dirname, "..", "lua", "plugin");
/** 插件资产名前缀（大写 Plugin 与 patch 进 DefinedFix 的 require 路径 "Plugin/…" 严格一致） */
const PLUGIN_ASSET_PREFIX = "gamedata/[uc]lua/Plugin/";
/** 官方明文 Lua 参考目录（内置 bundle 的明文源） */
const REF_LUA_DIR = path.join(
  __dirname,
  "..",
  "reference",
  "ArknightsGameData",
  "zh_CN",
  "gamedata",
  "[uc]lua",
);

/**
 * 读取内置 bundle 字节：.dat 解 zip（优先匹配内置 bundle 名条目，否则取首条目），.bin 直读。
 * @param input - 内置 bundle 路径（.dat 或 .bin）
 * @returns UnityFS bundle 字节
 */
async function readBuiltinBundle(input: string): Promise<Uint8Array> {
  const ext = path.extname(input).toLowerCase();
  if (ext !== ".dat") {
    return new Uint8Array(fs.readFileSync(input));
  }
  const zipData = fs.readFileSync(input);
  const zip = await JSZip.loadAsync(zipData);
  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  if (names.length === 0) {
    throw new Error(`内置 bundle .dat 内无条目: ${input}`);
  }
  const preferred = names.find((n) => n === BUILTIN_BUNDLE_NAME);
  const entry = zip.files[preferred ?? names[0]];
  const bytes = await entry.async("uint8array");
  return new Uint8Array(bytes);
}

/**
 * 资产命名风格：内置资产名是否带 gamedata/[uc]lua/ 前缀（Windows 版）或裸文件名（Android 版）。
 * 插件资产必须与内置风格一致，否则客户端 require 归一化后找不到资产。
 * @param builtin - 内置 Lua 资产列表
 * @returns "prefixed"（gamedata/[uc]lua/ 前缀）或 "bare"（裸文件名）
 */
export function detectAssetStyle(builtin: LuaAsset[]): "prefixed" | "bare" {
  const anyLua = builtin.find((a) => /\.lua$/i.test(a.name));
  if (anyLua && /^gamedata\/\[uc\]lua\//i.test(anyLua.name)) return "prefixed";
  return "bare";
}

/**
 * 递归收集 lua/plugin/ 下所有 .lua 为插件资产。
 * 命名风格与内置资产一致：prefixed → gamedata/[uc]lua/Plugin/<rel>（Windows）；
 * bare → 裸文件名（Android，客户端 require 归一化为 basename 匹配）。
 * @param dir   - 插件源码目录
 * @param style - 命名风格
 * @returns 插件 Lua 资产列表（按名排序）
 */
function collectPluginAssets(dir: string, style: "prefixed" | "bare"): LuaAsset[] {
  const out: LuaAsset[] = [];
  const walk = (cur: string): void => {
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith(".lua")) {
        const rel = path.relative(dir, full).split(path.sep).join("/");
        out.push({
          name: style === "prefixed" ? PLUGIN_ASSET_PREFIX + rel : rel,
          script: fs.readFileSync(full),
        });
      }
    }
  };
  walk(dir);
  out.sort((a, b) => (a.name < b.name ? -1 : 1));
  return out;
}

/** 判断资产名是否为插件资产（按当前命名风格，大小写不敏感） */
function isPluginAssetName(name: string, style: "prefixed" | "bare"): boolean {
  if (style === "prefixed") {
    return name.toLowerCase().startsWith(PLUGIN_ASSET_PREFIX.toLowerCase());
  }
  // bare：官方内置资产名不含 "/"（扁平裸名）——插件资产（含 "/"）需剔除
  return name.includes("/");
}

/**
 * 从官方明文 Lua 参考目录重建内置 bundle 的资产列表。
 * asset 名统一小写（对齐 resource_manifest_idx 约定：gamedata/[uc]lua/entry.lua 等）。
 * @param refDir - 官方明文 Lua 目录（[uc]lua）
 * @returns Lua 资产列表（按名排序）
 */
export function collectReferenceLua(refDir: string): LuaAsset[] {
  const out: LuaAsset[] = [];
  const walk = (cur: string): void => {
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith(".lua")) {
        const rel = path.relative(refDir, full).split(path.sep).join("/").toLowerCase();
        out.push({ name: "gamedata/[uc]lua/" + rel, script: fs.readFileSync(full) });
      }
    }
  };
  if (!fs.existsSync(refDir)) {
    throw new Error(`明文 Lua 参考目录不存在: ${refDir}`);
  }
  walk(refDir);
  out.sort((a, b) => (a.name < b.name ? -1 : 1));
  return out;
}

/**
 * 插件 hotfixer 清单（DefinedFix 注入条目，顺序 = 加载顺序）。
 * 引导类 network_redirect 必须最先（早于网络初始化前生效）；其余与
 * lua/plugin/PluginDefs.lua 保持一致。
 */
const PLUGIN_HOTFIXER_ENTRIES: string[] = [
  "Plugin/NetworkRedirectPlugin",
  "Plugin/EnemyHpPlugin",
  "Plugin/EnemyInfoPlugin",
  "Plugin/BattleAssistPlugin",
  "Plugin/PanelPlugin",
];

/**
 * 在 DefinedFix.lua 清单中注入各插件 hotfixer 条目（对齐官服：每个插件独立登记一条）。
 * 幂等：先剔除已注入的插件条目（避免对已重打包 bundle 二次注入），再按
 * 大小写不敏感锚点（"HotFixes/..." 或 "Hotfixes/..."）批量插入清单最前。
 * 使用游戏原生 hotfix 管线（HotfixProcesser.Do）逐条实例化各插件，比 patch entry.lua 更稳。
 * @param script  - 原始 DefinedFix.lua 文本
 * @param entries - 插件 hotfixer 条目（缺省用 PLUGIN_HOTFIXER_ENTRIES）
 * @returns 补丁后的 DefinedFix.lua 文本
 */
export function patchDefinedFix(script: string, entries: string[] = PLUGIN_HOTFIXER_ENTRIES): string {
  // 剔除已注入的插件条目（独立行精确匹配，避免误删内容中的同名引用）
  const stripped = script
    .split(/\r?\n/)
    .filter((line) => {
      const t = line.trim();
      return !entries.some((e) => t === `"${e}",` || t === `"${e}"`);
    })
    .join("\n");
  const markerRe = /["']\s*[Hh]ot[Ff]ixes?\//;
  const m = markerRe.exec(stripped);
  if (!m) {
    throw new Error("DefinedFix 补丁失败：未找到 hotfixer 条目（版本漂移？）");
  }
  const idx = m.index;
  // 在首个条目前插入全部插件条目（每行一条、带逗号；引导类 network_redirect 须在前）
  const block = entries.map((e) => `  "${e}",`).join("\n");
  return stripped.slice(0, idx) + block + "\n" + stripped.slice(idx);
}

/**
 * 合并内置 Lua 资产与插件资产，并 patch DefinedFix 以引导插件加载。
 * 自动适配两种平台格式：
 *   - Windows（明文，gamedata/[uc]lua/ 前缀）：保持现有行为；
 *   - Android（CRYPTIC_A 加密，裸文件名）：内置资产先解密 → 合并明文插件 →
 *     patch DefinedFix → 全部重新加密（客户端加载时自行解密）。
 * 内置 bundle 中已存在的插件资产会被剔除——构建期由 lua/plugin/ 重新合并，
 * 避免对已重打包 bundle 二次处理产生重名 TextAsset。
 * @param builtin - 内置 bundle 的全部 Lua 资产（可能加密）
 * @param pluginDir - 插件源码目录
 * @param forceEncrypt - 强制输出 CRYPTIC_A 加密（--from-ref 输入为明文，但 Android
 *                       客户端 PRODUCTION 模式按 cryptType 解密加载，明文资产会解密失败）
 * @returns 合并后的资产列表（含补丁后的 DefinedFix；格式与内置一致）
 */
export function mergeAndPatch(builtin: LuaAsset[], pluginDir: string, forceEncrypt: boolean = false): LuaAsset[] {
  // 输入是否加密（决定是否先解密）；输出是否加密（forceEncrypt 或输入加密——Android 客户端
  // PRODUCTION 模式按 cryptType 解密加载，--from-ref 明文输入也必须加密输出）
  const isEncInput = builtin.some((a) => /definedfix\.lua$/i.test(a.name) && isLuaEncrypted(a.script));
  const needEncrypt = forceEncrypt || isEncInput;
  // 1. 解密内置资产（仅输入为加密格式时）
  const decrypted: LuaAsset[] = isEncInput
    ? builtin.map((a) => ({ ...a, script: decryptLuaScript(a.script) }))
    : builtin.map((a) => ({ ...a }));
  // 2. 资产命名风格
  const style = detectAssetStyle(decrypted);
  const plugins = collectPluginAssets(pluginDir, style);
  // 3. 剔除内置资产中的插件资产（大小写不敏感，兼容 --from-ref 全小写命名）
  const builtinOnly = decrypted.filter((a) => !isPluginAssetName(a.name, style));
  const merged = builtinOnly.map((a) => ({ ...a }));
  let patched = false;
  for (const a of merged) {
    if (a.name.toLowerCase().endsWith("definedfix.lua")) {
      a.script = Buffer.from(patchDefinedFix(new TextDecoder().decode(a.script)), "utf8");
      patched = true;
      break;
    }
  }
  if (!patched) {
    throw new Error("内置 bundle 中未找到 DefinedFix.lua，无法引导插件");
  }
  const combined = [...plugins, ...merged];
  // 4. 重新加密（输入为加密格式或 forceEncrypt 时；插件资产同样加密，客户端统一解密）
  if (needEncrypt) {
    return combined.map((a) => ({ ...a, script: encryptLuaScript(a.script) }));
  }
  return combined;
}

/**
 * 重打包内置 Lua bundle 并输出覆盖 mod（.dat）。
 * @param builtinPath - 内置 bundle 路径（.dat 或 .bin）
 * @param pluginDir   - 插件源码目录
 * @param outModsDir  - 输出 mods 目录
 * @param bundleName  - 客户端资源名（zip 条目名；缺省用内置 Lua 主 bundle 名）
 * @param hashName    - 官方热更语义命名：bundle 名 = anon/<内容md5>.bin（覆盖 bundleName）
 * @returns 结果（dat 路径、bundle 字节、资产总数）
 */
export async function repackBuiltinLua(
  builtinPath: string,
  pluginDir: string,
  outModsDir: string,
  bundleName: string = BUILTIN_BUNDLE_NAME,
  hashName: boolean = false,
): Promise<{ dat: string; bundle: Uint8Array; assetCount: number }> {
  const builtinBytes = await readBuiltinBundle(builtinPath);
  const builtin = extractTextAssets(builtinBytes);
  if (builtin.length === 0) {
    throw new Error(`内置 bundle 未解析出任何 Lua 资产: ${builtinPath}`);
  }
  const merged = mergeAndPatch(builtin, pluginDir);
  return writeModDat(merged, outModsDir, bundleName, hashName);
}

/**
 * 从官方明文 Lua 参考目录重建内置 bundle（含插件 + DefinedFix 补丁）并输出覆盖 mod。
 * 免去提取客户端二进制的步骤：明文参考目录即内置 bundle 的源码。
 * @param refDir    - 官方明文 Lua 目录（[uc]lua）
 * @param pluginDir - 插件源码目录
 * @param outModsDir- 输出 mods 目录
 * @param bundleName - 客户端资源名（zip 条目名；缺省用内置 Lua 主 bundle 名）
 * @param encrypt   - 输出 Android CRYPTIC_A 加密格式（资产名裸名，参考目录须为平铺明文）
 * @param hashName  - 官方热更语义命名：bundle 名 = anon/<内容md5>.bin（覆盖 bundleName）
 * @returns 结果（dat 路径、bundle 字节、资产总数）
 */
export async function repackBuiltinFromRef(
  refDir: string,
  pluginDir: string,
  outModsDir: string,
  bundleName: string = BUILTIN_BUNDLE_NAME,
  encrypt: boolean = false,
  hashName: boolean = false,
): Promise<{ dat: string; bundle: Uint8Array; assetCount: number }> {
  const builtin = encrypt
    ? collectReferenceLuaBare(refDir)
    : collectReferenceLua(refDir);
  const merged = mergeAndPatch(builtin, pluginDir, encrypt);
  return writeModDat(merged, outModsDir, bundleName, hashName);
}

/**
 * 从明文 Lua 参考目录收集资产，资产名用裸文件名（Android 平铺布局，对应加密格式）。
 * @param refDir - 官方明文 Lua 目录（[uc]lua，平铺或带子目录均可，子目录剥除）
 * @returns Lua 资产列表（按名排序）
 */
function collectReferenceLuaBare(refDir: string): LuaAsset[] {
  const out: LuaAsset[] = [];
  const walk = (cur: string): void => {
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith(".lua")) {
        out.push({ name: entry.name, script: fs.readFileSync(full) });
      }
    }
  };
  if (!fs.existsSync(refDir)) {
    throw new Error(`明文 Lua 参考目录不存在: ${refDir}`);
  }
  walk(refDir);
  out.sort((a, b) => (a.name < b.name ? -1 : 1));
  return out;
}

/**
 * 将合并后的资产列表打包为 UnityFS bundle 并写为覆盖 mod（.dat）。
 * @param merged   - 合并后的资产列表
 * @param outModsDir - 输出 mods 目录
 * @param bundleName - 客户端资源名（zip 条目名；缺省用内置 Lua 主 bundle 名）
 * @param hashName  - 官方热更语义命名：zip 条目名 = anon/<内容md5>.bin，
 *                    dat 文件名 = anon_<内容md5>.dat（内容变 → 名变 → 客户端重新下载；
 *                    内容不变 → 名不变，幂等）。对齐官方 hot_update_list 的 lua bundle
 *                    重建替换方式（8.17 更新 5c28e218→6edf14bb 即此语义）。
 * @returns 结果（dat 路径、bundle 字节、资产总数）
 */
async function writeModDat(
  merged: LuaAsset[],
  outModsDir: string,
  bundleName: string = BUILTIN_BUNDLE_NAME,
  hashName: boolean = false,
): Promise<{ dat: string; bundle: Uint8Array; assetCount: number }> {
  const uf = packLuaBundle(merged);
  let entryName = bundleName;
  if (hashName) {
    // 内容 hash 命名：确定性（LUA_ZIP_DATE 固定时间戳 → 同内容同字节 → 同名）
    const md5 = createHash("md5").update(uf).digest("hex");
    entryName = `anon/${md5}.bin`;
  }
  const zip = new JSZip();
  zip.file(entryName, Buffer.from(uf), { createFolders: false, date: LUA_ZIP_DATE });
  const dat = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });

  fs.mkdirSync(outModsDir, { recursive: true });
  const datPath = path.join(outModsDir, bundleToModName(entryName));
  fs.writeFileSync(datPath, Buffer.from(dat));
  return { dat: datPath, bundle: uf, assetCount: merged.length };
}

/** CLI 入口 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const bundleIdx = args.indexOf("--bundle");
  const refIdx = args.indexOf("--from-ref");
  const outIdx = args.indexOf("--out");
  const platformIdx = args.indexOf("--platform");
  const bundleNameIdx = args.indexOf("--bundle-name");
  const encryptIdx = args.indexOf("--encrypt");
  const officialIdx = args.indexOf("--official");
  const builtinPath = bundleIdx >= 0 ? args[bundleIdx + 1] : "";
  const bundleName = bundleNameIdx >= 0 ? args[bundleNameIdx + 1] : BUILTIN_BUNDLE_NAME;
  const encrypt = encryptIdx >= 0;
  const hashName = officialIdx >= 0;
  const fromRef = refIdx >= 0;
  const platform = platformIdx >= 0 ? (args[platformIdx + 1] ?? "").toLowerCase() : "";
  let outModsDir = outIdx >= 0 ? args[outIdx + 1] : path.join(__dirname, "..", "mods");
  if (outIdx < 0 && (platform === "windows" || platform === "android")) {
    // 平台专属目录（mods/windows|android），避免单份 repack 同时下发两平台
    outModsDir = path.join(outModsDir, platform);
  }

  let result;
  if (fromRef) {
    console.log(`从官方明文 Lua 参考目录重建内置 bundle…${encrypt ? "（Android 加密格式）" : ""}${hashName ? "（官方 hash 命名）" : ""}`);
    result = await repackBuiltinFromRef(REF_LUA_DIR, PLUGIN_DIR, outModsDir, bundleName, encrypt, hashName);
  } else if (builtinPath) {
    result = await repackBuiltinLua(builtinPath, PLUGIN_DIR, outModsDir, bundleName, hashName);
  } else {
    console.error(
      "用法: pnpm run repack:lua -- --from-ref [--encrypt] [--official] [--bundle-name <客户端资源名>] [--platform <windows|android>] [--out <mods目录>]\n" +
        "  或: pnpm run repack:lua -- --bundle <内置bundle.dat|.bin> [--official] [--bundle-name <客户端资源名>] [--platform <windows|android>] [--out <mods目录>]",
    );
    process.exit(1);
  }
  console.log(`已覆盖内置 Lua bundle mod: ${result.dat}`);
  console.log(`  bundle: ${bundleName} (${result.bundle.length} B, ${result.assetCount} 条 Lua)`);

  // 启用 assets.enableMods
  const configPath = path.join(__dirname, "..", "data", "config.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
  if (!config.assets?.enableMods) {
    config.assets = config.assets || {};
    config.assets.enableMods = true;
    config.assets.downloadLocally = true;
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
    console.log("已启用 assets.enableMods（data/config.json）");
  } else {
    console.log("assets.enableMods 已启用");
  }
}

if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error("重打包失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}