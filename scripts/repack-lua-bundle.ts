/**
 * 内置 Lua bundle 重打包器（方案 A）
 *
 * 目标：把客户端内置 Lua 主 bundle（anon/7d91430e114d86fef7d3b3511151e12d.bin）重打包，
 * 将 lua/plugin/ 插件脚本 merge 进去，并 patch entry.lua 使其 require "Plugin/PluginEntry"，
 * 最后覆盖下发为 mods/anon_7d91430e114d86fef7d3b3511151e12d.dat，客户端热更即加载插件。
 *
 * 输入：内置 bundle（.bin UnityFS 或 .dat zip 单条目）。
 *   - 从已装客户端提取内置 bundle（ArkUnpacker 解包后定位 anon/7d91430e114d86fef7d3b3511151e12d.bin）。
 *   - 或直接给出该 bundle 的 .dat/.bin 路径。
 *
 * 用法：
 *   pnpm run repack:lua -- --bundle <内置bundle.dat|.bin>
 *   --bundle  必填，内置 Lua bundle 路径
 *   --out     输出 mods 目录（缺省 <项目根>/mods）
 */
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { packLuaBundle, type LuaAsset } from "./pack-lua-bundle";
import { extractTextAssets } from "./vendor/unityfs";

/** 内置 Lua 主 bundle 名（zip 条目名 = 客户端资源名） */
const BUILTIN_BUNDLE_NAME = "anon/7d91430e114d86fef7d3b3511151e12d.bin";
/** 对应 mod 下载名 */
const BUILTIN_MOD_NAME = "anon_7d91430e114d86fef7d3b3511151e12d.dat";
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
 * 读取内置 bundle 字节：.dat 解 zip 取单条目，.bin 直读。
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
  const entry = zip.files[names[0]];
  const bytes = await entry.async("uint8array");
  return new Uint8Array(bytes);
}

/**
 * 递归收集 lua/plugin/ 下所有 .lua 为插件资产（m_Name = gamedata/[uc]lua/Plugin/<rel>）。
 * @param dir - 插件源码目录
 * @returns 插件 Lua 资产列表（按名排序）
 */
function collectPluginAssets(dir: string): LuaAsset[] {
  const out: LuaAsset[] = [];
  const walk = (cur: string): void => {
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith(".lua")) {
        const rel = path.relative(dir, full).split(path.sep).join("/");
        out.push({ name: PLUGIN_ASSET_PREFIX + rel, script: fs.readFileSync(full) });
      }
    }
  };
  walk(dir);
  out.sort((a, b) => (a.name < b.name ? -1 : 1));
  return out;
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
 * 在 DefinedFix.lua 清单中注入引导 hotfixer：把 "Plugin/PluginBootHotfixer" 插到首个条目之前。
 * 使用游戏原生 hotfix 管线（HotfixProcesser.Do）引导插件加载，比 patch entry.lua 更稳。
 * @param script - 原始 DefinedFix.lua 文本
 * @returns 补丁后的 DefinedFix.lua 文本
 */
export function patchDefinedFix(script: string): string {
  const marker = '"HotFixes/';
  const idx = script.indexOf(marker);
  if (idx < 0) {
    throw new Error("DefinedFix 补丁失败：未找到 hotfixer 条目（版本漂移？）");
  }
  // 在首个条目前插入新条目（新条目带逗号，原首个条目及其逗号保留，Lua 5.1 语法合法）
  return script.slice(0, idx) + '  "Plugin/PluginBootHotfixer",\n' + script.slice(idx);
}

/**
 * 合并内置 Lua 资产与插件资产，并 patch DefinedFix 以引导插件加载。
 * @param builtin - 内置 bundle 的全部 Lua 资产
 * @param pluginDir - 插件源码目录
 * @returns 合并后的资产列表（含补丁后的 DefinedFix）
 */
export function mergeAndPatch(builtin: LuaAsset[], pluginDir: string): LuaAsset[] {
  const plugins = collectPluginAssets(pluginDir);
  const merged = builtin.map((a) => ({ ...a }));
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
  return [...plugins, ...merged];
}

/**
 * 重打包内置 Lua bundle 并输出覆盖 mod（.dat）。
 * @param builtinPath - 内置 bundle 路径（.dat 或 .bin）
 * @param pluginDir   - 插件源码目录
 * @param outModsDir  - 输出 mods 目录
 * @returns 结果（dat 路径、bundle 字节、资产总数）
 */
export async function repackBuiltinLua(
  builtinPath: string,
  pluginDir: string,
  outModsDir: string,
): Promise<{ dat: string; bundle: Uint8Array; assetCount: number }> {
  const builtinBytes = await readBuiltinBundle(builtinPath);
  const builtin = extractTextAssets(builtinBytes);
  if (builtin.length === 0) {
    throw new Error(`内置 bundle 未解析出任何 Lua 资产: ${builtinPath}`);
  }
  const merged = mergeAndPatch(builtin, pluginDir);

  const uf = packLuaBundle(merged);
  const zip = new JSZip();
  zip.file(BUILTIN_BUNDLE_NAME, Buffer.from(uf), { createFolders: false });
  const dat = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });

  fs.mkdirSync(outModsDir, { recursive: true });
  const datPath = path.join(outModsDir, BUILTIN_MOD_NAME);
  fs.writeFileSync(datPath, Buffer.from(dat));
  return { dat: datPath, bundle: uf, assetCount: merged.length };
}

/**
 * 从官方明文 Lua 参考目录重建内置 bundle（含插件 + DefinedFix 补丁）并输出覆盖 mod。
 * 免去提取客户端二进制的步骤：明文参考目录即内置 bundle 的源码。
 * @param refDir    - 官方明文 Lua 目录（[uc]lua）
 * @param pluginDir - 插件源码目录
 * @param outModsDir- 输出 mods 目录
 * @returns 结果（dat 路径、bundle 字节、资产总数）
 */
export async function repackBuiltinFromRef(
  refDir: string,
  pluginDir: string,
  outModsDir: string,
): Promise<{ dat: string; bundle: Uint8Array; assetCount: number }> {
  const builtin = collectReferenceLua(refDir);
  const merged = mergeAndPatch(builtin, pluginDir);
  return writeModDat(merged, outModsDir);
}

/**
 * 将合并后的资产列表打包为 UnityFS bundle 并写为覆盖 mod（.dat）。
 * @param merged   - 合并后的资产列表
 * @param outModsDir - 输出 mods 目录
 * @returns 结果（dat 路径、bundle 字节、资产总数）
 */
async function writeModDat(
  merged: LuaAsset[],
  outModsDir: string,
): Promise<{ dat: string; bundle: Uint8Array; assetCount: number }> {
  const uf = packLuaBundle(merged);
  const zip = new JSZip();
  zip.file(BUILTIN_BUNDLE_NAME, Buffer.from(uf), { createFolders: false });
  const dat = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });

  fs.mkdirSync(outModsDir, { recursive: true });
  const datPath = path.join(outModsDir, BUILTIN_MOD_NAME);
  fs.writeFileSync(datPath, Buffer.from(dat));
  return { dat: datPath, bundle: uf, assetCount: merged.length };
}

/** CLI 入口 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const bundleIdx = args.indexOf("--bundle");
  const refIdx = args.indexOf("--from-ref");
  const outIdx = args.indexOf("--out");
  const builtinPath = bundleIdx >= 0 ? args[bundleIdx + 1] : "";
  const fromRef = refIdx >= 0;
  const outModsDir = outIdx >= 0 ? args[outIdx + 1] : path.join(__dirname, "..", "mods");

  let result;
  if (fromRef) {
    console.log("从官方明文 Lua 参考目录重建内置 bundle…");
    result = await repackBuiltinFromRef(REF_LUA_DIR, PLUGIN_DIR, outModsDir);
  } else if (builtinPath) {
    result = await repackBuiltinLua(builtinPath, PLUGIN_DIR, outModsDir);
  } else {
    console.error(
      "用法: pnpm run repack:lua -- --from-ref [--out <mods目录>]\n" +
        "  或: pnpm run repack:lua -- --bundle <内置bundle.dat|.bin> [--out <mods目录>]",
    );
    process.exit(1);
  }
  console.log(`已覆盖内置 Lua bundle mod: ${result.dat}`);
  console.log(`  bundle: ${BUILTIN_BUNDLE_NAME} (${result.bundle.length} B, ${result.assetCount} 条 Lua)`);

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