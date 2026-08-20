/**
 * 最小 Lua 更新包打包器（Delta）
 *
 * 目标：在启用 Lua 注入（assets.enableMods）时，自动构建一个**最小更新包**——
 * 只包含「补丁后的 DefinedFix.lua + 全部插件资产」，以独立的哈希命名 bundle
 * （anon/<内容md5>.bin）下发，替代"整包重建"（523 条内置 Lua 全量重打包，体积大、
 * 每次更新慢）。
 *
 * 与 repack-lua-bundle（整包）的分工：
 *   - 整包（repackBuiltinFromRef）：把内置 523 条 + 插件合并成内置同名 bundle 覆盖。
 *   - 本脚本（delta）：只下发「DefinedFix 补丁 + 插件」最小增量。客户端按条合并
 *     require 时，用本 bundle 的 DefinedFix 覆盖内置同名资产并引入 Plugin/*。体积最小，
 *     后续内置 Lua 版本变化无需重发——只要 DefinedFix/插件内容不变，hash 稳定。
 *
 * 用法：
 *   pnpm run pack:lua:min [--ref <明文Lua参考目录>] [--plugin <插件目录>] [--out <mods目录>]
 *   --ref     明文 Lua 参考目录（缺省 data/[uc]lua，其次回退 reference/ArknightsGameData/...）
 *   --plugin  插件源码目录（缺省 <项目根>/lua/plugin）
 *   --out     输出 mods 目录（缺省 <项目根>/mods）
 *
 * 产物：mods/anon_<内容md5>.dat（zip 单条目 anon/<内容md5>.bin），内容为 UnityFS bundle。
 */
import * as fs from "fs";
import * as path from "path";
import { createHash } from "crypto";
import JSZip from "jszip";
import { collectReferenceLua, detectAssetStyle, collectPluginAssets, patchDefinedFix } from "./repack-lua-bundle";
import { packLuaBundle, type LuaAsset } from "./pack-lua-bundle";

/** zip 条目固定时间戳：内容不变时 md5 稳定（客户端不重复下载） */
const LUA_ZIP_DATE = new Date("2024-01-01T00:00:00.000Z");
/** 缺省插件源码目录（相对项目根） */
function defaultPluginDir(): string {
  return path.join(__dirname, "..", "lua", "plugin");
}
/** 缺省明文 Lua 参考目录：优先 data/[uc]lua（热更提取产物），回退 ArknightsGameData */
function defaultRefDirs(): string[] {
  return [
    path.join(__dirname, "..", "data", "[uc]lua"),
    path.join(__dirname, "..", "reference", "ArknightsGameData", "zh_CN", "gamedata", "[uc]lua"),
  ];
}
/** 缺省输出 mods 目录 */
function defaultOutDir(): string {
  return path.join(__dirname, "..", "mods");
}

/** 打包结果 */
export interface LuaMinPackResult {
  /** 官方哈希命名 bundle 名（anon/<内容md5>.bin） */
  bundleName: string;
  /** mod 文件名（anon_<内容md5>.dat） */
  datName: string;
  /** dat 完整路径 */
  dat: string;
  /** UnityFS bundle 字节 */
  bundle: Uint8Array;
  /** 插件资产数（不含 DefinedFix） */
  pluginCount: number;
}

/**
 * 从候选参考目录中取 DefinedFix.lua 原文（精确匹配 DefinedFix.lua，忽略大小写）。
 * @param refDirs - 候选明文 Lua 参考目录列表
 * @returns DefinedFix.lua 脚本；未找到返回 null
 */
function findDefinedFix(refDirs: string[]): LuaAsset | null {
  for (const refDir of refDirs) {
    if (!fs.existsSync(refDir)) continue;
    const ref = collectReferenceLua(refDir); // 资产名统一小写 gamedata/[uc]lua/...
    const df = ref.find((a) => /definedfix\.lua$/i.test(a.name));
    if (df) return df;
  }
  return null;
}

/**
 * 构建最小 Lua 更新包（DefinedFix 补丁 + 全部插件资产）。
 * @param refDirs  - 候选明文 Lua 参考目录（取 DefinedFix 原文；缺省用默认列表）
 * @param pluginDir - 插件源码目录（缺省 lua/plugin）
 * @param outDir   - 输出 mods 目录（缺省 mods/）
 * @returns 打包结果（哈希命名 bundle + dat 路径）
 */
export async function buildLuaMinPack(
  refDirs?: string[],
  pluginDir?: string,
  outDir?: string,
): Promise<LuaMinPackResult> {
  const refs = refDirs ?? defaultRefDirs();
  const plg = pluginDir ?? defaultPluginDir();
  const outs = outDir ?? defaultOutDir();

  const definedFix = findDefinedFix(refs);
  if (!definedFix) {
    throw new Error(
      `最小更新包构建失败：未在候选参考目录找到 DefinedFix.lua（${refs.join(", ")}）。` +
        `请先运行 pnpm run extract:lua（内置 bundle）或 pnpm run extract:lua:hot（热更）。`,
    );
  }
  if (!fs.existsSync(plg)) {
    throw new Error(`插件目录不存在: ${plg}`);
  }

  // 命名风格由 DefinedFix 资产名推断（Windows 带 gamedata/[uc]lua/ 前缀 / Android 裸名）。
  // 最小包资产：DefinedFix（用补丁版，注入插件 hotfixer 条目）+ 全部插件资产。
  const style = detectAssetStyle([definedFix]);
  const plugins = collectPluginAssets(plg, style);
  const patched = patchDefinedFix(new TextDecoder().decode(definedFix.script));
  const assets: LuaAsset[] = [
    { name: definedFix.name, script: Buffer.from(patched, "utf8") },
    ...plugins,
  ];

  const uf = packLuaBundle(assets);
  const md5 = createHash("md5").update(uf).digest("hex");
  const bundleName = `anon/${md5}.bin`;

  const zip = new JSZip();
  zip.file(bundleName, Buffer.from(uf), { createFolders: false, date: LUA_ZIP_DATE });
  const datBuf = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });

  fs.mkdirSync(outs, { recursive: true });
  const datName = bundleName.replace(/\//g, "_").replace(/\.[^.]*$/, "") + ".dat";
  const dat = path.join(outs, datName);
  fs.writeFileSync(dat, Buffer.from(datBuf));

  return { bundleName, datName, dat, bundle: uf, pluginCount: plugins.length };
}

/** CLI 入口 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const pluginIdx = args.indexOf("--plugin");
  const outIdx = args.indexOf("--out");
  const refIdx = args.indexOf("--ref");
  const pluginDir = pluginIdx >= 0 ? args[pluginIdx + 1] : defaultPluginDir();
  const outDir = outIdx >= 0 ? args[outIdx + 1] : defaultOutDir();
  const refDirs = refIdx >= 0 ? [args[refIdx + 1]] : defaultRefDirs();

  const result = await buildLuaMinPack(refDirs, pluginDir, outDir);
  console.log(`构建最小 Lua 更新包: ${result.dat}`);
  console.log(`  bundle: ${result.bundleName} (${result.bundle.length} B, 含补丁 DefinedFix + ${result.pluginCount} 个插件)`);
}

if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error("构建失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}