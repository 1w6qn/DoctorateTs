/**
 * 内置 Lua bundle 提取器
 *
 * 从内置 Lua 主 bundle（anon/7d91430e114d86fef7d3b3511151e12d.bin）中提取全部明文 Lua 脚本，
 * 写入参考目录 reference/ArknightsGameData/zh_CN/gamedata/[uc]lua/，
 * 供 repack-lua-bundle.ts --from-ref 重建（无需再依赖客户端二进制）。
 *
 * 说明（关于「从官方 hot_update_list 提取」）：
 *   - 该内置 Lua bundle 属于客户端 base 资产，**不在**官方 hot_update_list.json 的 abInfos 中
 *     （清单仅含可热更的增量资产；当前 2.7.61 清单 14981 条无此 hash，CDN 各版本路径亦 404）。
 *   - bundle 哈希由官方 resource_manifest_idx.json（ArknightsGameData）确认：
 *     assetToBundleList 中全部 gamedata/[uc]lua/* 资产的 bundleIndex=2246
 *     → bundles[2246].name = anon/7d91430e114d86fef7d3b3511151e12d.bin。
 *   - 因此实际取数源为已装客户端内的该 bundle（.dat zip / .bin UnityFS），本脚本负责解包提取。
 *
 * 用法：
 *   pnpm run extract:lua -- --bundle <内置bundle.dat|.bin> [--out <参考目录>]
 *   --bundle  必填，内置 Lua bundle 路径
 *   --out     参考输出目录（缺省 <项目根>/reference/ArknightsGameData/zh_CN/gamedata/[uc]lua）
 */
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { extractTextAssets, type TextAssetData } from "./vendor/unityfs";
import { decryptLuaScript, isLuaEncrypted } from "./vendor/lua-crypt";

/** Lua 资产名前缀（对齐客户端资源名约定） */
const LUA_PREFIX = "gamedata/[uc]lua/";
/** 插件资产子目录（构建期由 lua/plugin/ 重新合并，提取时跳过避免重复） */
const PLUGIN_SUBDIR = "plugin/";
/** 引导 hotfixer 条目（构建期由 patchDefinedFix 注入，提取时需还原） */
const BOOT_ENTRY = '"Plugin/PluginBootHotfixer"';
/** 内置 Lua 主 bundle 名（.dat 多条目时优先匹配该条目） */
const BUILTIN_BUNDLE_NAME = "anon/7d91430e114d86fef7d3b3511151e12d.bin";

/** 默认参考输出目录（相对项目根） */
function defaultRefDir(): string {
  return path.join(__dirname, "..", "reference", "ArknightsGameData", "zh_CN", "gamedata", "[uc]lua");
}

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
  const zip = await JSZip.loadAsync(fs.readFileSync(input));
  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  if (names.length === 0) {
    throw new Error(`内置 bundle .dat 内无条目: ${input}`);
  }
  const preferred = names.find((n) => n === BUILTIN_BUNDLE_NAME);
  const entry = zip.files[preferred ?? names[0]];
  return new Uint8Array(await entry.async("uint8array"));
}

/**
 * 还原 DefinedFix.lua 的官方原版：剔除 patchDefinedFix 注入的引导 hotfixer 条目。
 * 若不剔除，reference 里将带注入标记，--from-ref 重建时会二次注入。
 * @param script - 可能被注入过的 DefinedFix.lua 文本
 * @returns 剔除引导条目后的文本
 */
function stripBootInjection(script: string): string {
  const lines = script.split(/\r?\n/);
  const kept = lines.filter((line) => {
    const trimmed = line.trim();
    // 仅剔除恰好是引导条目（含逗号的独立行）的情况，避免误删内容中的同名引用
    return !(trimmed === `${BOOT_ENTRY},` || trimmed === BOOT_ENTRY);
  });
  return kept.join("\n");
}

/**
 * 从内置 bundle 提取全部 Lua 脚本到参考目录。
 * 跳过插件资产（plugin/* 或插件裸名，构建期重新合并）并还原 DefinedFix 注入标记；
 * Android 加密格式（CRYPTIC_A）自动解密后写入。
 * @param bundlePath - 内置 bundle 路径（.dat 或 .bin）
 * @param outDir     - 参考输出目录
 * @returns 统计信息
 */
export async function extractLuaBundle(
  bundlePath: string,
  outDir: string,
): Promise<{ total: number; written: number; skipped: number; unchanged: number }> {
  const bytes = await readBuiltinBundle(bundlePath);
  const assets = extractTextAssets(bytes);
  if (assets.length === 0) {
    throw new Error(`内置 bundle 未解析出任何 TextAsset: ${bundlePath}`);
  }

  let written = 0;
  let skipped = 0;
  const unchanged: string[] = [];
  const skippedList: string[] = [];

  for (const asset of assets) {
    const name = asset.name;
    const lower = name.toLowerCase();
    const isPrefixed = lower.startsWith(LUA_PREFIX);
    if (!isPrefixed && !lower.endsWith(".lua")) {
      skipped++;
      skippedList.push(name);
      continue;
    }
    const rel = isPrefixed ? name.slice(LUA_PREFIX.length) : name;
    // 跳过插件资产（构建期由 lua/plugin/ 重新合并；仅 prefixed 布局的 plugin/ 子目录，
    // Android 裸名布局的官方内置 bundle 不含插件资产，全量保留）
    if (rel.toLowerCase().startsWith(PLUGIN_SUBDIR)) {
      skipped++;
      skippedList.push(name);
      continue;
    }
    // 解密（Android CRYPTIC_A 加密格式；明文资产原样保留）
    let script = asset.script;
    try {
      if (isLuaEncrypted(script)) {
        script = decryptLuaScript(script);
      }
    } catch {
      // 解密失败视为明文，原样写入（版本漂移时至少保留原始字节可人工分析）
    }
    // 还原 DefinedFix 的注入标记；unchanged 仅统计「DefinedFix 未含注入标记（官方原版）」的数量
    const isDefinedFix = rel.toLowerCase().endsWith("definedfix.lua");
    let injected = false;
    if (isDefinedFix) {
      const text = new TextDecoder().decode(script);
      injected = text.includes(BOOT_ENTRY);
      if (injected) {
        script = Buffer.from(stripBootInjection(text), "utf8");
      }
    }
    if (isDefinedFix && !injected) unchanged.push(rel);

    const outPath = path.join(outDir, rel);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, Buffer.from(script));
    written++;
  }

  return {
    total: assets.length,
    written,
    skipped,
    unchanged: unchanged.length,
  };
}

/** CLI 入口 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const bundleIdx = args.indexOf("--bundle");
  const outIdx = args.indexOf("--out");
  const bundlePath = bundleIdx >= 0 ? args[bundleIdx + 1] : "";
  const outDir = outIdx >= 0 ? args[outIdx + 1] : defaultRefDir();

  if (!bundlePath) {
    console.error(
      "用法: pnpm run extract:lua -- --bundle <内置bundle.dat|.bin> [--out <参考目录>]",
    );
    process.exit(1);
  }

  const result = await extractLuaBundle(bundlePath, outDir);
  console.log(`提取完成: ${result.total} 条资产 → ${outDir}`);
  console.log(`  写入 ${result.written} 条明文 Lua，跳过 ${result.skipped} 条（非 Lua/插件资产）`);
  if (result.unchanged > 0) {
    console.log(`  注意: ${result.unchanged} 条 DefinedFix 未含注入标记（已是官方原版）`);
  }

  // 提示后续重建命令
  console.log(`\n参考目录已就绪，可用以下命令重建并覆盖内置 bundle mod：`);
  console.log(`  pnpm run repack:lua -- --from-ref`);
}

if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error("提取失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
