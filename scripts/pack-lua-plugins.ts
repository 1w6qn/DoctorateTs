/**
 * Lua 插件打包器：把 lua/plugin/ 下的明文 Lua 插件脚本打包为单个 UnityFS bundle，
 * 并包装为 mods/*.dat（zip 单条目，条目名 = bundle 名），经 app/ops/assets/asset.ts mod 管线热更下发。
 *
 * 用法：
 *   pnpm run pack:lua-plugins [--dir <lua根目录>] [--out <mods目录>]
 *   --dir   必填，Lua 插件源码根目录（缺省 <项目根>/lua/plugin）
 *   --out   输出目录（缺省 <项目根>/mods）
 *
 * 产物：<out>/plugin_lua.dat（zip 单条目 "plugin_lua.bin"，内容为 UnityFS bundle）。
 * 客户端集成（注入 hot_update_list + 覆盖内置 Lua bundle）见 .trae/specs/lua-hot-update.md。
 */
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { packLuaBundle, type LuaAsset } from "./pack-lua-bundle";

/** 默认 Lua 插件源码根目录（相对项目根） */
const DEFAULT_LUA_DIR = path.join(__dirname, "..", "lua", "plugin");
/** 默认输出 mods 目录（相对项目根） */
const DEFAULT_OUT_DIR = path.join(__dirname, "..", "mods");
/** 产出 bundle 名（zip 条目名 = 客户端资源名） */
const BUNDLE_NAME = "plugin_lua.bin";
/** 产出 mod 文件名 */
const MOD_NAME = "plugin_lua.dat";
/** 插件资产名前缀（与 repack-lua-bundle 的插件资产一致：gamedata/[uc]lua/Plugin/） */
const PLUGIN_ASSET_PREFIX = "gamedata/[uc]lua/Plugin/";

interface CliArgs {
  dir: string;
  out: string;
}

/** 解析 CLI 参数 */
function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { dir: DEFAULT_LUA_DIR, out: DEFAULT_OUT_DIR };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--dir") args.dir = argv[++i] ?? "";
    else if (arg === "--out") args.out = argv[++i] ?? "";
    else if (arg === "--help" || arg === "-h") {
      console.log("用法: pnpm run pack:lua-plugins [--dir <lua根目录>] [--out <mods目录>]");
      process.exit(0);
    }
  }
  return args;
}

/**
 * 递归收集目录下所有 .lua 文件为 Lua 资产，m_Name = gamedata/[uc]lua/Plugin/<相对 POSIX 路径>，
 * 与 require 路径 "Plugin/…" 及 repack-lua-bundle 的插件资产命名约定一致。
 * @param dir - Lua 插件源码根目录
 * @returns Lua 资产列表（按名排序）
 */
function collectLuaAssets(dir: string): LuaAsset[] {
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
  if (!fs.existsSync(dir)) {
    throw new Error(`Lua 插件目录不存在: ${dir}`);
  }
  walk(dir);
  out.sort((a, b) => (a.name < b.name ? -1 : 1));
  return out;
}

/**
 * 打包 Lua 插件目录为 mods/plugin_lua.dat（zip 单条目 UnityFS bundle）。
 * @param dir - Lua 插件源码根目录
 * @param out - 输出 mods 目录
 * @returns 打包结果（dat 路径、bundle 字节、资产列表）
 */
export async function packLuaPlugins(
  dir: string,
  out: string,
): Promise<{ dat: string; bundle: Uint8Array; assets: LuaAsset[] }> {
  const assets = collectLuaAssets(dir);
  if (assets.length === 0) {
    throw new Error(`Lua 插件目录无 .lua 文件（${dir}）`);
  }
  const uf = packLuaBundle(assets);
  const zip = new JSZip();
  zip.file(BUNDLE_NAME, Buffer.from(uf), { createFolders: false });
  const buf = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
  fs.mkdirSync(out, { recursive: true });
  const outPath = path.join(out, MOD_NAME);
  fs.writeFileSync(outPath, buf);
  return { dat: outPath, bundle: uf, assets };
}

/** CLI 入口 */
async function main(): Promise<void> {
  const { dir, out } = parseArgs(process.argv.slice(2));
  let result;
  try {
    result = await packLuaPlugins(dir, out);
  } catch (e) {
    console.warn(e instanceof Error ? e.message : String(e));
    return;
  }
  console.log(`已生成 Lua 插件 mod: ${result.dat}`);
  console.log(`  bundle: ${BUNDLE_NAME} (${result.bundle.length} B, ${result.assets.length} 条 Lua)`);
  for (const a of result.assets) {
    console.log(`    ${a.name}`);
  }
  console.log(`启用：将 data/config.json 的 "assets" -> "enableMods" 置 true，重启服务后客户端热更拉取。`);
}

if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error("打包失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}