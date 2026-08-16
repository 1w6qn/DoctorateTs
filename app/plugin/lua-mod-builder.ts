/**
 * Lua 插件 mod 自动构建器
 *
 * 服务启动（assets.enableMods=true 且 assets.autoBuildLuaMod !== false）时自动确保
 * 内置 Lua bundle 覆盖 mod（mods/anon_7d91430e114d86fef7d3b3511151e12d.dat）为最新：
 *   - mod 缺失、或 lua/plugin/ 任一 .lua（含目录 mtime，覆盖删除场景）新于产物时自动重打包；
 *   - 数据源优先级：reference 明文目录（--from-ref 同源，最干净）→ 现有 mod 自身
 *     （解包 → 剔除旧插件资产/剥离注入 → 合并当前插件 → 重打包，幂等，见 repack-lua-bundle）；
 *   - 两者皆无（首次运行且未提供客户端 bundle / 未 extract）→ warn 并跳过，不影响启动。
 *
 * 产物确定性：zip 条目固定时间戳（LUA_ZIP_DATE），插件内容不变时 md5 稳定，
 * 客户端不会因每次启动自动重建而重复全量下载。
 */
import * as fs from "fs";
import * as path from "path";
import { logger } from "@utils/logger";
import { repackBuiltinLua, repackBuiltinFromRef } from "../../scripts/repack-lua-bundle";

/** 内置 Lua 主 bundle 覆盖 mod 文件名（对应 app/asset.ts mod 管线下载名） */
export const BUILTIN_LUA_MOD_NAME = "anon_7d91430e114d86fef7d3b3511151e12d.dat";

/** 自动构建结果 */
export interface LuaModBuildResult {
  /** 本次是否执行了重打包 */
  built: boolean;
  /** 结果说明（up-to-date / from-ref / self-repack / no-source / error: ...） */
  reason: string;
  /** 产物路径（构建成功或已存在时非 null） */
  dat: string | null;
}

/** 构建选项（测试可注入临时目录） */
export interface LuaModBuildOptions {
  /** mods 输出目录（缺省 <项目根>/mods） */
  modsDir?: string;
  /** 插件源码目录（缺省 <项目根>/lua/plugin） */
  pluginDir?: string;
  /** 官方明文 Lua 参考目录（缺省 <项目根>/reference/ArknightsGameData/zh_CN/gamedata/[uc]lua） */
  refDir?: string;
  /** 强制重打包（跳过过期检测） */
  force?: boolean;
}

/** 缺省插件源码目录（相对项目根） */
function defaultPluginDir(): string {
  return path.join(__dirname, "..", "..", "lua", "plugin");
}

/** 缺省官方明文 Lua 参考目录 */
function defaultRefDir(): string {
  return path.join(
    __dirname,
    "..",
    "..",
    "reference",
    "ArknightsGameData",
    "zh_CN",
    "gamedata",
    "[uc]lua",
  );
}

/**
 * 递归统计目录下 .lua 文件的最新 mtime（含目录 mtime，覆盖删除场景）。
 * @param dir - 目录
 * @returns 最新 mtimeMs；目录不存在返回 null
 */
function newestLuaMtime(dir: string): number | null {
  if (!fs.existsSync(dir)) return null;
  let newest = fs.statSync(dir).mtimeMs; // 目录 mtime：文件新增/删除均会更新
  const walk = (cur: string): void => {
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith(".lua")) {
        newest = Math.max(newest, fs.statSync(full).mtimeMs);
      }
    }
  };
  walk(dir);
  return newest;
}

/**
 * 判断覆盖 mod 是否过期：
 *   - mod 缺失；
 *   - 插件源码（文件/目录 mtime）新于产物；
 *   - 参考目录（含 .lua）新于产物（重新 extract 新客户端 bundle 后自动重建）。
 * @param datPath - 覆盖 mod 路径
 * @param pluginDir - 插件源码目录
 * @param refDir - 官方明文 Lua 参考目录（可选；有 .lua 内容时参与过期判断）
 * @returns 是否需重打包
 */
export function isLuaModStale(datPath: string, pluginDir: string, refDir?: string): boolean {
  if (!fs.existsSync(datPath)) return true;
  const datMtime = fs.statSync(datPath).mtimeMs;
  const newestPlugin = newestLuaMtime(pluginDir);
  if (newestPlugin === null) return true; // 插件目录缺失（异常态，交由构建报错/跳过）
  if (newestPlugin > datMtime) return true;
  if (refDir !== undefined && hasLuaFiles(refDir)) {
    const newestRef = newestLuaMtime(refDir);
    if (newestRef !== null && newestRef > datMtime) return true;
  }
  return false;
}

/**
 * 递归判断目录下是否存在 .lua 文件（参考目录有效性的依据：
 * 空目录/未 extract 的目录不能作为数据源，避免误入 from-ref 构建后报错）。
 * @param dir - 目录
 * @returns 是否含至少一个 .lua 文件
 */
function hasLuaFiles(dir: string): boolean {
  if (!fs.existsSync(dir)) return false;
  try {
    const walk = (cur: string): boolean => {
      for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
        if (entry.isDirectory()) {
          if (walk(path.join(cur, entry.name))) return true;
        } else if (entry.name.endsWith(".lua")) {
          return true;
        }
      }
      return false;
    };
    return walk(dir);
  } catch {
    return false;
  }
}

/**
 * 确保内置 Lua bundle 覆盖 mod 为最新（缺省不强制，按过期检测）。
 * 永不抛错：任何构建失败仅记录 warn，不影响服务启动。
 * @param options - 路径覆盖 / 强制选项
 * @returns 构建结果
 */
export async function ensureLuaModBuilt(
  options: LuaModBuildOptions = {},
): Promise<LuaModBuildResult> {
  const modsDir = options.modsDir ?? path.join(__dirname, "..", "..", "mods");
  const pluginDir = options.pluginDir ?? defaultPluginDir();
  const refDir = options.refDir ?? defaultRefDir();
  const datPath = path.join(modsDir, BUILTIN_LUA_MOD_NAME);

  const skipReason =
    options.force === true ? null : isLuaModStale(datPath, pluginDir, refDir) ? null : "up-to-date";
  if (skipReason !== null) {
    if (fs.existsSync(datPath)) {
      logger.debug("Plugin", `Lua mod 已是最新，跳过自动构建: ${datPath}`);
      return { built: false, reason: skipReason, dat: datPath };
    }
    return { built: false, reason: skipReason, dat: null };
  }

  try {
    let result;
    let reason: string;
    if (hasLuaFiles(refDir)) {
      // 优先：官方明文参考目录（最干净，无自举依赖）
      result = await repackBuiltinFromRef(refDir, pluginDir, modsDir);
      reason = "from-ref";
    } else if (fs.existsSync(datPath)) {
      // 回退：现有 mod 自举（幂等——剔除旧插件/剥离注入后再合并当前插件）
      result = await repackBuiltinLua(datPath, pluginDir, modsDir);
      reason = "self-repack";
    } else {
      logger.warn(
        "Plugin",
        `Lua mod 自动构建跳过：无数据源（缺少参考目录 ${refDir}，且无现有 mod ${datPath}）。` +
          `请先提供客户端内置 bundle 运行 pnpm run extract:lua / repack:lua，或放入现有 mod。`,
      );
      return { built: false, reason: "no-source", dat: null };
    }
    logger.info(
      "Plugin",
      `Lua mod 自动构建完成（${reason}）: ${result.dat}（${result.assetCount} 条 Lua）`,
    );
    return { built: true, reason, dat: result.dat };
  } catch (error) {
    // 容错：构建失败不阻断启动（保留现有 mod；缺失则客户端回退官方内置 bundle）
    logger.warn("Plugin", `Lua mod 自动构建失败（不影响启动）: ${(error as Error).message}`);
    return { built: false, reason: `error: ${(error as Error).message}`, dat: fs.existsSync(datPath) ? datPath : null };
  }
}
