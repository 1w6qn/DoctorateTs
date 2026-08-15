/**
 * 插件目录解析器（单一数据源）
 *
 * 以 lua/plugin/PluginDefs.lua 为唯一来源，解析插件目录（id/name/desc/module），
 * 供 PluginConfigService 使用，消除服务端 PLUGIN_CATALOG 与 Lua 侧清单的双份硬编码漂移。
 *
 * PluginDefs.lua 格式（字段顺序固定：id → name → desc → module）：
 *   local PluginDefs = {
 *     { id = "enemy_hp", name = "敌人血量显示", desc = "...", module = "Plugin/EnemyHpPlugin" },
 *     ...
 *   }
 */
import * as fs from "fs";
import * as path from "path";
import { logger } from "@utils/logger";

/** 插件目录条目 */
export interface PluginCatalogEntry {
  id: string;
  name: string;
  desc: string;
  /** 客户端 require 路径（如 Plugin/EnemyHpPlugin） */
  module: string;
}

/** 内置回退目录（解析失败时使用，保持向后兼容） */
export const FALLBACK_CATALOG: readonly PluginCatalogEntry[] = Object.freeze([
  { id: "enemy_hp", name: "敌人血量显示", desc: "在敌人血条旁显示具体血量数值", module: "Plugin/EnemyHpPlugin" },
  { id: "enemy_info", name: "敌人属性面板", desc: "战斗中长按并点击敌人查看属性与路线", module: "Plugin/EnemyInfoPlugin" },
  { id: "battle_assist", name: "战斗辅助", desc: "战斗时间轴 / 倍速 / TAS 暂停帧", module: "Plugin/BattleAssistPlugin" },
  { id: "plugin_panel", name: "插件管理面板", desc: "现代化插件启停管理面板", module: "Plugin/PanelPlugin" },
]);

/** PluginDefs.lua 中单个条目块的正则（id → name → desc → module，顺序固定） */
const ENTRY_RE =
  /id\s*=\s*"([^"]*)"\s*,\s*name\s*=\s*"([^"]*)"\s*,\s*desc\s*=\s*"([^"]*)"\s*,\s*module\s*=\s*"([^"]*)"/g;

/**
 * 从 PluginDefs.lua 文本解析插件目录。
 * @param content - PluginDefs.lua 源码文本
 * @returns 插件目录条目列表（按出现顺序）
 */
export function parsePluginDefs(content: string): PluginCatalogEntry[] {
  const out: PluginCatalogEntry[] = [];
  ENTRY_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ENTRY_RE.exec(content)) !== null) {
    const [, id, name, desc, module] = m;
    if (!id || !module) continue;
    out.push({ id, name: name || id, desc: desc || "", module });
  }
  return out;
}

/**
 * 加载插件目录：读取 PluginDefs.lua 并解析。
 * 文件缺失或解析结果为空时回退内置目录，保证服务端不因目录异常而不可用。
 * @param luaPath - PluginDefs.lua 绝对路径（缺省 <项目根>/lua/plugin/PluginDefs.lua）
 * @returns 插件目录
 */
export function loadPluginCatalog(luaPath?: string): PluginCatalogEntry[] {
  const file = luaPath ?? path.join(__dirname, "..", "..", "lua", "plugin", "PluginDefs.lua");
  try {
    if (fs.existsSync(file)) {
      const parsed = parsePluginDefs(fs.readFileSync(file, "utf-8"));
      if (parsed.length > 0) {
        return parsed;
      }
      logger.warn("Plugin", `PluginDefs.lua 解析结果为空（${file}），使用内置目录`);
    }
  } catch (error) {
    logger.warn("Plugin", `读取 PluginDefs.lua 失败（${file}），使用内置目录`, error);
  }
  return [...FALLBACK_CATALOG];
}
