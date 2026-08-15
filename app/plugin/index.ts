/**
 * 插件服务模块出口。
 * 统一导出 PluginConfigService、单例与插件目录解析，供 admin 路由等使用。
 */
export {
  PluginConfigService,
  pluginConfigService,
  __resetPluginConfigService,
  type PluginDefinition,
} from "./PluginConfigService";
export { loadPluginCatalog, parsePluginDefs, FALLBACK_CATALOG, type PluginCatalogEntry } from "./plugin-catalog";