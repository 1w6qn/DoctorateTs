/**
 * 插件服务模块出口。
 * 统一导出 PluginConfigService、单例与插件目录，供 admin 路由等使用。
 */
export {
  PluginConfigService,
  pluginConfigService,
  PLUGIN_CATALOG,
  __resetPluginConfigService,
  type PluginDefinition,
} from "./PluginConfigService";