--[[
  NetworkRedirectPlugin.lua —— 私服引导插件

  把官服客户端引导到本私服，纯 Lua hotfix 实现（无需 Frida）：
    1. hotfix Torappu.Network.Networker.get_overrideRouterUrl —— 让客户端从私服拉取
       network_config（路由配置），后续 gameServer/sdkServer 等全部指向私服；
    2. hotfix Torappu.CryptUtils.VerifySignMD5RSA —— 返回 true 绕过 RSA 签名校验
       （官服对 network_config 与 BSON 响应做 RSA-MD5 签名，见
       NetworkRouter.cs:409 / BsonNetConverter_WithSign.cs:56，私服无对应私钥必须绕过）。

  说明：
    - Networker 实现 IHotfixable 且 get_overrideRouterUrl 有 __Hotfix0_get_overrideRouterUrl
      委托字段，属性 getter 可被 xLua hotfix（方法名 get_xxx）。
    - 本插件在游戏启动早期（DefinedFix 管线 → HotfixProcesser.Do）加载，早于网络模块初始化，
      因此 getter 首次被读取时即命中私服地址。
    - 私服地址改 SERVER_URL 即可；默认与 hook/main.ts（Frida 版）保持一致。

  依赖：Base/BaseModule（Class）、Plugin/BasePlugin、Plugin/PluginHotfix。
--]]
local NetworkRedirectPlugin = Class("NetworkRedirectPlugin", require("Plugin/BasePlugin"))
local eutil = CS.Torappu.Lua.Util

-- 类级元数据（管理器/面板/管理端目录以此为准；与 PluginDefs.lua 保持一致）
NetworkRedirectPlugin.id = "network_redirect"
NetworkRedirectPlugin.name = "私服引导"
NetworkRedirectPlugin.desc = "将客户端网络路由与签名校验重定向到本私服（保持启用，关闭则连不回私服）"

-- 私服地址（改为你机器的局域网 IP / 域名；端口与 data/config.json 的 server 一致）
-- 客户端与服务端同机时用 127.0.0.1 最稳（绕开防火墙）；跨设备联机时改为本机局域网 IP。
local SERVER_URL = "http://127.0.0.1:8443"

--[[
  Networker.get_overrideRouterUrl 的替换实现：返回私服 network_config 路由地址。
  @return 私服路由 URL
--]]
local function _RouterUrlFix(self)
  return SERVER_URL .. "/config/prod/official/network_config"
end

--[[
  CryptUtils.VerifySignMD5RSA 的替换实现：恒返回 true（绕过 RSA 签名校验）。
  同名两个重载（string,string,string / byte[],byte[],string）均由本函数适配。
  @return true
--]]
local function _VerifySignFix(self, a, b, c)
  return true
end

--[[
  插件启用：安装私服引导补丁。
--]]
function NetworkRedirectPlugin:OnLoad()
  self:Fix_ex(CS.Torappu.Network.Networker, "get_overrideRouterUrl", _RouterUrlFix)
  self:Fix_ex(CS.Torappu.CryptUtils, "VerifySignMD5RSA", _VerifySignFix)
  eutil.Log("[NetworkRedirectPlugin] 私服引导已启用: " .. SERVER_URL)
end

--[[
  插件停用：补丁由 BasePlugin 统一还原。
--]]
function NetworkRedirectPlugin:OnUnload()
  eutil.Log("[NetworkRedirectPlugin] 私服引导已停用")
end

return NetworkRedirectPlugin
