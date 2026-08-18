# 明日方舟客户端 APK 安全审查报告（校验 / 反作弊 / 暗桩）

> 审查对象：客户端反编译 C# 源码（22963 个 .cs）D:\develop\DoctorateTs\reference\arknights-2.7.61-csharp；APK 本体：签名 V1(JAR 签名) 存在 / V2/V3(APK Signing Block) 存在（V3 需解析 signer 版本，此处仅确认 block）
> 生成时间：2026-08-18T05:41:45.192Z

## 结论速览

- **A. 完整性 / 签名校验**：RSA 响应验签（必须绕过）+ 热更资源 md5 校验（mod 方案已兼容）
- **B. 反作弊**：CodeStage 检测器 5 类 + Obscured 混淆值 + ACE/MTP（native 层，动态分析）
- **C. 暗桩 / 埋点**：EventLogSDK 埋点 + CrashSight 崩溃上报 + OneChannel/Webview + 硬编码域名
- **D. APK 本体（Java / native / 资源层）**：5 个 dex + 51 个 so 库 + 5 个敏感权限

## A. 完整性 / 签名校验

### RSA 响应签名校验 VerifySignMD5RSA

官服对 network_config 路由配置与 BSON/加密响应做 RSA-MD5 签名，客户端验签失败即拒绝。私服必须绕过（Lua 引导插件已 hotfix 返回 true）。

| 位置 | 命中 |
|---|---|
| `Assembly-CSharp/Torappu/CryptUtils.cs:206` | `public static bool VerifySignMD5RSA(string content, string sign, string publicKey)` |
| `Assembly-CSharp/Torappu/CryptUtils.cs:212` | `return VerifySignMD5RSA(Encoding.UTF8.GetBytes(content), sign2, publicKey);` |
| `Assembly-CSharp/Torappu/CryptUtils.cs:220` | `public static bool VerifySignMD5RSA(byte[] contentBytes, byte[] sign, string publicKey)` |
| `Assembly-CSharp\Torappu.DB\BsonNetConverter_WithSign.cs:56` | `if (CryptUtils.VerifySignMD5RSA(contentBytes, array, signPubKey))` |
| `Assembly-CSharp\Torappu.DB\CrypticConverter_WithSign.cs:109` | `if (!CryptUtils.VerifySignMD5RSA(contentBytes, array, signPubKey))` |
| `Assembly-CSharp\Torappu.Network\NetworkRouter.cs:409` | `if (CryptUtils.VerifySignMD5RSA(networkRouterConfig.content, sign, text))` |

### 热更资源完整性校验 HotUpdater

按 hot_update_list 的 md5/hash 判定资源是否需更新；私服 mod 方案通过替换 hash 让客户端下载自定义资源（正常链路）。

| 位置 | 命中 |
|---|---|
| `Assembly-CSharp\Torappu.Resource\HotUpdater.cs:2028` | `string md = abInfo.md5;` |
| `Assembly-CSharp\Torappu.Resource\HotUpdater.cs:2046` | `string md2 = abInfo.md5;` |
| `Assembly-CSharp\Torappu.Resource\HotUpdater.cs:3125` | `private static DelegateBridge __Hotfix0__CheckIfAssetDirty;` |
| `Assembly-CSharp\Torappu.Resource\HotUpdater.cs:4383` | `private static bool _CheckIfAssetDirty(HotUpdateInfo.ABInfo abInfo, Dictionary<string, string> oldHashMap, Dictionary<string, string> oldMD5Map, Dictionary<stri` |
| `Assembly-CSharp\Torappu.Resource\HotUpdater.cs:4389` | `DelegateBridge _Hotfix0__CheckIfAssetDirty = __Hotfix0__CheckIfAssetDirty;` |
| `Assembly-CSharp\Torappu.Resource\HotUpdater.cs:4391` | `if (_Hotfix0__CheckIfAssetDirty == null && flag)` |
| `Assembly-CSharp\Torappu.Resource\HotUpdater.cs:4393` | `string hash = abInfo.hash;` |
| `Assembly-CSharp\Torappu.Resource\HotUpdater.cs:4399` | `bool flag2 = abInfo.md5 != valueOrDefault;` |
| `Assembly-CSharp\Torappu.Resource\HotUpdater.cs:4418` | `bool flag4 = _Hotfix0__CheckIfAssetDirty.__Gen_Delegate_Imp1227((HotUpdateInfo.ABInfo)num, oldHashMap, oldMD5Map, oldTypeMap);` |

## B. 反作弊

### CodeStage.InjectionDetector

注入检测（内存修改 / 注入框架）。定义存在于客户端程序集，但游戏代码无直接 new/引用，通常由场景组件（Inspector）配置启用。

| 位置 | 命中 |
|---|---|
| `-:0` | `(游戏代码未直接引用——可能经场景 prefab / Inspector 配置挂载)` |

### CodeStage.SpeedHackDetector

游戏加速器检测。定义存在于客户端程序集，但游戏代码无直接 new/引用，通常由场景组件（Inspector）配置启用。

| 位置 | 命中 |
|---|---|
| `-:0` | `(游戏代码未直接引用——可能经场景 prefab / Inspector 配置挂载)` |

### CodeStage.TimeCheatingDetector

系统时间篡改检测。定义存在于客户端程序集，但游戏代码无直接 new/引用，通常由场景组件（Inspector）配置启用。

| 位置 | 命中 |
|---|---|
| `-:0` | `(游戏代码未直接引用——可能经场景 prefab / Inspector 配置挂载)` |

### CodeStage.WallHackDetector

透视 / 穿墙检测。定义存在于客户端程序集，但游戏代码无直接 new/引用，通常由场景组件（Inspector）配置启用。

| 位置 | 命中 |
|---|---|
| `-:0` | `(游戏代码未直接引用——可能经场景 prefab / Inspector 配置挂载)` |

### CodeStage.ObscuredCheatingDetector

混淆值作弊检测（对 Obscured* 类型篡改）。定义存在于客户端程序集，但游戏代码无直接 new/引用，通常由场景组件（Inspector）配置启用。

| 位置 | 命中 |
|---|---|
| `-:0` | `(游戏代码未直接引用——可能经场景 prefab / Inspector 配置挂载)` |

### CodeStage.ActDetectorBase

检测器基类。定义存在于客户端程序集，但游戏代码无直接 new/引用，通常由场景组件（Inspector）配置启用。

| 位置 | 命中 |
|---|---|
| `-:0` | `(游戏代码未直接引用——可能经场景 prefab / Inspector 配置挂载)` |

### Obscured* 混淆数值类型

CodeStage 混淆值（防内存修改），常用于玩家资源/战斗数值等敏感字段。

| 位置 | 命中 |
|---|---|
| `Assembly-CSharp\Torappu\AttributesData.cs:53` | `public ObscuredInt maxHp;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:58` | `public ObscuredInt atk;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:63` | `public ObscuredInt def;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:68` | `public ObscuredFloat magicResistance;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:73` | `public ObscuredInt cost;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:78` | `public ObscuredInt blockCnt;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:83` | `public ObscuredFloat moveSpeed;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:88` | `public ObscuredFloat attackSpeed;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:93` | `public ObscuredFloat baseAttackTime;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:98` | `public ObscuredInt respawnTime;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:103` | `public ObscuredFloat hpRecoveryPerSec;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:108` | `public ObscuredFloat spRecoveryPerSec;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:113` | `public ObscuredInt maxDeployCount;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:118` | `public ObscuredInt maxDeckStackCnt;` |
| `Assembly-CSharp\Torappu\AttributesData.cs:123` | `public ObscuredInt tauntLevel;` |

### ACE / MTP（com.hg.sdk，Java/native 层）

腾讯 ACE + Hypergryph MTP 反作弊 SDK 在 Java/native 层，C# 源码不可见，需动态分析；现有 hook/main.ts 已置空 MTPProxyApplication.onProxyCreate / MTPDetection.onUserLogin 处理。

（无源码级命中，见说明）

## C. 暗桩 / 埋点

### Hypergryph.EventLogSDK

鹰角事件日志 SDK：行为埋点 / 上报（登录、进关、支付等）。

| 位置 | 命中 |
|---|---|
| `Hypergryph.EventLogSDK\Hypergryph.SDK\HGEventLogSDKAppInstance.cs:97` | `public static void Flush()` |
| `Hypergryph.EventLogSDK\Hypergryph.SDK\HGEventLogSDKMgr.cs:107` | `public static void Flush()` |

### torappu.CrashSight.Standalone

腾讯 CrashSight 崩溃/异常上报 SDK（含设备信息收集）。

| 位置 | 命中 |
|---|---|
| `Assembly-CSharp\Torappu.CrashSight\CrashSightSDK.cs:20` | `public unsafe static void Init()` |
| `torappu.CrashSight.Standalone\CrashSightAgent.cs:543` | `public static void Init(string app_id, string app_key, string app_version)` |
| `torappu.CrashSight.Standalone\GCloud.UQM\UQM.cs:19` | `public static void Init()` |
| `torappu.CrashSight.Standalone\GCloud.UQM\UQMCrash.cs:571` | `public static void Init(string app_id, string app_key, string app_version)` |
| `torappu.CrashSight.Standalone\GCloud.UQM\UQMMessageCenter.cs:44` | `public void Init()` |

### Hypergryph.OneChannel / Webview

渠道服务与内嵌 WebView（运营活动页 / 公告页，可能加载外联页面）。

（无源码级命中，见说明）

### 硬编码外联域名

客户端源码中出现的固定域名（去重，已排除注释与第三方资产 URL）——评估数据外流面。

（无源码级命中，见说明）

## D. APK 本体（Java / native / 资源层）

### Dex 反作弊特征

Java 层反作弊 SDK 字符串特征（com.hg.sdk / MTP / ACE / root / 注入 / 模拟器 / 调试检测）

| 位置 | 命中 |
|---|---|
| `classes.dex:0` | `[Root / 提权检测] …ersedHorizontalSet..isReversedVertical..isRooted..isRotateSupported..isRotationNeeded..i…` |
| `classes.dex:0` | `[注入 / Hook 检测] …\|bid\|bike\|bing\|bingo\|bio\|biz\|black\|blackfriday\|bloomberg\|blue\|bms\|bmw\|bnl\|bnpparibas\|…` |
| `classes.dex:0` | `[模拟器检测] …pty-impl..isEmptyImpl..isEmptyLoadPath..isEmulator..isEmulatorAndApi21..isEnableANRCrashMo…` |
| `classes.dex:0` | `[EventLogSDK 事件上报] …/hms/ads/identifier/e;."Lcom/hypergryph/eventlog/EventLog;.%Lcom/hypergryph/platform/hgs…` |
| `classes.dex:0` | `[CrashSight / Bugly 崩溃上报] …..begin.. .(.....end.. .(.B.....com.uqm.crashsight.protobufB.DescriptorProtosH.Z>github.co…` |
| `classes.dex:0` | `[统计 / 广告埋点] …Lcom/u8/sdk/UserExtraData;. Lcom/u8/sdk/analytics/UDAgent$1;. Lcom/u8/sdk/analytics/UDAge…` |
| `classes2.dex:0` | `[Root / 提权检测] …in/failsafe/su../system/bin/qemu-props../system/bin/su.%/system/lib/libc_malloc_debug_qemu.so.…` |
| `classes2.dex:0` | `[注入 / Hook 检测] …8c7b0edc262196ab4b0082.#de.robv.android.xposed.XposedBridge. de.robv.android.xposed.in…` |
| `classes2.dex:0` | `[模拟器检测] …./data/local/xbin/su../data/misc/../dev/qemu_pipe../dev/socket/baseband_genyd../dev/…` |
| `classes2.dex:0` | `[EventLogSDK 事件上报] …decoder$Mode.5$SwitchMap$com$hypergryph$eventlog$utils$Tools$REMOTE.I$SwitchMap$com$hype…` |
| `classes2.dex:0` | `[CrashSight / Bugly 崩溃上报] ….2..SightPkg.ExceptionUploadB6.*com.uqm.crashsight.crashreport.common.infoB.SightPkgb.prot…` |
| `classes2.dex:0` | `[统计 / 广告埋点] …/SwitchNetManagerExternal;./Lcn/jiguang/analytics/page/ActivityLifecycle$1;.-Lcn/jiguang/…` |
| `classes3.dex:0` | `[Root / 提权检测] …tem/bin/netcfg../system/bin/qemu-props../system/bin/su../system/build.prop../system/etc/.has_s…` |
| `classes3.dex:0` | `[注入 / Hook 检测] …dc..dc:..dd..ddata..de.#de.robv.android.xposed.XposedBridge. de.robv.android.xposed.in…` |
| `classes3.dex:0` | `[模拟器检测] …eruser.daemon/../dev/cpuctl/tasks../dev/qemu_pipe../dev/socket/baseband_genyd../dev/…` |
| `classes3.dex:0` | `[EventLogSDK 事件上报] …nload/utils/LogHelper;."Lcom/hypergryph/eventlog/EventLog;..Lcom/hypergryph/platform/sha…` |
| `classes3.dex:0` | `[CrashSight / Bugly 崩溃上报] …SDK VER: %s.B# You can use Bugly(http:\\bugly.qq.com) to get more Crash Detail!.,#+++…` |
| `classes4.dex:0` | `[MTP 反作弊] …:: HGShareImpl construction.$Is here :: MTPDetection construction.)Is here :: PermissionRequ…` |
| `classes4.dex:0` | `[Root / 提权检测] …system/bin/failsafe/su../system/bin/sh../system/bin/su../system/sd/xbin/su../system/xbin/su../…` |
| `classes4.dex:0` | `[注入 / Hook 检测] …elegate..dd..ddata..de.#de.robv.android.xposed.XposedBridge.8de.robv.android.xposed.Xp…` |
| … | 共 24 处命中，已截断 |

### Dex 埋点 / 暗桩特征

Java 层埋点与上报 SDK（EventLog / CrashSight / OneChannel / 统计）

| 位置 | 命中 |
|---|---|
| `classes.dex:0` | `[EventLogSDK 事件上报] …/hms/ads/identifier/e;."Lcom/hypergryph/eventlog/EventLog;.%Lcom/hypergryph/platform/hgs…` |
| `classes.dex:0` | `[CrashSight / Bugly 崩溃上报] …..begin.. .(.....end.. .(.B.....com.uqm.crashsight.protobufB.DescriptorProtosH.Z>github.co…` |
| `classes.dex:0` | `[统计 / 广告埋点] …Lcom/u8/sdk/UserExtraData;. Lcom/u8/sdk/analytics/UDAgent$1;. Lcom/u8/sdk/analytics/UDAge…` |
| `classes2.dex:0` | `[EventLogSDK 事件上报] …decoder$Mode.5$SwitchMap$com$hypergryph$eventlog$utils$Tools$REMOTE.I$SwitchMap$com$hype…` |
| `classes2.dex:0` | `[CrashSight / Bugly 崩溃上报] ….2..SightPkg.ExceptionUploadB6.*com.uqm.crashsight.crashreport.common.infoB.SightPkgb.prot…` |
| `classes2.dex:0` | `[统计 / 广告埋点] …/SwitchNetManagerExternal;./Lcn/jiguang/analytics/page/ActivityLifecycle$1;.-Lcn/jiguang/…` |
| `classes3.dex:0` | `[EventLogSDK 事件上报] …nload/utils/LogHelper;."Lcom/hypergryph/eventlog/EventLog;..Lcom/hypergryph/platform/sha…` |
| `classes3.dex:0` | `[CrashSight / Bugly 崩溃上报] …SDK VER: %s.B# You can use Bugly(http:\\bugly.qq.com) to get more Crash Detail!.,#+++…` |
| `classes4.dex:0` | `[EventLogSDK 事件上报] …ew$ScaleType.9$SwitchMap$com$hypergryph$eventlog$utils$ThirdPartyIdType.3$SwitchMap$com$…` |
| `classes4.dex:0` | `[CrashSight / Bugly 崩溃上报] …should not be empty!..appId:..appId_for_crashsight..appInfo..appInstanceAppId..appKey..app…` |
| `classes4.dex:0` | `[统计 / 广告埋点] ….cn.jiguang..cn.jiguang.ads..cn.jiguang.analytics..cn.jiguang.common..cn.jiguang.dy.FileL…` |
| `classes5.dex:0` | `[统计 / 广告埋点] …g/al/d;..Lcn/jiguang/al/e;.-Lcn/jiguang/analytics/page/ActivityLifecycle;."Lcn/jiguang/an…` |

### Native 库清单（lib/*.so）

共 51 个 so；命中安全/上报关键词 18 个

| 位置 | 命中 |
|---|---|
| `lib/arm64-v8a/libBugly.so:0` | `lib/arm64-v8a/libBugly.so（190656 B）` |
| `lib/arm64-v8a/libCrashSight.so:0` | `lib/arm64-v8a/libCrashSight.so（1093048 B）` |
| `lib/arm64-v8a/libcri_ware_unity.so:0` | `lib/arm64-v8a/libcri_ware_unity.so（2653920 B）` |
| `lib/arm64-v8a/libHGEventlog.so:0` | `lib/arm64-v8a/libHGEventlog.so（321312 B）` |
| `lib/arm64-v8a/libhgvulkanapi.so:0` | `lib/arm64-v8a/libhgvulkanapi.so（292920 B）` |
| `lib/arm64-v8a/libsmsdk.so:0` | `lib/arm64-v8a/libsmsdk.so（826104 B）` |
| `lib/arm64-v8a/libtapsdkcore.so:0` | `lib/arm64-v8a/libtapsdkcore.so（4212056 B）` |
| `lib/arm64-v8a/libtprt.so:0` | `lib/arm64-v8a/libtprt.so（1692296 B）` |
| `lib/arm64-v8a/libunity.so:0` | `lib/arm64-v8a/libunity.so（20012592 B）` |
| `lib/armeabi-v7a/libBugly.so:0` | `lib/armeabi-v7a/libBugly.so（165628 B）` |
| `lib/armeabi-v7a/libCrashSight.so:0` | `lib/armeabi-v7a/libCrashSight.so（747936 B）` |
| `lib/armeabi-v7a/libcri_ware_unity.so:0` | `lib/armeabi-v7a/libcri_ware_unity.so（2303432 B）` |
| `lib/armeabi-v7a/libHGEventlog.so:0` | `lib/armeabi-v7a/libHGEventlog.so（181824 B）` |
| `lib/armeabi-v7a/libhgvulkanapi.so:0` | `lib/armeabi-v7a/libhgvulkanapi.so（169612 B）` |
| `lib/armeabi-v7a/libsmsdk.so:0` | `lib/armeabi-v7a/libsmsdk.so（742376 B）` |
| `lib/armeabi-v7a/libtapsdkcore.so:0` | `lib/armeabi-v7a/libtapsdkcore.so（2788652 B）` |
| `lib/armeabi-v7a/libtprt.so:0` | `lib/armeabi-v7a/libtprt.so（1411924 B）` |
| `lib/armeabi-v7a/libunity.so:0` | `lib/armeabi-v7a/libunity.so（15202504 B）` |

### AndroidManifest 敏感权限

检出 5 个敏感权限

| 位置 | 命中 |
|---|---|
| `AndroidManifest.xml:0` | `QUERY_ALL_PACKAGES` |
| `AndroidManifest.xml:0` | `READ_EXTERNAL_STORAGE` |
| `AndroidManifest.xml:0` | `INSTALL_PACKAGES` |
| `AndroidManifest.xml:0` | `REQUEST_INSTALL_PACKAGES` |
| `AndroidManifest.xml:0` | `WRITE_SETTINGS` |

### 硬编码域名（dex 层）

检出 91 个去重域名

| 位置 | 命中 |
|---|---|
| `classes*.dex:0` | `www.googleapis.com（13 次）` |
| `classes*.dex:0` | `openmobile.qq.com（8 次）` |
| `classes*.dex:0` | `mclient.alipay.com（7 次）` |
| `classes*.dex:0` | `imgcache.qq.com（6 次）` |
| `classes*.dex:0` | `opencloud.wostore.cn（5 次）` |
| `classes*.dex:0` | `user.hypergryph.com（5 次）` |
| `classes*.dex:0` | `issuetracker.google.com（4 次）` |
| `classes*.dex:0` | `ak.hypergryph.com（4 次）` |
| `classes*.dex:0` | `onepass.geetest.com（3 次）` |
| `classes*.dex:0` | `service.weibo.com（3 次）` |
| `classes*.dex:0` | `wappaygw.alipay.com（3 次）` |
| `classes*.dex:0` | `schemas.android.com（2 次）` |
| `classes*.dex:0` | `open.weibo.cn（2 次）` |
| `classes*.dex:0` | `ak-web-staging.hypergryph.com（2 次）` |
| `classes*.dex:0` | `appsupport.qq.com（2 次）` |
| `classes*.dex:0` | `as.hypergryph.com（2 次）` |
| `classes*.dex:0` | `core-api-account-dev.hypergryph.net（2 次）` |
| `classes*.dex:0` | `loggw-exsdk.alipay.com（2 次）` |
| `classes*.dex:0` | `mcgw.alipay.com（2 次）` |
| `classes*.dex:0` | `mobilegw.alipay.com（2 次）` |

### assets 资源结构（采样）

Unity 资源布局（AB bundle 目录 / 加密 Lua bundle 等）

| 位置 | 命中 |
|---|---|
| `assets/:0` | `assets/AB/Android/745b15f58f014d6568da4ae045d95a3f.idx（10241604 B）` |
| `assets/:0` | `assets/AB/Android/activity/commonassets.ab（4627815 B）` |
| `assets/:0` | `assets/AB/Android/akvt/prfb_fx_0.ab（156191 B）` |
| `assets/:0` | `assets/AB/Android/akvt/prfb_spn_0.ab（14609 B）` |
| `assets/:0` | `assets/AB/Android/akvt/prfb_spn_1.ab（5759 B）` |
| `assets/:0` | `assets/AB/Android/akvt/prfb_trp_0.ab（84016 B）` |
| `assets/:0` | `assets/AB/Android/anon/03c294ec637a9d2aa11ca45006bf20a2.bin（379828 B）` |
| `assets/:0` | `assets/AB/Android/anon/057ce414728716944e50014e7a34d437.bin（2741563 B）` |
| `assets/:0` | `assets/AB/Android/anon/076eaf0724466661547a9d77855c0776.bin（3588 B）` |
| `assets/:0` | `assets/AB/Android/anon/0b57b98e9391802ac345ce338beb3eeb.bin（2155 B）` |
| `assets/:0` | `assets/AB/Android/anon/0c7428e9e598f1efb2dfea78b3f935e6.bin（1246028 B）` |
| `assets/:0` | `assets/AB/Android/anon/0d688f1808e17ccf5294634f668be5f4.bin（1732241 B）` |

## 审查说明

- **完整性/签名校验**是私服接入的关键面：`VerifySignMD5RSA` 必须绕过（Lua 引导插件已处理），热更 md5 校验走 mod 替换 hash 方案（现有管线已兼容）。
- **反作弊**分三层：C# 层 CodeStage 检测器（可被 Lua hotfix 针对性停用）、Java/native 层（dex 检出 MTP/root/注入/模拟器检测，见 D 章；需 Frida/动态处理，见 hook/main.ts）、混淆值（影响内存修改类外挂，与私服无关）。
- **暗桩/埋点**主要影响隐私面与数据外流：C# 层 EventLogSDK/CrashSight + dex 层同套 SDK 的 Java 实现（com.hypergryph.eventlog / com.uqm.crashsight）+ 极光（cn.jiguang）+ 支付宝/QQ/微博渠道 SDK；私服场景建议在网关层观察上报域名并决定是否放行。
- **APK 层注意**：dex 检出开发环境域残留（`ak-web-staging.hypergryph.com`、`core-api-account-dev.hypergryph.net`）——仅作内部情报，非私服风险点；敏感权限（QUERY_ALL_PACKAGES/INSTALL_PACKAGES 等）属游戏热更新与渠道 SDK 常规需求。
- **静态字符串扫描存在少量误报**（如 `isRooted` 命中 View 旋转方法），需结合上下文确认。
