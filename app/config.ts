/**
 * 配置模块
 * 
 * 读取并导出应用配置数据，包括服务器地址、端口、版本号、资源配置等。
 */

import { readJsonSync } from "@utils/file";
import os from "os";

/**
 * 自动检测本机局域网 IPv4 地址（真机/模拟器连接场景）
 * 取第一个非回环 IPv4；无局域网 IP 时回退 127.0.0.1
 */
export function detectLocalIp(): string {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal) {
        return net.address;
      }
    }
  }
  return "127.0.0.1";
}

/**
 * 用户配置接口
 * 
 * 定义应用配置的数据结构。
 */
interface UserConfig {
  /** 服务器主机地址 */
  Host: string;
  /** 服务器端口 */
  PORT: number;
  /** 是否完全离线模式启动（不进行任何网络操作，使用本地缓存数据） */
  offline?: boolean;
  /** 是否启动时自动更新数据（缺省 false——激进默认：仅 npm run update / --auto-update 更新） */
  autoUpdate?: boolean;
  /** 登录响应主版本号（客户端校验用——去硬编码，缺省 "446"） */
  majorVersion?: string;
  /** 版本信息 */
  version: {
    /** 资源版本 */
    resVersion: string;
    /** 客户端版本 */
    clientVersion: string;
    /** Windows 独立资源版本（可选；缺省回退 resVersion） */
    windows?: { resVersion: string; clientVersion: string };
  };
  /** 资源配置 */
  assets: {
    /** 是否启用模组 */
    enableMods: boolean;
    /** 是否本地下载 */
    downloadLocally: boolean;
    /** 是否自动更新 */
    autoUpdate: boolean;
    /** 代理模式（odpy 参考）：直接转发官服 CDN，不落盘 */
    downloadPeoxy?: boolean;
    /** 是否启动时自动重打包内置 Lua bundle mod（缺省 true；false 关闭自动构建） */
    autoBuildLuaMod?: boolean;
  };
  /** 网络配置 */
  NetworkConfig: object;
  /** 远程功能配置（新版 remote_config 接口响应，缺省使用官方默认值） */
  RemoteConfig?: Record<string, unknown>;
  /** 抓包专用官服转发模式：as/gs 流量转发官服并记录（等价命令行 --capture） */
  capture?: {
    /** 是否开启官服转发（客户端连接私服，as/gs 请求转发官服；config/asset/admin 仍本地响应）。
     *  开启时强制禁用 assets.enableMods——抓包须还原官服原生资源，mod 污染抓包流量 */
    enabled?: boolean;
    /** 官服 as 主机（缺省 https://as.hypergryph.com） */
    asHost?: string;
    /** 官服 gs 主机（缺省 https://ak-gs-gf.hypergryph.com） */
    gsHost?: string;
    /** arkhub 网关本地转发器监听端口（缺省 30000，对齐官服网关端口） */
    gatewayPort?: number;
    /** 统一抓包存储根目录（缺省 tmp/capture；一般无需覆盖） */
    root?: string;
  };
  /** 调试配置 */
  debug?: {
    /** 是否记录请求/响应到统一抓包存储 tmp/capture/（traffic-recorder 中间件） */
    recordTraffic?: boolean;
    /**
     * 抓包记录排除的路径前缀（覆盖默认列表；传空数组 [] = 全部记录）。
     * 默认排除本地管理/资源/配置噪音：/admin /assetbundle /pcSdk /config /api /audit /batch_event
     */
    recordTrafficExclude?: string[];
  };
  /** 管理后台配置 */
  admin?: {
    /** 是否开启 /admin HTTP 管理接口 */
    enable: boolean;
    /** 管理 API Bearer Token */
    token: string;
  };
  /** 认证模式：single（单例——secret 强制 1，任意 token 宽松）/ real（真实——多账号严格校验） */
  authMode?: "single" | "real";
  /** 官服操作自定义后端（enabled=true 时官服工具库/操作走自定义地址，可指向 obs 观察服务器或自建代理） */
  officialBackend?: {
    enabled?: boolean;
    /** 游戏服务器地址（缺省 https://ak-gs-gf.hypergryph.com） */
    game?: string;
    /** 账号服务器地址（缺省 https://as.hypergryph.com） */
    account?: string;
    /** 配置服务器地址（缺省 https://ak-conf.hypergryph.com） */
    conf?: string;
  };
  /** 单例模式固定账号 uid（默认 "1"——如某账号异常可切换过渡） */
  singleUid?: string;
  /** 单例模式是否自动生成满配账号（全干员/全物品，随版本刷新——默认开启） */
  singleAutoMaxAccount?: boolean;
  /** 开发者调试配置 */
  developer?: {
    /**
     * 客户端可见服务器时间戳冻结（activity 切换用，参考 DoctoratePy）：
     * -1（缺省）= 真实时间；数值 = 冻结到该时间戳（仅允许过去时间，未来值回退真实时间）
     */
    timestamp?: number;
  };
  /** 支付配置（pay 路由） */
  pay?: {
    /**
     * 支付模式：
     * - "fake"（缺省）：虚假支付——createOrder 后 confirmOrderAlipay/Wechat 直接成功，
     *   confirmOrder 立即发货，全程免费（私服测试用）
     * - "real"：真实支付——confirmOrderAlipay/Wechat 仅登记支付，须支付渠道异步回调
     *   /pay/notify（或管理端 `pay order <id> confirm` 手动确认）标记 paid 后，
     *   confirmOrder 才发货
     */
    mode?: "fake" | "real";
    /** 支付宝支付参数（real 模式：app_id/notify 地址/密钥） */
    alipay?: {
      appId?: string;
      notifyUrl?: string;
      privateKey?: string;
    };
    /** 微信支付参数（real 模式：appid/商户号/密钥） */
    wechat?: {
      appId?: string;
      mchId?: string;
      apiKey?: string;
    };
  };
}

/** 应用配置实例 */
const config = readJsonSync<UserConfig>("./data/config.json");

// Host 支持 "auto"：自动检测本机局域网 IPv4（避免硬编码 IP，换网络环境无需改配置）
if (String(config.Host).includes("auto")) {
  config.Host = `http://${detectLocalIp()}`;
}

/**
 * 端口覆盖：命令行 --port <n> > 环境变量 PORT > config.json
 * 支持不同端口启动：`PORT=9000 npm start` 或 `npm start -- --port 9000`
 * （config.PORT 被 index.ts listen 与各 resolveServer 地址拼接共同消费，统一在此覆盖）
 */
export function resolvePortOverride(args?: string[], envPort?: string): number | null {
  const argv = args ?? process.argv.slice(2);
  const idx = argv.indexOf("--port");
  if (idx !== -1 && argv[idx + 1] !== undefined) {
    const p = Number(argv[idx + 1]);
    if (Number.isInteger(p) && p > 0 && p < 65536) return p;
  }
  const env = envPort !== undefined ? envPort : process.env.PORT;
  if (env !== undefined) {
    const p = Number(env);
    if (Number.isInteger(p) && p > 0 && p < 65536) return p;
  }
  return null;
}

const overridePort = resolvePortOverride();
if (overridePort !== null) {
  config.PORT = overridePort;
}

export default config;