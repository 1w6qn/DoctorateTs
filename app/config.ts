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
  /** 版本信息 */
  version: {
    /** 资源版本 */
    resVersion: string;
    /** 客户端版本 */
    clientVersion: string;
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
  };
  /** 网络配置 */
  NetworkConfig: object;
  /** 远程功能配置（新版 remote_config 接口响应，缺省使用官方默认值） */
  RemoteConfig?: Record<string, unknown>;
  /** 管理后台配置 */
  admin?: {
    /** 是否开启 /admin HTTP 管理接口 */
    enable: boolean;
    /** 管理 API Bearer Token */
    token: string;
  };
  /** 认证模式：single（单例——secret 强制 1，任意 token 宽松）/ real（真实——多账号严格校验） */
  authMode?: "single" | "real";
  /** 单例模式是否自动生成满配账号（全干员/全物品，随版本刷新——默认开启） */
  singleAutoMaxAccount?: boolean;
}

/** 应用配置实例 */
const config = readJsonSync<UserConfig>("./data/config.json");

// Host 支持 "auto"：自动检测本机局域网 IPv4（避免硬编码 IP，换网络环境无需改配置）
if (String(config.Host).includes("auto")) {
  config.Host = `http://${detectLocalIp()}`;
}

export default config;