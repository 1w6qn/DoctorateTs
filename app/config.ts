/**
 * 配置模块
 * 
 * 读取并导出应用配置数据，包括服务器地址、端口、版本号、资源配置等。
 */

import { readJsonSync } from "@utils/file";

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
  };
  /** 网络配置 */
  NetworkConfig: object;
}

/** 应用配置实例 */
const config = readJsonSync<UserConfig>("./data/config.json");

export default config;